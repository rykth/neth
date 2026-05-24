//go:build linux

package tun

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const cloneDevice = "/dev/net/tun"

// ifreq is the Linux struct ifreq (40 bytes on amd64/arm64)
type ifreq [40]byte

func (r *ifreq) setName(name string) {
	copy(r[:unix.IFNAMSIZ], name)
}

func (r *ifreq) getName() string {
	b := r[:unix.IFNAMSIZ]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func (r *ifreq) setFlags(flags uint16) {
	binary.NativeEndian.PutUint16(r[unix.IFNAMSIZ:], flags)
}

func (r *ifreq) getFlags() uint16 {
	return binary.NativeEndian.Uint16(r[unix.IFNAMSIZ:])
}

func (r *ifreq) setMTU(mtu int) {
	binary.NativeEndian.PutUint32(r[unix.IFNAMSIZ:], uint32(mtu)) //nolint:gosec
}

// setSockaddrIn writes an IPv4 sockaddr_in into the ifreq union:
//
//	bytes [IFNAMSIZ+0 .. +1]  sin_family (AF_INET, native endian)
//	bytes [IFNAMSIZ+2 .. +3]  sin_port   (0)
//	bytes [IFNAMSIZ+4 .. +7]  sin_addr   (network byte order = big-endian)
func (r *ifreq) setSockaddrIn(ip [4]byte) {
	binary.NativeEndian.PutUint16(r[unix.IFNAMSIZ:], uint16(unix.AF_INET))
	copy(r[unix.IFNAMSIZ+4:], ip[:])
}

// Device is an open Linux TUN interface.
type Device struct {
	file *os.File
	name string
}

// Open creates (or reopens) a TUN interface named name, assigns cidr as its
// IPv4 address, sets mtu, and brings it up.  Requires CAP_NET_ADMIN.
func Open(name, cidr string, mtu int) (*Device, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("tun: parse CIDR %q: %w", cidr, err)
	}
	if !prefix.Addr().Is4() {
		return nil, fmt.Errorf("tun: only IPv4 supported, got %s", cidr)
	}

	fd, err := unix.Open(cloneDevice, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open %s: %w", cloneDevice, err)
	}

	var tunIfr ifreq
	tunIfr.setName(name)
	tunIfr.setFlags(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := ioctlPtr(fd, unix.TUNSETIFF, unsafe.Pointer(&tunIfr)); err != nil { //nolint:gosec
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", err)
	}
	devName := tunIfr.getName()

	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: control socket: %w", err)
	}
	defer func() { _ = unix.Close(sock) }() //nolint:gosec

	var addrIfr ifreq
	addrIfr.setName(devName)
	addrIfr.setSockaddrIn(prefix.Addr().As4())
	if err := ioctlPtr(sock, unix.SIOCSIFADDR, unsafe.Pointer(&addrIfr)); err != nil { //nolint:gosec
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: SIOCSIFADDR: %w", err)
	}

	var maskIfr ifreq
	maskIfr.setName(devName)
	maskIfr.setSockaddrIn(prefixMask4(prefix.Bits()))
	if err := ioctlPtr(sock, unix.SIOCSIFNETMASK, unsafe.Pointer(&maskIfr)); err != nil { //nolint:gosec
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: SIOCSIFNETMASK: %w", err)
	}

	var mtuIfr ifreq
	mtuIfr.setName(devName)
	mtuIfr.setMTU(mtu)
	if err := ioctlPtr(sock, unix.SIOCSIFMTU, unsafe.Pointer(&mtuIfr)); err != nil { //nolint:gosec
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: SIOCSIFMTU: %w", err)
	}

	var flagsIfr ifreq
	flagsIfr.setName(devName)
	if err := ioctlPtr(sock, unix.SIOCGIFFLAGS, unsafe.Pointer(&flagsIfr)); err != nil { //nolint:gosec
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: SIOCGIFFLAGS: %w", err)
	}
	flagsIfr.setFlags(flagsIfr.getFlags() | unix.IFF_UP)
	if err := ioctlPtr(sock, unix.SIOCSIFFLAGS, unsafe.Pointer(&flagsIfr)); err != nil { //nolint:gosec
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tun: SIOCSIFFLAGS: %w", err)
	}

	// Switch to loose reverse-path filtering (rp_filter=2) on the TUN.
	// Overlay traffic injected into the TUN has source IPs routable via
	// other interfaces. The kernel uses max(all, iface) to determine the
	// effective rp_filter; setting the per-interface value to 2 (loose)
	// overrides the common default of 1 (strict) that would silently drop
	// every decrypted VPN packet.
	rpPath := fmt.Sprintf("/proc/sys/net/ipv4/conf/%s/rp_filter", devName)
	_ = os.WriteFile(rpPath, []byte("2"), 0o644) //nolint:gosec

	return &Device{
		file: os.NewFile(uintptr(fd), devName),
		name: devName,
	}, nil
}

func (d *Device) Read(buf []byte) (int, error) {
	return d.file.Read(buf)
}

func (d *Device) Write(buf []byte) (int, error) {
	return d.file.Write(buf)
}

func (d *Device) Close() error {
	return d.file.Close()
}

func (d *Device) Name() string {
	return d.name
}

// prefixMask4 converts a prefix length to a 4-byte network-byte-order mask.
func prefixMask4(bits int) [4]byte {
	m := ^uint32(0) << (32 - bits)
	return [4]byte{byte(m >> 24), byte(m >> 16), byte(m >> 8), byte(m)}
}

func ioctlPtr(fd int, req uintptr, arg unsafe.Pointer) error {
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), req, uintptr(arg)); errno != 0 {
		return errno
	}
	return nil
}
