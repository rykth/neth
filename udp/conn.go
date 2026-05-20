package udp

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

type Conn struct {
	inner *net.UDPConn
}

// Listen binds a UDP/IPv4 socket on host:port
func Listen(host string, port int) (*Conn, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	lc := net.ListenConfig{Control: setReusePort}
	pc, err := lc.ListenPacket(context.Background(), "udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("udp: listen %s: %w", addr, err)
	}
	return &Conn{inner: pc.(*net.UDPConn)}, nil
}

func (c *Conn) ReadFrom(buf []byte) (int, *net.UDPAddr, error) {
	return c.inner.ReadFromUDP(buf)
}

func (c *Conn) WriteTo(buf []byte, addr *net.UDPAddr) (int, error) {
	return c.inner.WriteTo(buf, addr)
}

func (c *Conn) LocalAddr() *net.UDPAddr {
	return c.inner.LocalAddr().(*net.UDPAddr)
}

func (c *Conn) Close() error {
	return c.inner.Close()
}

// setReusePort is a net.ListenConfig.Control callback that enables SO_REUSEPORT
// before the kernel binds the address. It must be set before bind - not after
// - which is why we use ListenConfig rather than net.ListenUDP + SetsockoptInt.
func setReusePort(_ string, _ string, c syscall.RawConn) error {
	var setErr error
	if err := c.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return setErr
}
