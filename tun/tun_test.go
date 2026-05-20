//go:build linux

package tun_test

import (
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rykth/neth/tun"
)

func dialUDP4(ip string, port int) (net.Conn, error) {
	return net.Dial("udp4", net.JoinHostPort(ip, strconv.Itoa(port)))
}

func TestOpenClose(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root / CAP_NET_ADMIN")
	}

	dev, err := tun.Open("neth-test0", "192.168.201.1/24", 1400)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if dev.Name() != "neth-test0" {
		t.Errorf("Name() = %q, want %q", dev.Name(), "neth-test0")
	}

	if err := dev.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// Open creates a TUN interface with 192.168.202.1/24 and sets SIOCSIFNETMASK
// so the kernel adds a connected route for 192.168.202.0/24 via the interface.
// When this process dials UDP to 192.168.202.2 the kernel routes that packet
// through the TUN interface, making the fd readable.
func TestReceivePacket(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root / CAP_NET_ADMIN")
	}

	const (
		tunName = "neth-test1"
		tunCIDR = "192.168.202.1/24"
		dstIP   = "192.168.202.2"
		dstPort = 59876
	)

	dev, err := tun.Open(tunName, tunCIDR, 1500)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer dev.Close()

	type result struct {
		pkt []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 1500)
		n, err := dev.Read(buf)
		ch <- result{buf[:n], err}
	}()

	conn, err := dialUDP4(dstIP, dstPort)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("neth")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("TUN Read: %v", r.err)
		}
		if len(r.pkt) < 20 {
			t.Fatalf("packet too short: %d bytes", len(r.pkt))
		}
		if r.pkt[0]>>4 != 4 {
			t.Errorf("expected IPv4 (version 4), got version %d", r.pkt[0]>>4)
		}
		t.Logf("TUN received %d-byte IPv4 packet", len(r.pkt))
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for packet from TUN fd")
	}
}

func TestInvalidCIDR(t *testing.T) {
	// No kernel calls; parse error is returned before any ioctl.
	_, err := tun.Open("neth-test2", "not-a-cidr", 1500)
	if err == nil {
		t.Fatal("expected error for invalid CIDR, got nil")
	}
}

func TestIPv6Rejected(t *testing.T) {
	// No kernel calls; IPv6 check fires before TUNSETIFF.
	_, err := tun.Open("neth-test3", "fd00::1/64", 1500)
	if err == nil {
		t.Fatal("expected error for IPv6 CIDR, got nil")
	}
}
