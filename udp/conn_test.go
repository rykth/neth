package udp_test

import (
	"bytes"
	"testing"

	"github.com/rykth/neth/udp"
)

func TestListenAndSend(t *testing.T) {
	server, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Listen server: %v", err)
	}
	defer server.Close()

	client, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Listen client: %v", err)
	}
	defer client.Close()

	msg := []byte("neth-udp-test")

	if _, err := client.WriteTo(msg, server.LocalAddr()); err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	buf := make([]byte, 512)
	n, from, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}

	if !bytes.Equal(buf[:n], msg) {
		t.Errorf("received %q, want %q", buf[:n], msg)
	}
	if from.String() != client.LocalAddr().String() {
		t.Errorf("from = %s, want %s", from, client.LocalAddr())
	}
}

func TestReusePort(t *testing.T) {
	c1, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	defer c1.Close()

	port := c1.LocalAddr().Port

	c2, err := udp.Listen("127.0.0.1", port) // test SO_REUSEPORT
	if err != nil {
		t.Fatalf("second Listen on port %d (SO_REUSEPORT): %v", port, err)
	}
	c2.Close()
}

func TestLocalAddr(t *testing.T) {
	c, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer c.Close()

	addr := c.LocalAddr()
	if addr == nil {
		t.Fatal("LocalAddr() returned nil")
	}
	if addr.IP.String() != "127.0.0.1" {
		t.Errorf("IP = %s, want 127.0.0.1", addr.IP)
	}
	if addr.Port == 0 {
		t.Error("Port should be non-zero after binding")
	}
}

func TestBidirectional(t *testing.T) {
	a, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Listen a: %v", err)
	}
	defer a.Close()

	b, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("Listen b: %v", err)
	}
	defer b.Close()

	ping := []byte("ping")
	pong := []byte("pong")

	// a → b
	if _, err := a.WriteTo(ping, b.LocalAddr()); err != nil {
		t.Fatalf("a→b WriteTo: %v", err)
	}
	buf := make([]byte, 64)
	n, from, err := b.ReadFrom(buf)
	if err != nil {
		t.Fatalf("b ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], ping) {
		t.Errorf("b received %q, want %q", buf[:n], ping)
	}

	// b replies to a using the from address
	if _, err := b.WriteTo(pong, from); err != nil {
		t.Fatalf("b→a WriteTo: %v", err)
	}
	n, _, err = a.ReadFrom(buf)
	if err != nil {
		t.Fatalf("a ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], pong) {
		t.Errorf("a received %q, want %q", buf[:n], pong)
	}
}
