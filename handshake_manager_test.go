package neth_test

import (
	"crypto"
	"net/netip"
	"testing"
	"time"

	noise "github.com/flynn/noise"

	"github.com/rykth/neth"
	"github.com/rykth/neth/cert"
	"github.com/rykth/neth/header"
	"github.com/rykth/neth/udp"
)

type mgrPeer struct {
	cert  *cert.Certificate
	dhKey noise.DHKey
}

func makeMgrPeer(t *testing.T, ca *cert.Certificate, caKey crypto.Signer, name, vpnCIDR string) mgrPeer {
	t.Helper()
	priv, pub, err := cert.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	prefix := netip.MustParsePrefix(vpnCIDR)
	c, err := ca.Sign(name, prefix, nil, pub, 24*time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign %s: %v", name, err)
	}
	return mgrPeer{cert: c, dhKey: noise.DHKey{Private: priv, Public: pub}}
}

func routeMgr(conn *udp.Conn, mgr *neth.HandshakeManager) {
	buf := make([]byte, 65536)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])

		h, err := header.Parse(pkt)
		if err != nil || h.Type != header.TypeHandshake {
			continue
		}
		switch header.HandshakeSubType(h.SubType) {
		case header.HandshakeInitiation:
			_ = mgr.HandleStage0(pkt, from)
		case header.HandshakeResponse:
			_ = mgr.HandleStage1(pkt)
		}
	}
}

func TestHandshakeManagerRoundTrip(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caPool := []*cert.Certificate{ca}

	alice := makeMgrPeer(t, ca, caKey, "alice", "10.0.0.1/24")
	bob := makeMgrPeer(t, ca, caKey, "bob", "10.0.0.2/24")

	aliceConn, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("alice Listen: %v", err)
	}
	defer aliceConn.Close()

	bobConn, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("bob Listen: %v", err)
	}
	defer bobConn.Close()

	type result struct {
		host    *neth.HostInfo
		pending [][]byte
	}
	aliceDone := make(chan result, 1)
	bobDone := make(chan result, 1)

	aliceMgr := neth.NewHandshakeManager(
		alice.cert,
		alice.dhKey,
		caPool,
		aliceConn,
		func(h *neth.HostInfo, pending [][]byte) {
			aliceDone <- result{h, pending}
		})

	bobMgr := neth.NewHandshakeManager(
		bob.cert,
		bob.dhKey,
		caPool,
		bobConn,
		func(h *neth.HostInfo, pending [][]byte) {
			bobDone <- result{h, pending}
		})

	// Initiate before starting routing goroutines so the queued packet is
	// guaranteed to land in the pending list before any routing occurs.
	if err := aliceMgr.StartHandshake(bob.cert.VpnIP.Addr(), bobConn.LocalAddr(), bob.cert); err != nil {
		t.Fatalf("StartHandshake: %v", err)
	}

	go routeMgr(aliceConn, aliceMgr)
	go routeMgr(bobConn, bobMgr)

	timeout := time.After(5 * time.Second)

	var ar result
	select {
	case ar = <-aliceDone:
	case <-timeout:
		t.Fatal("timeout: alice handshake did not complete")
	}

	var br result
	select {
	case br = <-bobDone:
	case <-timeout:
		t.Fatal("timeout: bob handshake did not complete")
	}

	if ar.host.VpnIP != bob.cert.VpnIP.Addr() {
		t.Errorf("alice HostInfo.VpnIP = %v, want %v", ar.host.VpnIP, bob.cert.VpnIP.Addr())
	}
	if ar.host.SendCipher == nil || ar.host.RecvCipher == nil {
		t.Error("alice HostInfo: nil cipher(s)")
	}

	if br.host.VpnIP != alice.cert.VpnIP.Addr() {
		t.Errorf("bob HostInfo.VpnIP = %v, want %v", br.host.VpnIP, alice.cert.VpnIP.Addr())
	}
	if br.host.SendCipher == nil || br.host.RecvCipher == nil {
		t.Error("bob HostInfo: nil cipher(s)")
	}

	// Bob is the responder - no queued packets on his side.
	if len(br.pending) != 0 {
		t.Errorf("bob pending = %d, want 0", len(br.pending))
	}
}

func TestHandshakeManagerQueuedPackets(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caPool := []*cert.Certificate{ca}

	alice := makeMgrPeer(t, ca, caKey, "alice", "10.0.0.1/24")
	bob := makeMgrPeer(t, ca, caKey, "bob", "10.0.0.2/24")

	aliceConn, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("alice Listen: %v", err)
	}
	defer aliceConn.Close()

	bobConn, err := udp.Listen("127.0.0.1", 0)
	if err != nil {
		t.Fatalf("bob Listen: %v", err)
	}
	defer bobConn.Close()

	aliceDone := make(chan [][]byte, 1)
	aliceMgr := neth.NewHandshakeManager(
		alice.cert,
		alice.dhKey,
		caPool,
		aliceConn,
		func(_ *neth.HostInfo, pending [][]byte) {
			aliceDone <- pending
		},
	)

	bobMgr := neth.NewHandshakeManager(
		bob.cert,
		bob.dhKey,
		caPool,
		bobConn,
		func(_ *neth.HostInfo, _ [][]byte) {},
	)

	// Initiate the handshake and queue two packets before routing starts so
	// they are guaranteed to be in the pending list.
	if err := aliceMgr.StartHandshake(bob.cert.VpnIP.Addr(), bobConn.LocalAddr(), bob.cert); err != nil {
		t.Fatalf("StartHandshake: %v", err)
	}
	packets := [][]byte{[]byte("first"), []byte("second")}
	for _, p := range packets {
		aliceMgr.QueuePacket(bob.cert.VpnIP.Addr(), p)
	}

	go routeMgr(aliceConn, aliceMgr)
	go routeMgr(bobConn, bobMgr)

	var pending [][]byte
	select {
	case pending = <-aliceDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout: handshake did not complete")
	}

	if len(pending) != len(packets) {
		t.Fatalf("pending count = %d, want %d", len(pending), len(packets))
	}
	for i, want := range packets {
		if string(pending[i]) != string(want) {
			t.Errorf("pending[%d] = %q, want %q", i, pending[i], want)
		}
	}
}
