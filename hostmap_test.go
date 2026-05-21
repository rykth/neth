package neth_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"

	"github.com/rykth/neth"
	"github.com/rykth/neth/noiseutil"
)

func makeAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	return gcm
}

func makeHost(t *testing.T, vpnIP string, idx uint32) *neth.HostInfo {
	t.Helper()
	return &neth.HostInfo{
		VpnIP:      netip.MustParseAddr(vpnIP),
		Remote:     &net.UDPAddr{IP: net.ParseIP("1.2.3.4"), Port: 4242},
		Index:      idx,
		SendCipher: makeAEAD(t),
		RecvCipher: makeAEAD(t),
	}
}

func TestHostMapAddAndGet(t *testing.T) {
	m := neth.NewHostMap()

	h := makeHost(t, "10.0.0.1", 1)
	m.Add(h)

	got := m.GetByVpnIP(netip.MustParseAddr("10.0.0.1"))
	if got != h {
		t.Error("GetByVpnIP returned wrong host")
	}

	got2 := m.GetByIndex(1)
	if got2 != h {
		t.Error("GetByIndex returned wrong host")
	}
}

func TestHostMapMiss(t *testing.T) {
	m := neth.NewHostMap()
	if m.GetByVpnIP(netip.MustParseAddr("10.0.0.99")) != nil {
		t.Error("expected nil for unknown IP")
	}
	if m.GetByIndex(999) != nil {
		t.Error("expected nil for unknown index")
	}
}

func TestHostMapRemove(t *testing.T) {
	m := neth.NewHostMap()
	h := makeHost(t, "10.0.0.2", 2)
	m.Add(h)
	m.Remove(netip.MustParseAddr("10.0.0.2"))

	if m.GetByVpnIP(netip.MustParseAddr("10.0.0.2")) != nil {
		t.Error("VPN IP should be gone after Remove")
	}
	if m.GetByIndex(2) != nil {
		t.Error("index should be gone after Remove")
	}
}

func TestHostMapReplace(t *testing.T) {
	m := neth.NewHostMap()
	h1 := makeHost(t, "10.0.0.3", 3)
	h2 := makeHost(t, "10.0.0.3", 4)
	m.Add(h1)
	m.Add(h2)

	if m.GetByVpnIP(netip.MustParseAddr("10.0.0.3")) != h2 {
		t.Error("Add should replace existing entry for same VPN IP")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	aead := makeAEAD(t)
	header := []byte{0x01, 0x02, 0x03, 0x04} // simulated neth header
	plain := []byte("hello overlay network")

	ct, err := noiseutil.Encrypt(aead, 0, header, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(ct) <= len(plain) {
		t.Error("ciphertext should be longer than plaintext (AEAD tag)")
	}

	pt, err := noiseutil.Decrypt(aead, 0, header, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(plain) {
		t.Errorf("roundtrip: got %q want %q", pt, plain)
	}
}

func TestEncryptWrongCounter(t *testing.T) {
	aead := makeAEAD(t)
	header := []byte("hdr")
	plain := []byte("test")

	ct, _ := noiseutil.Encrypt(aead, 10, header, plain)
	_, err := noiseutil.Decrypt(aead, 11, header, ct)
	if err == nil {
		t.Error("Decrypt with wrong counter must fail (different nonce)")
	}
}

func TestEncryptWrongAD(t *testing.T) {
	aead := makeAEAD(t)
	plain := []byte("test")

	ct, _ := noiseutil.Encrypt(aead, 0, []byte("header-A"), plain)
	_, err := noiseutil.Decrypt(aead, 0, []byte("header-B"), ct)
	if err == nil {
		t.Error("Decrypt with tampered header must fail (AEAD tag mismatch)")
	}
}

func TestCounterNonce(t *testing.T) {
	n := noiseutil.CounterNonce(0)
	if len(n) != 12 {
		t.Fatalf("nonce length = %d, want 12", len(n))
	}
	// Counter 0: first 8 bytes all zero, last 4 bytes zero
	for _, b := range n {
		if b != 0 {
			t.Error("counter 0 nonce should be all zeros")
			break
		}
	}

	n1 := noiseutil.CounterNonce(1)
	if n1[0] != 1 {
		t.Errorf("counter 1 nonce byte 0 = %d, want 1 (little-endian)", n1[0])
	}
}

func TestReplayWindowFresh(t *testing.T) {
	h := &neth.HostInfo{}
	// first time we see counter 0 is not a replay
	if h.CheckReplay(0) {
		t.Error("counter 0 should not be a replay on first sight")
	}

	// Second time is a replay
	if !h.CheckReplay(0) {
		t.Error("counter 0 should be a replay the second time")
	}
}

func TestReplayWindowAdvancing(t *testing.T) {
	h := &neth.HostInfo{}
	for i := uint64(0); i < 100; i++ {
		if h.CheckReplay(i) {
			t.Errorf("counter %d should not be a replay (first sight)", i)
		}
	}

	// all of 0..99 are now in the window; replay check must reject them
	for i := uint64(0); i < 100; i++ {
		if !h.CheckReplay(i) {
			t.Errorf("counter %d should be a replay (already seen)", i)
		}
	}
}

func TestReplayWindowTooOld(t *testing.T) {
	h := &neth.HostInfo{}
	if h.CheckReplay(5000) {
		t.Fatal("5000 should not be replay")
	}

	if !h.CheckReplay(0) {
		t.Error("counter 0 should be rejected as too old after window advance to 5000")
	}
}

func TestReplayWindowOutOfOrder(t *testing.T) {
	h := &neth.HostInfo{}
	h.CheckReplay(100)
	if h.CheckReplay(50) {
		t.Error("counter 50 should not be replay (not yet seen, within window)")
	}

	if !h.CheckReplay(50) {
		t.Error("counter 50 should be replay on second sight")
	}
}
