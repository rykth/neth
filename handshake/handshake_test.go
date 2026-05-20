package handshake_test

import (
	"crypto/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/flynn/noise"
	"google.golang.org/protobuf/proto"

	"github.com/rykth/neth/cert"
	"github.com/rykth/neth/handshake"
)

type peer struct {
	cert  *cert.Certificate
	dhKey noise.DHKey
}

func makePeer(t *testing.T, name, vpnCIDR string) peer {
	t.Helper()

	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	priv, pub, err := cert.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	prefix, err := netip.ParsePrefix(vpnCIDR)
	if err != nil {
		t.Fatalf("ParsePrefix: %v", err)
	}

	nodeCert, err := ca.Sign(name, prefix, nil, pub, 24*time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	return peer{cert: nodeCert, dhKey: noise.DHKey{Private: priv, Public: pub}}
}

func TestNoiseRoundTrip(t *testing.T) {
	alice := makePeer(t, "alice", "10.0.0.1/24")
	bob := makePeer(t, "bob", "10.0.0.2/24")

	pskAB := handshake.DerivePreSharedKey(alice.cert, bob.cert)
	pskBA := handshake.DerivePreSharedKey(bob.cert, alice.cert)
	if string(pskAB) != string(pskBA) {
		t.Fatal("PSK not symmetric")
	}

	// Initiator (Alice) knows Bob's static public key in advance (from cert).
	aliceHS, err := handshake.NewInitiatorState(alice.dhKey, bob.dhKey.Public, pskAB)
	if err != nil {
		t.Fatalf("NewInitiatorState: %v", err)
	}
	// Responder (Bob) only needs its own key + PSK.
	bobHS, err := handshake.NewResponderState(bob.dhKey, pskAB)
	if err != nil {
		t.Fatalf("NewResponderState: %v", err)
	}

	payload0 := []byte("alice handshake init")
	msg0, cs1a0, cs2a0, err := aliceHS.WriteMessage(nil, payload0)
	if err != nil {
		t.Fatalf("alice WriteMessage: %v", err)
	}
	if cs1a0 != nil || cs2a0 != nil {
		t.Error("cipher states must be nil before IK handshake completes (initiator)")
	}

	gotPayload0, cs1b0, cs2b0, err := bobHS.ReadMessage(nil, msg0)
	if err != nil {
		t.Fatalf("bob ReadMessage msg0: %v", err)
	}
	if cs1b0 != nil || cs2b0 != nil {
		t.Error("cipher states must be nil before IK handshake completes (responder after msg0)")
	}
	if string(gotPayload0) != string(payload0) {
		t.Errorf("msg0 payload = %q, want %q", gotPayload0, payload0)
	}

	payload1 := []byte("bob handshake reply")
	msg1, cs1b, cs2b, err := bobHS.WriteMessage(nil, payload1)
	if err != nil {
		t.Fatalf("bob WriteMessage: %v", err)
	}
	if cs1b == nil || cs2b == nil {
		t.Fatal("cipher states must be non-nil after responder writes msg1")
	}

	gotPayload1, cs1a, cs2a, err := aliceHS.ReadMessage(nil, msg1)
	if err != nil {
		t.Fatalf("alice ReadMessage msg1: %v", err)
	}
	if cs1a == nil || cs2a == nil {
		t.Fatal("cipher states must be non-nil after initiator reads msg1")
	}
	if string(gotPayload1) != string(payload1) {
		t.Errorf("msg1 payload = %q, want %q", gotPayload1, payload1)
	}

	ad := []byte("neth-header-bytes")
	plain := []byte("hello encrypted world")

	// Alice (c1) → Bob (c1 decrypts)
	ct, err := cs1a.Encrypt(nil, ad, plain)
	if err != nil {
		t.Fatalf("alice encrypt: %v", err)
	}
	pt, err := cs1b.Decrypt(nil, ad, ct)
	if err != nil {
		t.Fatalf("bob decrypt (alice→bob): %v", err)
	}
	if string(pt) != string(plain) {
		t.Errorf("alice→bob roundtrip: got %q want %q", pt, plain)
	}

	// Bob (c2) → Alice (c2 decrypts)
	ct2, err := cs2b.Encrypt(nil, ad, plain)
	if err != nil {
		t.Fatalf("bob encrypt: %v", err)
	}
	pt2, err := cs2a.Decrypt(nil, ad, ct2)
	if err != nil {
		t.Fatalf("alice decrypt (bob→alice): %v", err)
	}
	if string(pt2) != string(plain) {
		t.Errorf("bob→alice roundtrip: got %q want %q", pt2, plain)
	}
}

func TestBuildAndVerifyHMAC(t *testing.T) {
	alice := makePeer(t, "alice", "10.0.0.1/24")

	noiseBytes := make([]byte, 32)
	if _, err := rand.Read(noiseBytes); err != nil {
		t.Fatal(err)
	}

	msg, err := handshake.BuildInitiatorMessage(alice.cert, noiseBytes, 42)
	if err != nil {
		t.Fatalf("BuildInitiatorMessage: %v", err)
	}

	if err := handshake.VerifyHMAC(msg, alice.cert); err != nil {
		t.Fatalf("VerifyHMAC should accept valid message: %v", err)
	}

	msg.NoisePayload[0] ^= 0xFF
	if err := handshake.VerifyHMAC(msg, alice.cert); err == nil {
		t.Error("VerifyHMAC should reject tampered noise payload")
	}
}

func TestDerivePreSharedKey(t *testing.T) {
	alice := makePeer(t, "alice", "10.0.0.1/24")
	bob := makePeer(t, "bob", "10.0.0.2/24")
	carol := makePeer(t, "carol", "10.0.0.3/24")

	pskAB := handshake.DerivePreSharedKey(alice.cert, bob.cert)
	pskBA := handshake.DerivePreSharedKey(bob.cert, alice.cert)

	if len(pskAB) != 32 {
		t.Fatalf("PSK length = %d, want 32", len(pskAB))
	}
	if string(pskAB) != string(pskBA) {
		t.Error("DerivePreSharedKey must be symmetric (XOR)")
	}

	pskAC := handshake.DerivePreSharedKey(alice.cert, carol.cert)
	if string(pskAB) == string(pskAC) {
		t.Error("different cert pairs should produce different PSKs")
	}
}

func TestParseHandshakeMessage(t *testing.T) {
	alice := makePeer(t, "alice", "10.0.0.1/24")

	noiseBytes := make([]byte, 48)
	if _, err := rand.Read(noiseBytes); err != nil {
		t.Fatal(err)
	}

	original, err := handshake.BuildInitiatorMessage(alice.cert, noiseBytes, 77)
	if err != nil {
		t.Fatalf("BuildInitiatorMessage: %v", err)
	}

	raw, err := proto.Marshal(original)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}

	parsed, err := handshake.ParseHandshakeMessage(raw)
	if err != nil {
		t.Fatalf("ParseHandshakeMessage: %v", err)
	}
	if string(parsed.NoisePayload) != string(noiseBytes) {
		t.Error("NoisePayload mismatch after proto round-trip")
	}
	if string(parsed.Hmac) != string(original.Hmac) {
		t.Error("HMAC mismatch after proto round-trip")
	}

	details, err := handshake.ParseDetails(parsed)
	if err != nil {
		t.Fatalf("ParseDetails: %v", err)
	}
	if details.InitiatorIndex != 77 {
		t.Errorf("InitiatorIndex = %d, want 77", details.InitiatorIndex)
	}
}
