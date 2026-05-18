package cert_test

import (
	"bytes"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/rykth/neth/cert"
)

func TestGenerateCA(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if caKey == nil {
		t.Fatal("GenerateCA returned nil private key")
	}
	if !ca.IsCA() {
		t.Error("CA certificate IsCA() should be true")
	}
	if ca.Name() != "test-ca" {
		t.Errorf("Name(): got %q, want %q", ca.Name(), "test-ca")
	}
	if len(ca.Fingerprint()) != 32 {
		t.Errorf("Fingerprint() length: got %d, want 32", len(ca.Fingerprint()))
	}
	if ca.X25519PublicKey != nil {
		t.Error("CA certificate should not have an X25519PublicKey")
	}
}

func TestCAVerify(t *testing.T) {
	ca, _, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := cert.VerifyCA(ca, time.Now()); err != nil {
		t.Errorf("VerifyCA: %v", err)
	}
}

func TestSignAndVerifyNode(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	_, nodePub, err := cert.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	vpnIP := netip.MustParsePrefix("10.0.0.1/24")
	groups := []string{"infra", "web"}

	node, err := ca.Sign("node1", vpnIP, groups, nodePub, 12*time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if node.IsCA() {
		t.Error("node certificate IsCA() should be false")
	}
	if node.Name() != "node1" {
		t.Errorf("Name(): got %q, want %q", node.Name(), "node1")
	}
	if node.VpnIP != vpnIP {
		t.Errorf("VpnIP: got %v, want %v", node.VpnIP, vpnIP)
	}
	if !reflect.DeepEqual(node.Groups, groups) {
		t.Errorf("Groups: got %v, want %v", node.Groups, groups)
	}
	if !bytes.Equal(node.X25519PublicKey, nodePub) {
		t.Error("X25519PublicKey mismatch")
	}

	if err := cert.Verify(node, []*cert.Certificate{ca}, time.Now()); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestSignNoGroups(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	_, nodePub, _ := cert.GenerateX25519KeyPair()

	node, err := ca.Sign("node1", netip.MustParsePrefix("10.0.0.1/24"), nil, nodePub, time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if node.Groups != nil {
		t.Errorf("Groups: expected nil, got %v", node.Groups)
	}
	if err := cert.Verify(node, []*cert.Certificate{ca}, time.Now()); err != nil {
		t.Errorf("Verify: %v", err)
	}
}

func TestPEMRoundTrip(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	_, nodePub, _ := cert.GenerateX25519KeyPair()
	vpnIP := netip.MustParsePrefix("10.0.0.5/24")
	groups := []string{"ops"}

	node, err := ca.Sign("node1", vpnIP, groups, nodePub, time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	node2, err := cert.Parse(node.PEM())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !bytes.Equal(node2.Fingerprint(), node.Fingerprint()) {
		t.Error("Fingerprint mismatch after PEM round-trip")
	}
	if node2.VpnIP != node.VpnIP {
		t.Errorf("VpnIP after round-trip: got %v, want %v", node2.VpnIP, node.VpnIP)
	}
	if !reflect.DeepEqual(node2.Groups, node.Groups) {
		t.Errorf("Groups after round-trip: got %v, want %v", node2.Groups, node.Groups)
	}
	if !bytes.Equal(node2.X25519PublicKey, node.X25519PublicKey) {
		t.Error("X25519PublicKey mismatch after PEM round-trip")
	}
}

func TestVerifyExpiredCert(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	_, nodePub, _ := cert.GenerateX25519KeyPair()

	node, err := ca.Sign("node1", netip.MustParsePrefix("10.0.0.1/24"), nil, nodePub, time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	future := time.Now().Add(2 * time.Hour)
	if err := cert.Verify(node, []*cert.Certificate{ca}, future); err == nil {
		t.Error("expected error verifying expired certificate, got nil")
	}
}

func TestVerifyExpiredCA(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", time.Second)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	_, nodePub, _ := cert.GenerateX25519KeyPair()

	node, err := ca.Sign("node1", netip.MustParsePrefix("10.0.0.1/24"), nil, nodePub, 10*time.Second, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	future := time.Now().Add(2 * time.Second)
	if err := cert.Verify(node, []*cert.Certificate{ca}, future); err == nil {
		t.Error("expected error when CA is expired, got nil")
	}
}

func TestVerifyWrongCA(t *testing.T) {
	ca1, caKey1, _ := cert.GenerateCA("ca1", 24*time.Hour)
	ca2, _, _ := cert.GenerateCA("ca2", 24*time.Hour)
	_, nodePub, _ := cert.GenerateX25519KeyPair()

	node, err := ca1.Sign("node1", netip.MustParsePrefix("10.0.0.1/24"), nil, nodePub, time.Hour, caKey1)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := cert.Verify(node, []*cert.Certificate{ca2}, time.Now()); err == nil {
		t.Error("expected error verifying cert with wrong CA, got nil")
	}
}

func TestVerifyRejectsCAAsNode(t *testing.T) {
	ca, _, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := cert.Verify(ca, []*cert.Certificate{ca}, time.Now()); err == nil {
		t.Error("Verify should reject a CA certificate, got nil")
	}
}

func TestVerifyCARejectsNodeCert(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	_, nodePub, _ := cert.GenerateX25519KeyPair()
	node, err := ca.Sign("node1", netip.MustParsePrefix("10.0.0.1/24"), nil, nodePub, time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := cert.VerifyCA(node, time.Now()); err == nil {
		t.Error("VerifyCA should reject a non-CA certificate, got nil")
	}
}

func TestEd25519KeyRoundTrip(t *testing.T) {
	_, caKey, err := cert.GenerateCA("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	pemBytes, err := cert.MarshalEd25519PrivateKey(caKey)
	if err != nil {
		t.Fatalf("MarshalEd25519PrivateKey: %v", err)
	}
	key2, err := cert.ParseEd25519PrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParseEd25519PrivateKey: %v", err)
	}
	if !bytes.Equal(key2, caKey) {
		t.Error("Ed25519 private key mismatch after round-trip")
	}
}

func TestX25519KeyRoundTrip(t *testing.T) {
	priv, _, err := cert.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	pemBytes, err := cert.MarshalX25519PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalX25519PrivateKey: %v", err)
	}
	priv2, err := cert.ParseX25519PrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParseX25519PrivateKey: %v", err)
	}
	if !bytes.Equal(priv2, priv) {
		t.Error("X25519 private key mismatch after round-trip")
	}
}

func TestParseInvalidPEM(t *testing.T) {
	cases := []struct {
		name string
		pem  []byte
	}{
		{"empty", []byte{}},
		{"garbage", []byte("not pem at all")},
		{"wrong type", []byte("-----BEGIN WRONG TYPE-----\naGVsbG8=\n-----END WRONG TYPE-----\n")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := cert.Parse(tc.pem); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestMultipleGroupsIPv6(t *testing.T) {
	ca, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	_, nodePub, _ := cert.GenerateX25519KeyPair()
	vpnIP := netip.MustParsePrefix("fd00::1/64")
	groups := []string{"group-a", "group-b", "group-c"}

	node, err := ca.Sign("ipv6-node", vpnIP, groups, nodePub, time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	node2, err := cert.Parse(node.PEM())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if node2.VpnIP != vpnIP {
		t.Errorf("VpnIP: got %v, want %v", node2.VpnIP, vpnIP)
	}
	if !reflect.DeepEqual(node2.Groups, groups) {
		t.Errorf("Groups: got %v, want %v", node2.Groups, groups)
	}
}
