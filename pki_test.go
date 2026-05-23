package neth_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rykth/neth"
	"github.com/rykth/neth/cert"
	"github.com/rykth/neth/config"
)

type pkiFixture struct {
	caPath   string
	certPath string
	keyPath  string
	privKey  []byte
}

func newPKIFixture(t *testing.T) pkiFixture {
	t.Helper()
	dir := t.TempDir()

	caCert, caKey, err := cert.GenerateCA("test-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	caPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caPath, caCert.PEM(), 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}

	privKey, pubKey, err := cert.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	vpnPrefix := netip.MustParsePrefix("10.0.0.1/24")
	nodeCert, err := caCert.Sign("test-node", vpnPrefix, nil, pubKey, 24*time.Hour, caKey)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	certPath := filepath.Join(dir, "node.crt")
	if err := os.WriteFile(certPath, nodeCert.PEM(), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	keyPEM, err := cert.MarshalX25519PrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalX25519PrivateKey: %v", err)
	}
	keyPath := filepath.Join(dir, "node.key")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return pkiFixture{
		caPath:   caPath,
		certPath: certPath,
		keyPath:  keyPath,
		privKey:  privKey,
	}
}

func TestLoadPKISuccess(t *testing.T) {
	fix := newPKIFixture(t)

	pki, err := neth.LoadPKI(config.PKIConfig{
		CA:   fix.caPath,
		Cert: fix.certPath,
		Key:  fix.keyPath,
	})
	if err != nil {
		t.Fatalf("LoadPKI: %v", err)
	}

	if len(pki.CACerts) != 1 {
		t.Errorf("CACerts count = %d, want 1", len(pki.CACerts))
	}
	if pki.NodeCert == nil {
		t.Fatal("NodeCert is nil")
	}
	if pki.NodeCert.Name() != "test-node" {
		t.Errorf("NodeCert.Name = %q, want test-node", pki.NodeCert.Name())
	}
	if len(pki.Curve25519Key) != 32 {
		t.Errorf("Curve25519Key len = %d, want 32", len(pki.Curve25519Key))
	}
	for i, b := range pki.Curve25519Key {
		if b != fix.privKey[i] {
			t.Errorf("Curve25519Key differs at byte %d", i)
			break
		}
	}
}

func TestLoadPKIMissingCA(t *testing.T) {
	fix := newPKIFixture(t)
	_, err := neth.LoadPKI(config.PKIConfig{
		CA:   fix.caPath + ".missing",
		Cert: fix.certPath,
		Key:  fix.keyPath,
	})
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
}

func TestLoadPKIMissingCert(t *testing.T) {
	fix := newPKIFixture(t)
	_, err := neth.LoadPKI(config.PKIConfig{
		CA:   fix.caPath,
		Cert: fix.certPath + ".missing",
		Key:  fix.keyPath,
	})
	if err == nil {
		t.Fatal("expected error for missing cert file")
	}
}

func TestLoadPKIMissingKey(t *testing.T) {
	fix := newPKIFixture(t)
	_, err := neth.LoadPKI(config.PKIConfig{
		CA:   fix.caPath,
		Cert: fix.certPath,
		Key:  fix.keyPath + ".missing",
	})
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestLoadPKIWrongCA(t *testing.T) {
	dir := t.TempDir()

	otherCA, _, err := cert.GenerateCA("other-ca", 24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	otherCAPath := filepath.Join(dir, "other-ca.crt")
	if err := os.WriteFile(otherCAPath, otherCA.PEM(), 0o600); err != nil {
		t.Fatalf("write other CA: %v", err)
	}

	// Real cert + key signed by fix's CA.
	fix := newPKIFixture(t)

	_, err = neth.LoadPKI(config.PKIConfig{
		CA:   otherCAPath, // wrong CA
		Cert: fix.certPath,
		Key:  fix.keyPath,
	})
	if err == nil {
		t.Fatal("expected error when cert is signed by different CA")
	}
}

func TestLoadPKIKeyMismatch(t *testing.T) {
	fix := newPKIFixture(t)

	dir := t.TempDir()
	wrongPriv, _, err := cert.GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}
	wrongKeyPEM, err := cert.MarshalX25519PrivateKey(wrongPriv)
	if err != nil {
		t.Fatalf("MarshalX25519PrivateKey: %v", err)
	}
	wrongKeyPath := filepath.Join(dir, "wrong.key")
	if err := os.WriteFile(wrongKeyPath, wrongKeyPEM, 0o600); err != nil {
		t.Fatalf("write wrong key: %v", err)
	}

	_, err = neth.LoadPKI(config.PKIConfig{
		CA:   fix.caPath,
		Cert: fix.certPath,
		Key:  wrongKeyPath,
	})
	if err == nil {
		t.Fatal("expected error when key does not match certificate")
	}
}

func TestLoadPKICAIsNotCA(t *testing.T) {
	fix := newPKIFixture(t)

	_, err := neth.LoadPKI(config.PKIConfig{
		CA:   fix.certPath, // node cert used as CA — must be rejected
		Cert: fix.certPath,
		Key:  fix.keyPath,
	})
	if err == nil {
		t.Fatal("expected error when CA path points to a node cert")
	}
}
