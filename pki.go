package neth

import (
	"crypto/subtle"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/rykth/neth/cert"
	"github.com/rykth/neth/config"
)

// PKI holds the loaded and verified PKI material for this node.
type PKI struct {
	CACerts       []*cert.Certificate // CA certs used to verify peers
	NodeCert      *cert.Certificate   // this node's signed certificate
	Curve25519Key []byte              // raw 32-byte Curve25519 private key
}

// LoadPKI reads the CA certificate, node certificate, and Curve25519 private key
func LoadPKI(cfg config.PKIConfig) (*PKI, error) {
	caCert, err := loadAndParseCA(cfg.CA)
	if err != nil {
		return nil, err
	}

	nodeCert, err := loadAndParseNodeCert(cfg.Cert, caCert)
	if err != nil {
		return nil, err
	}

	privKey, err := loadAndVerifyKey(cfg.Key, nodeCert)
	if err != nil {
		return nil, err
	}

	return &PKI{
		CACerts:       []*cert.Certificate{caCert},
		NodeCert:      nodeCert,
		Curve25519Key: privKey,
	}, nil
}

func loadAndParseCA(path string) (*cert.Certificate, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("pki: read CA %q: %w", path, err)
	}
	caCert, err := cert.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CA: %w", err)
	}
	if err := cert.VerifyCA(caCert, time.Now()); err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	return caCert, nil
}

func loadAndParseNodeCert(path string, ca *cert.Certificate) (*cert.Certificate, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("pki: read cert %q: %w", path, err)
	}
	nodeCert, err := cert.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("pki: parse cert: %w", err)
	}
	if err := cert.Verify(nodeCert, []*cert.Certificate{ca}, time.Now()); err != nil {
		return nil, fmt.Errorf("pki: %w", err)
	}
	return nodeCert, nil
}

func loadAndVerifyKey(path string, nodeCert *cert.Certificate) ([]byte, error) {
	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("pki: read key %q: %w", path, err)
	}
	privKey, err := cert.ParseX25519PrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("pki: parse key: %w", err)
	}

	derivedPub, err := curve25519.X25519(privKey, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("pki: derive public key: %w", err)
	}
	if subtle.ConstantTimeCompare(derivedPub, nodeCert.X25519PublicKey) != 1 {
		return nil, fmt.Errorf("pki: private key does not match the public key in the certificate")
	}
	return privKey, nil
}
