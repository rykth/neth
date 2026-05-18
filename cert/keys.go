package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// GenerateX25519KeyPair generates a new X25519 (Curve25519) keypair for use
// in the Noise Protocol handshake.
func GenerateX25519KeyPair() (priv, pub []byte, err error) {
	priv = make([]byte, 32)
	if _, err = rand.Read(priv); err != nil {
		return nil, nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	// Clamp the scalar per RFC 7748 §5.
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	pub, err = curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		return nil, nil, fmt.Errorf("derive X25519 public key: %w", err)
	}
	return priv, pub, nil
}

// MarshalEd25519PrivateKey encodes an Ed25519 private key.
func MarshalEd25519PrivateKey(key ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal Ed25519 private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParseEd25519PrivateKey decodes a PKCS#8 PEM-encoded Ed25519 private key.
func ParseEd25519PrivateKey(pemBytes []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("parse Ed25519 private key: no PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Ed25519 private key: %w", err)
	}
	ed, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parse Ed25519 private key: PEM contains a %T, not an Ed25519 key", key)
	}
	return ed, nil
}

const pemTypeCurve25519Key = "NETH CURVE25519 PRIVATE KEY"

// MarshalX25519PrivateKey encodes a raw 32-byte Curve25519 private key as PEM.
func MarshalX25519PrivateKey(key []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("marshal X25519 private key: expected 32 bytes, got %d", len(key))
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCurve25519Key, Bytes: key}), nil
}

// ParseX25519PrivateKey decodes a PEM-encoded Curve25519 private key.
func ParseX25519PrivateKey(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("parse X25519 private key: no PEM block")
	}
	if block.Type != pemTypeCurve25519Key {
		return nil, fmt.Errorf("parse X25519 private key: expected %q, got %q", pemTypeCurve25519Key, block.Type)
	}
	if len(block.Bytes) != 32 {
		return nil, fmt.Errorf("parse X25519 private key: expected 32 bytes, got %d", len(block.Bytes))
	}
	return block.Bytes, nil
}
