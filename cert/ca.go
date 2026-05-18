package cert

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/netip"
	"time"
)

// GenerateCA creates a new self-signed CA certificate.
func GenerateCA(name string, duration time.Duration) (*Certificate, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:          newSerial(),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(duration),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CA certificate: %w", err)
	}
	cert, err := parseDER(der)
	if err != nil {
		return nil, nil, err
	}
	return cert, priv, nil
}

// Sign issues a new node certificate signed by this CA.
func (ca *Certificate) Sign(
	name string,
	vpnIP netip.Prefix,
	groups []string,
	curve25519Pub []byte,
	duration time.Duration,
	caKey crypto.Signer,
) (*Certificate, error) {
	// Ephemeral Ed25519 key required by X.509, not used by neth.
	nodePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sign: generate identity key: %w", err)
	}

	extVpnIP, err := encodeVpnIP(vpnIP)
	if err != nil {
		return nil, fmt.Errorf("sign: encode vpn_ip: %w", err)
	}
	extCurve, err := encodeCurve25519Key(curve25519Pub)
	if err != nil {
		return nil, fmt.Errorf("sign: encode curve25519_key: %w", err)
	}

	extras := []pkix.Extension{extVpnIP, extCurve}
	if len(groups) > 0 {
		extGroups, err := encodeGroups(groups)
		if err != nil {
			return nil, fmt.Errorf("sign: encode groups: %w", err)
		}
		extras = append(extras, extGroups)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber:    newSerial(),
		Subject:         pkix.Name{CommonName: name},
		NotBefore:       now,
		NotAfter:        now.Add(duration),
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: extras,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.x509, nodePub, caKey)
	if err != nil {
		return nil, fmt.Errorf("sign: create certificate: %w", err)
	}
	return parseDER(der)
}

func newSerial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// crypto/rand failure is fatal — the system's entropy source is broken.
		panic("cert: cannot generate serial number: " + err.Error())
	}
	return n
}
