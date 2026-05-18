package cert

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/netip"
)

const pemTypeCert = "CERTIFICATE"

// Certificate is a parsed neth certificate.
type Certificate struct {
	raw  []byte // original DER bytes; source of truth for fingerprint/PEM
	x509 *x509.Certificate

	// Fields derived from custom X.509 extensions.
	VpnIP  netip.Prefix
	Groups []string

	// X25519PublicKey is the Curve25519 public key for the Noise handshake.
	// For node certs it comes from the X.509 SubjectPublicKeyInfo (id-X25519).
	// For CA certs this is nil - CAs use Ed25519 only.
	X25519PublicKey []byte
}

// Parse decodes a PEM-encoded certificate and extracts neth-specific fields.
func Parse(pemBytes []byte) (*Certificate, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("cert: no PEM block found")
	}
	if block.Type != pemTypeCert {
		return nil, fmt.Errorf("cert: expected %q PEM block, got %q", pemTypeCert, block.Type)
	}
	return parseDER(block.Bytes)
}

func parseDER(der []byte) (*Certificate, error) {
	x, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("cert: parse X.509: %w", err)
	}
	c := &Certificate{raw: der, x509: x}

	// Walk extensions for neth-specific fields.
	for _, ext := range x.Extensions {
		switch {
		case ext.Id.Equal(oidVpnIP):
			if c.VpnIP, err = decodeVpnIP(ext); err != nil {
				return nil, err
			}
		case ext.Id.Equal(oidGroups):
			if c.Groups, err = decodeGroups(ext); err != nil {
				return nil, err
			}
		case ext.Id.Equal(oidCurve25519Key):
			if c.X25519PublicKey, err = decodeCurve25519Key(ext); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

// PEM returns the PEM-encoded certificate.
func (c *Certificate) PEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: pemTypeCert, Bytes: c.raw})
}

// Fingerprint returns the SHA-256 digest of the raw DER bytes.
func (c *Certificate) Fingerprint() []byte {
	h := sha256.Sum256(c.raw)
	return h[:]
}

// IsCA reports whether this is a CA certificate.
func (c *Certificate) IsCA() bool {
	return c.x509.IsCA
}

// Name returns the Common Name from the certificate subject.
func (c *Certificate) Name() string {
	return c.x509.Subject.CommonName
}

// X509 returns the underlying *x509.Certificate for use with stdlib APIs.
func (c *Certificate) X509() *x509.Certificate {
	return c.x509
}
