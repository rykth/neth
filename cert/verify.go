package cert

import (
	"crypto/x509"
	"fmt"
	"time"
)

// Verify checks that cert was signed by a CA in caPool and is valid at now.
func Verify(cert *Certificate, caPool []*Certificate, now time.Time) error {
	if cert.IsCA() {
		return fmt.Errorf("verify: expected node certificate, got CA certificate")
	}
	pool := x509.NewCertPool()
	for _, ca := range caPool {
		pool.AddCert(ca.x509)
	}
	opts := x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		// We do not use TLS extended key usages - neth has its own access model.
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := cert.x509.Verify(opts); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return nil
}

// VerifyCA checks that ca is a valid, self-signed CA certificate.
func VerifyCA(ca *Certificate, now time.Time) error {
	if !ca.IsCA() {
		return fmt.Errorf("verify CA: certificate is not a CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.x509)
	opts := x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	if _, err := ca.x509.Verify(opts); err != nil {
		return fmt.Errorf("verify CA: %w", err)
	}
	return nil
}
