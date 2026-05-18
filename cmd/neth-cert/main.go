package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rykth/neth/cert"
)

const usage = `neth-cert - neth certificate management

Usage:
  neth-cert ca      --name <name> [--duration <dur>] [--out-dir <dir>]
  neth-cert sign    --ca-crt <file> --ca-key <file> --name <name> --ip <cidr>
                    [--groups <g1,g2,...>] [--duration <dur>] [--out-dir <dir>]
  neth-cert verify  --ca-crt <file> --cert <file>
  neth-cert print   --cert <file>

Durations are Go duration strings, e.g. 8760h (1 year), 720h (30 days).
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}
	var err error
	switch os.Args[1] {
	case "ca":
		err = cmdCA(os.Args[2:])
	case "sign":
		err = cmdSign(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "print":
		err = cmdPrint(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// cmdCA creates a new CA certificate and private key.
func cmdCA(args []string) error {
	fs := flag.NewFlagSet("ca", flag.ContinueOnError)
	name := fs.String("name", "", "CA common name (required)")
	dur := fs.Duration("duration", 8760*time.Hour, "validity duration")
	outDir := fs.String("out-dir", ".", "directory to write output files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("--name is required")
	}

	ca, caKey, err := cert.GenerateCA(*name, *dur)
	if err != nil {
		return fmt.Errorf("generate CA: %w", err)
	}

	crtPath := filepath.Join(*outDir, *name+".crt")
	keyPath := filepath.Join(*outDir, *name+".key")

	if err := writeFile(crtPath, ca.PEM(), 0o644); err != nil {
		return err
	}
	keyPEM, err := cert.MarshalEd25519PrivateKey(caKey)
	if err != nil {
		return err
	}
	if err := writeFile(keyPath, keyPEM, 0o600); err != nil {
		return err
	}

	fmt.Printf("CA certificate : %s\n", crtPath)
	fmt.Printf("CA private key : %s\n", keyPath)
	printCertSummary(ca)
	return nil
}

// cmdSign issues a new node certificate signed by an existing CA.
func cmdSign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	caCrtPath := fs.String("ca-crt", "", "path to CA certificate (required)")
	caKeyPath := fs.String("ca-key", "", "path to CA private key (required)")
	name := fs.String("name", "", "node common name (required)")
	ip := fs.String("ip", "", "VPN IP address with prefix, e.g. 10.0.0.1/24 (required)")
	groups := fs.String("groups", "", "comma-separated group names")
	dur := fs.Duration("duration", 8760*time.Hour, "validity duration")
	outDir := fs.String("out-dir", ".", "directory to write output files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caCrtPath == "" || *caKeyPath == "" || *name == "" || *ip == "" {
		return fmt.Errorf("--ca-crt, --ca-key, --name, and --ip are required")
	}

	vpnIP, err := netip.ParsePrefix(*ip)
	if err != nil {
		return fmt.Errorf("invalid --ip %q: %w", *ip, err)
	}

	caPEM, err := os.ReadFile(*caCrtPath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	ca, err := cert.Parse(caPEM)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}
	if !ca.IsCA() {
		return fmt.Errorf("%s is not a CA certificate", *caCrtPath)
	}

	caKeyPEM, err := os.ReadFile(*caKeyPath)
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}
	caKey, err := cert.ParseEd25519PrivateKey(caKeyPEM)
	if err != nil {
		return fmt.Errorf("parse CA key: %w", err)
	}

	// Ensure the key matches the certificate.
	expectedPub := caKey.Public().(ed25519.PublicKey)
	if ca.X509().PublicKey.(ed25519.PublicKey) != nil {
		certPub, ok := ca.X509().PublicKey.(ed25519.PublicKey)
		if ok && string(certPub) != string(expectedPub) {
			return fmt.Errorf("CA key does not match CA certificate")
		}
	}

	nodePriv, nodePub, err := cert.GenerateX25519KeyPair()
	if err != nil {
		return fmt.Errorf("generate node key: %w", err)
	}

	var groupList []string
	if *groups != "" {
		for _, g := range strings.Split(*groups, ",") {
			if g = strings.TrimSpace(g); g != "" {
				groupList = append(groupList, g)
			}
		}
	}

	node, err := ca.Sign(*name, vpnIP, groupList, nodePub, *dur, caKey)
	if err != nil {
		return fmt.Errorf("sign certificate: %w", err)
	}

	crtPath := filepath.Join(*outDir, *name+".crt")
	keyPath := filepath.Join(*outDir, *name+".key")

	if err := writeFile(crtPath, node.PEM(), 0o644); err != nil {
		return err
	}
	nodeKeyPEM, err := cert.MarshalX25519PrivateKey(nodePriv)
	if err != nil {
		return err
	}
	if err := writeFile(keyPath, nodeKeyPEM, 0o600); err != nil {
		return err
	}

	fmt.Printf("Node certificate : %s\n", crtPath)
	fmt.Printf("Node private key : %s\n", keyPath)
	printCertSummary(node)
	return nil
}

// cmdVerify checks a node certificate against a CA.
func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	caCrtPath := fs.String("ca-crt", "", "path to CA certificate (required)")
	certPath := fs.String("cert", "", "path to certificate to verify (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *caCrtPath == "" || *certPath == "" {
		return fmt.Errorf("--ca-crt and --cert are required")
	}

	caPEM, err := os.ReadFile(*caCrtPath)
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	ca, err := cert.Parse(caPEM)
	if err != nil {
		return fmt.Errorf("parse CA certificate: %w", err)
	}

	nodePEM, err := os.ReadFile(*certPath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	node, err := cert.Parse(nodePEM)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	if err := cert.Verify(node, []*cert.Certificate{ca}, time.Now()); err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	fmt.Println("OK: certificate is valid")
	return nil
}

// cmdPrint pretty-prints a certificate's fields.
func cmdPrint(args []string) error {
	fs := flag.NewFlagSet("print", flag.ContinueOnError)
	certPath := fs.String("cert", "", "path to certificate (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *certPath == "" {
		return fmt.Errorf("--cert is required")
	}

	pemBytes, err := os.ReadFile(*certPath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	c, err := cert.Parse(pemBytes)
	if err != nil {
		return fmt.Errorf("parse certificate: %w", err)
	}

	printCertSummary(c)
	return nil
}

func printCertSummary(c *cert.Certificate) {
	x := c.X509()
	fmt.Printf("  Name        : %s\n", c.Name())
	fmt.Printf("  Is CA       : %v\n", c.IsCA())
	if c.VpnIP.IsValid() {
		fmt.Printf("  VPN IP      : %s\n", c.VpnIP)
	}
	if len(c.Groups) > 0 {
		fmt.Printf("  Groups      : %s\n", strings.Join(c.Groups, ", "))
	}
	if len(c.X25519PublicKey) > 0 {
		fmt.Printf("  X25519 key  : %s\n", hex.EncodeToString(c.X25519PublicKey))
	}
	fmt.Printf("  Not before  : %s\n", x.NotBefore.Format(time.RFC3339))
	fmt.Printf("  Not after   : %s\n", x.NotAfter.Format(time.RFC3339))
	fmt.Printf("  Fingerprint : %s\n", hex.EncodeToString(c.Fingerprint()))
}

func writeFile(path string, data []byte, mode os.FileMode) error {
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
