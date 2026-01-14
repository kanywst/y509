// Package main provides a utility script to generate demo certificates.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"os"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("Failed to generate certs: %v", err)
	}
	log.Println("Successfully generated testdata/demo/certs.pem")
}

func run() error {
	// Create output directory
	if err := os.MkdirAll("testdata/demo", 0755); err != nil {
		return err
	}

	// 1. Root CA
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Y509 Demo Root CA",
			Organization: []string{"Y509 Demo Org"},
		},
		NotBefore:             time.Now().AddDate(-10, 0, 0),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	rootDer, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}

	// 2. Intermediate CA
	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	intTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName:   "Y509 Demo Intermediate",
			Organization: []string{"Y509 Demo Org"},
		},
		NotBefore:             time.Now().AddDate(-5, 0, 0),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}

	intDer, err := x509.CreateCertificate(rand.Reader, intTmpl, rootTmpl, &intKey.PublicKey, rootKey)
	if err != nil {
		return err
	}

	intCert, _ := x509.ParseCertificate(intDer)

	// Helper to create leaf certs
	createLeaf := func(cn string, days int, sn int64) ([]byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}

		var notBefore, notAfter time.Time
		if days < 0 {
			// Expired: valid from [now + days - 365] to [now + days]
			notAfter = time.Now().AddDate(0, 0, days)
			notBefore = notAfter.AddDate(-1, 0, 0)
		} else {
			// Valid/Expiring: valid from [now - 1 day] to [now + days]
			notBefore = time.Now().AddDate(0, 0, -1)
			notAfter = time.Now().AddDate(0, 0, days)
		}

		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(sn),
			Subject: pkix.Name{
				CommonName:   cn,
				Organization: []string{"Y509 Demo Org"},
			},
			NotBefore:   notBefore,
			NotAfter:    notAfter,
			KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			DNSNames:    []string{cn, "internal.demo"},
		}

		return x509.CreateCertificate(rand.Reader, tmpl, intCert, &key.PublicKey, intKey)
	}

	// 3. Valid Leaf (1 year)
	validDer, err := createLeaf("valid.y509.demo", 365, 3)
	if err != nil {
		return err
	}

	// 4. Expired Leaf (Expired 10 days ago)
	expiredDer, err := createLeaf("expired.y509.demo", -10, 4)
	if err != nil {
		return err
	}

	// 5. Expiring Leaf (Expires in 5 days)
	expiringDer, err := createLeaf("expiring.y509.demo", 5, 5)
	if err != nil {
		return err
	}

	// Write to file (Mix order to show sorting/listing)
	f, err := os.Create("testdata/demo/certs.pem")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Order in file: Valid, Expired, Expiring, Intermediate, Root
	certs := [][]byte{validDer, expiredDer, expiringDer, intDer, rootDer}
	for _, cert := range certs {
		if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
			return err
		}
	}

	return nil
}
