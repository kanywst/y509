package model

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/kanywst/y509/pkg/certificate"
)

// TestRedialAgainstARealServer drives the whole path the r key runs: a real
// handshake, through certificate.FetchChain, back into the model.
//
// The server issues a fresh certificate per connection, so the serial on the
// selected certificate changes only if the redial genuinely went back to the
// wire. A fake Redialer cannot show that.
func TestRedialAgainstARealServer(t *testing.T) {
	addr := startRotatingTLSServer(t)

	dial := func(ctx context.Context) (*certificate.ConnectResult, error) {
		return certificate.FetchChain(ctx, addr, certificate.ConnectOptions{
			Timeout: 5 * time.Second,
		})
	}

	first, err := dial(context.Background())
	if err != nil {
		t.Fatalf("first dial: %v", err)
	}

	m := NewModel(first.Certificates, loadTestConfig(t))
	m.SetRedial(addr, dial)
	out := pump(t, *m, tea.WindowSizeMsg{Width: 120, Height: 40})
	out = pump(t, out, keyPress('x'))

	before := out.certificates[0].Certificate.SerialNumber.String()

	out = pump(t, out, keyPress('r'))

	if out.redialing {
		t.Fatal("the redial never completed")
	}
	after := out.certificates[0].Certificate.SerialNumber.String()
	if after == before {
		t.Errorf("the serial is unchanged at %s, so r did not fetch a new certificate", after)
	}
}

// startRotatingTLSServer serves a self-signed certificate minted per handshake
// on 127.0.0.1, and returns host:port. No DNS, no outbound traffic.
func startRotatingTLSServer(t *testing.T) string {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			cert, err := freshSelfSigned()
			return &cert, err
		},
	})
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	return ln.Addr().String()
}

// freshSelfSigned mints a certificate with a new serial. The key is ECDSA
// rather than RSA because this runs inside a handshake the test pump is waiting
// on, and RSA-2048 generation is slow enough to make that wait a coin toss.
func freshSelfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "redial.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
