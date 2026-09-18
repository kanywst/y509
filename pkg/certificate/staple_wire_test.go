package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

// staplingServer serves a chain with an OCSP response attached, the way a
// server with stapling switched on does.
func staplingServer(t *testing.T, chain [][]byte, key *ecdsa.PrivateKey, staple []byte) string {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: chain,
			PrivateKey:  key,
			OCSPStaple:  staple,
		}},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	return listener.Addr().String()
}

// wireChain mints a root and a leaf for 127.0.0.1 and returns the DER a server
// presents, the leaf key, the parsed pair, and the root key so the test can
// sign an OCSP response as the issuer.
func wireChain(t *testing.T) (der [][]byte, leafKey *ecdsa.PrivateKey, leaf, root *x509.Certificate, rootKey *ecdsa.PrivateKey) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Wire Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if root, err = x509.ParseCertificate(rootDER); err != nil {
		t.Fatal(err)
	}

	if leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(0x2a),
		Subject:      pkix.Name{CommonName: "wire.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"wire.test"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	if leaf, err = x509.ParseCertificate(leafDER); err != nil {
		t.Fatal(err)
	}

	return [][]byte{leafDER, rootDER}, leafKey, leaf, root, rootKey
}

// TestFetchChainReadsTheStaple is the point of the feature: the response the
// server attached comes back read, not as a bare bool.
func TestFetchChainReadsTheStaple(t *testing.T) {
	der, leafKey, leaf, root, rootKey := wireChain(t)
	next := time.Now().Add(12 * time.Hour)
	respDER, err := ocsp.CreateResponse(root, root, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: leaf.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   next,
	}, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	addr := staplingServer(t, der, leafKey, respDER)
	result, err := FetchChain(context.Background(), addr, ConnectOptions{ServerName: "wire.test"})
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}

	if !result.OCSPStapled {
		t.Fatal("the server stapled a response and the result says it did not")
	}
	if result.StapleErr != nil {
		t.Fatalf("StapleErr = %v, want the response read", result.StapleErr)
	}
	if result.Staple == nil {
		t.Fatal("OCSPStapled is true but the response was not read")
	}
	if result.Staple.Status != "good" {
		t.Errorf("Status = %q, want %q", result.Staple.Status, "good")
	}
	if !result.Staple.Verified {
		t.Error("the issuer was in the presented chain, so the signature should have been checked")
	}
	if !result.Staple.NextUpdate.Truncate(time.Second).Equal(next.UTC().Truncate(time.Second)) {
		t.Errorf("NextUpdate = %v, want %v", result.Staple.NextUpdate, next)
	}
}

// TestFetchChainVerifiesASelfSignedLeafsStaple covers the case where the chain
// has one certificate and that certificate is its own issuer. Reporting the
// signature as unchecked there would claim the issuer was missing when it is
// the certificate on screen.
func TestFetchChainVerifiesASelfSignedLeafsStaple(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: "solo.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	respDER, err := ocsp.CreateResponse(cert, cert, ocsp.Response{
		Status:       ocsp.Good,
		SerialNumber: cert.SerialNumber,
		ThisUpdate:   time.Now().Add(-time.Hour),
		NextUpdate:   time.Now().Add(time.Hour),
	}, key)
	if err != nil {
		t.Fatal(err)
	}

	addr := staplingServer(t, [][]byte{der}, key, respDER)
	result, err := FetchChain(context.Background(), addr, ConnectOptions{ServerName: "solo.test"})
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if result.Staple == nil {
		t.Fatal("the staple was not read")
	}
	if !result.Staple.Verified {
		t.Error("a self-signed leaf's own staple was reported as unverifiable")
	}
}

// TestFetchChainWithoutAStaple covers the common case. The absence is recorded
// as an absence, never as a problem.
func TestFetchChainWithoutAStaple(t *testing.T) {
	der, leafKey, _, _, _ := wireChain(t)
	addr := staplingServer(t, der, leafKey, nil)

	result, err := FetchChain(context.Background(), addr, ConnectOptions{ServerName: "wire.test"})
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if result.OCSPStapled {
		t.Error("no response was stapled and the result says one was")
	}
	if result.Staple != nil {
		t.Errorf("Staple = %+v, want nil", result.Staple)
	}
	if result.StapleErr != nil {
		t.Errorf("StapleErr = %v, want none: not stapling is not an error", result.StapleErr)
	}
}

// TestFetchChainKeepsTheChainWhenTheStapleIsGarbage covers the rule that an
// unreadable staple must not cost the user the certificates they asked for.
func TestFetchChainKeepsTheChainWhenTheStapleIsGarbage(t *testing.T) {
	der, leafKey, _, _, _ := wireChain(t)
	addr := staplingServer(t, der, leafKey, []byte("not an OCSP response at all"))

	result, err := FetchChain(context.Background(), addr, ConnectOptions{ServerName: "wire.test"})
	if err != nil {
		t.Fatalf("FetchChain: %v, want the chain returned despite the staple", err)
	}
	if len(result.Certificates) != 2 {
		t.Errorf("got %d certificates, want the 2 the server presented", len(result.Certificates))
	}
	if result.StapleErr == nil {
		t.Error("an unreadable staple was not reported")
	}
	if result.Staple != nil {
		t.Error("an unreadable staple produced a parsed response")
	}
}

// TestJSONConnectionCarriesTheStaple pins the --json contract. Everything
// crossing the boundary is a string, a timestamp or a bool, never an OCSP
// constant's number.
func TestJSONConnectionCarriesTheStaple(t *testing.T) {
	next := time.Now().Add(6 * time.Hour)
	conn := NewJSONConnection(&ConnectResult{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		OCSPStapled: true,
		Staple: &Staple{
			Status:       "good",
			SerialNumber: "2a",
			ProducedAt:   time.Now().Add(-time.Hour),
			ThisUpdate:   time.Now().Add(-time.Hour),
			NextUpdate:   next,
			Verified:     true,
		},
	})

	out, err := json.Marshal(conn)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	for _, want := range []string{`"ocspStapled":true`, `"status":"good"`, `"serialNumber":"2a"`, `"verified":true`, `"expired":false`} {
		if !strings.Contains(got, want) {
			t.Errorf("connection JSON is missing %s:\n%s", want, got)
		}
	}
}

// TestJSONConnectionOmitsAnAbsentStaple keeps the common case quiet: a server
// that staples nothing produces no ocspStaple key at all.
func TestJSONConnectionOmitsAnAbsentStaple(t *testing.T) {
	out, err := json.Marshal(NewJSONConnection(&ConnectResult{Version: tls.VersionTLS13}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "ocspStaple\"") {
		t.Errorf("an absent staple still produced a key:\n%s", out)
	}
	if strings.Contains(string(out), "ocspStapleError") {
		t.Errorf("an absent staple produced an error key:\n%s", out)
	}
}

// TestJSONStapleOmitsNextUpdateWhenAbsent covers the difference between "no
// expiry" and "do not cache": a null would claim the responder gave one.
func TestJSONStapleOmitsNextUpdateWhenAbsent(t *testing.T) {
	out, err := json.Marshal(NewJSONStaple(&Staple{Status: "good"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "nextUpdate") {
		t.Errorf("a response with no NextUpdate still produced the key:\n%s", out)
	}
}
