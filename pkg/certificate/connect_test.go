package certificate

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantAddress string
		wantHost    string
		wantErr     bool
	}{
		{name: "host and port", in: "example.com:8443", wantAddress: "example.com:8443", wantHost: "example.com"},
		{name: "bare host defaults to 443", in: "example.com", wantAddress: "example.com:443", wantHost: "example.com"},
		{name: "https URL", in: "https://example.com", wantAddress: "example.com:443", wantHost: "example.com"},
		{name: "URL with a path", in: "https://example.com/a/b?c=d", wantAddress: "example.com:443", wantHost: "example.com"},
		{name: "URL with a port", in: "https://example.com:8443/x", wantAddress: "example.com:8443", wantHost: "example.com"},
		{name: "IPv4", in: "10.0.0.1:443", wantAddress: "10.0.0.1:443", wantHost: "10.0.0.1"},
		{name: "bracketed IPv6 with a port", in: "[::1]:8443", wantAddress: "[::1]:8443", wantHost: "::1"},
		{name: "trailing slash", in: "example.com/", wantAddress: "example.com:443", wantHost: "example.com"},
		{name: "empty", in: "", wantErr: true},
		{name: "scheme only", in: "https://", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address, host, err := normalizeAddress(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeAddress(%q): %v", tt.in, err)
			}
			if address != tt.wantAddress {
				t.Errorf("address = %q, want %q", address, tt.wantAddress)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
		})
	}
}

// testServer starts a TLS listener presenting the given chain, leaf first, and
// returns its address.
func testServer(t *testing.T, chain [][]byte, key *ecdsa.PrivateKey) string {
	t.Helper()

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: chain, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
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
			// The handshake happens on the first read; we don't need the bytes.
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()

	return listener.Addr().String()
}

// serverChain mints a root and a leaf and returns the DER the server should
// present, along with the leaf's key.
func serverChain(t *testing.T, leafCN string) (der [][]byte, leafKey *ecdsa.PrivateKey, root *x509.Certificate) {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: leafCN},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{leafCN},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}

	return [][]byte{leafDER, rootDER}, leafKey, root
}

// TestFetchChain_PreservesServerOrder checks that the certificates come back in
// the order the server sent them, leaf first.
func TestFetchChain_PreservesServerOrder(t *testing.T) {
	der, key, _ := serverChain(t, "leaf.test")
	addr := testServer(t, der, key)

	result, err := FetchChain(context.Background(), addr, ConnectOptions{ServerName: "leaf.test"})
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}

	if len(result.Certificates) != 2 {
		t.Fatalf("expected 2 certificates, got %d", len(result.Certificates))
	}
	if got := result.Certificates[0].Certificate.Subject.CommonName; got != "leaf.test" {
		t.Errorf("first certificate = %q, want the leaf %q", got, "leaf.test")
	}
	if got := result.Certificates[1].Certificate.Subject.CommonName; got != "Test Root CA" {
		t.Errorf("second certificate = %q, want %q", got, "Test Root CA")
	}
	for i, info := range result.Certificates {
		if info.Index != i {
			t.Errorf("certificate %d: Index = %d, want %d", i, info.Index, i)
		}
	}
	if result.Version == 0 {
		t.Error("no TLS version recorded")
	}
}

// TestFetchChain_UntrustedServerStillReturnsTheChain is the point of the
// feature: a chain the system does not trust is exactly what the user wants to
// look at, so the handshake must not reject it.
func TestFetchChain_UntrustedServerStillReturnsTheChain(t *testing.T) {
	der, key, root := serverChain(t, "leaf.test")
	addr := testServer(t, der, key)

	result, err := FetchChain(context.Background(), addr, ConnectOptions{ServerName: "leaf.test"})
	if err != nil {
		t.Fatalf("FetchChain refused an untrusted chain: %v", err)
	}

	// The chain came back; now judging it is VerifyChain's job, and it should
	// say the root is not trusted.
	chain := make([]*x509.Certificate, len(result.Certificates))
	for i, info := range result.Certificates {
		chain[i] = info.Certificate
	}

	verdict, err := VerifyChain(chain, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if verdict.Level != TrustSelfAnchored {
		t.Errorf("Level = %v, want %v", verdict.Level, TrustSelfAnchored)
	}

	// And with the root supplied, it verifies.
	verdict, err = VerifyChain(chain, VerifyOptions{ExtraRoots: []*x509.Certificate{root}})
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if verdict.Level != TrustAnchored {
		t.Errorf("with the root trusted: Level = %v (%v), want %v", verdict.Level, verdict.Err, TrustAnchored)
	}
}

// TestFetchChain_Timeout checks that a server which never speaks TLS is given
// up on rather than hanging.
func TestFetchChain_Timeout(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// Accept, then say nothing at all -- block on a read until the client hangs
	// up, rather than sleeping, so the goroutine does not outlive the test.
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 1))
	}()

	start := time.Now()
	_, err = FetchChain(context.Background(), listener.Addr().String(), ConnectOptions{
		Timeout: 200 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v; the timeout was not honoured", elapsed)
	}
}

// TestFetchChain_ConnectionRefused checks the error when nothing is listening.
func TestFetchChain_ConnectionRefused(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = FetchChain(context.Background(), addr, ConnectOptions{Timeout: time.Second})
	if err == nil {
		t.Fatal("expected an error connecting to a closed port")
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Logf("error was %v", err)
	}
}

// TestNegotiateStartTLS_UnsupportedProtocol checks the error names the ones
// that do work.
func TestNegotiateStartTLS_UnsupportedProtocol(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })

	err := negotiateStartTLS(client, "gopher")
	if err == nil {
		t.Fatal("expected an error for an unknown protocol")
	}
	for _, supported := range StartTLSProtocols {
		if !strings.Contains(err.Error(), supported) {
			t.Errorf("error does not mention the supported protocol %q: %v", supported, err)
		}
	}
}

// TestStartTLSPostgres drives the SSLRequest exchange against a fake server.
func TestStartTLSPostgres(t *testing.T) {
	tests := []struct {
		name    string
		reply   byte
		wantErr bool
	}{
		{name: "server accepts", reply: 'S', wantErr: false},
		{name: "server refuses TLS", reply: 'N', wantErr: true},
		{name: "server says something else", reply: 'X', wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			go func() {
				defer func() { _ = server.Close() }()
				request := make([]byte, 8)
				if _, err := server.Read(request); err != nil {
					return
				}
				// The body must be the SSLRequest magic number, 80877103.
				if request[4] != 0x04 || request[5] != 0xd2 || request[6] != 0x16 || request[7] != 0x2f {
					t.Errorf("client sent the wrong SSLRequest body: %x", request[4:])
				}
				_, _ = server.Write([]byte{tt.reply})
			}()

			err := startTLSPostgres(client)
			if tt.wantErr && err == nil {
				t.Error("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestNormalizeAddress_Awkward covers the shapes that used to come out wrong:
// a URL carrying userinfo, and a bracketed IPv6 literal with no port.
func TestNormalizeAddress_Awkward(t *testing.T) {
	tests := []struct {
		name        string
		in          string
		wantAddress string
		wantHost    string
	}{
		{
			name: "URL with userinfo",
			// Left in place, "user:pass@example.com" becomes the host, and goes
			// out as both the DNS name and the SNI value.
			in:          "https://user:pass@example.com/admin",
			wantAddress: "example.com:443",
			wantHost:    "example.com",
		},
		{
			name:        "userinfo without a scheme",
			in:          "user@example.com:8443",
			wantAddress: "example.com:8443",
			wantHost:    "example.com",
		},
		{
			name: "trailing colon with no port",
			// net.SplitHostPort accepts this and returns an empty port, which
			// would dial an invalid address.
			in:          "example.com:",
			wantAddress: "example.com:443",
			wantHost:    "example.com",
		},
		{
			name: "bracketed IPv6 with no port",
			// The brackets belong to the address syntax, not the host. Kept,
			// they are sent as the SNI name and JoinHostPort double-wraps them.
			in:          "[::1]",
			wantAddress: "[::1]:443",
			wantHost:    "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address, host, err := normalizeAddress(tt.in)
			if err != nil {
				t.Fatalf("normalizeAddress(%q): %v", tt.in, err)
			}
			if address != tt.wantAddress {
				t.Errorf("address = %q, want %q", address, tt.wantAddress)
			}
			if host != tt.wantHost {
				t.Errorf("host = %q, want %q", host, tt.wantHost)
			}
		})
	}
}

// fakeLineServer replies with the given script, line by line, to whatever the
// client sends. It returns the client end of the connection.
func fakeLineServer(t *testing.T, script []string) net.Conn {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		defer func() { _ = server.Close() }()
		reader := bufio.NewReader(server)
		for _, reply := range script {
			if reply == "<read>" {
				if _, err := reader.ReadString('\n'); err != nil {
					return
				}
				continue
			}
			if _, err := server.Write([]byte(reply)); err != nil {
				return
			}
		}
		// Let the client finish reading before the pipe closes.
		time.Sleep(50 * time.Millisecond)
	}()

	return client
}

// TestStartTLSSMTP_MultiLineReplies covers the reply shapes that used to desync
// the exchange: a multi-line greeting, and an EHLO reply whose last line is a
// bare code with no trailing space.
func TestStartTLSSMTP_MultiLineReplies(t *testing.T) {
	tests := []struct {
		name    string
		script  []string
		wantErr bool
	}{
		{
			name: "multi-line greeting",
			script: []string{
				"220-mail.example.com ESMTP Postfix\r\n",
				"220-This server is monitored\r\n",
				"220 Ready\r\n",
				"<read>", // EHLO
				"250-mail.example.com\r\n",
				"250-PIPELINING\r\n",
				"250 STARTTLS\r\n",
				"<read>", // STARTTLS
				"220 Go ahead\r\n",
			},
		},
		{
			name: "EHLO reply ends with a bare code and no space",
			script: []string{
				"220 mail.example.com ESMTP\r\n",
				"<read>",
				"250-mail.example.com\r\n",
				"250\r\n", // legal, and used to hang the old loop forever
				"<read>",
				"220 Go ahead\r\n",
			},
		},
		{
			name: "server refuses STARTTLS",
			script: []string{
				"220 mail.example.com ESMTP\r\n",
				"<read>",
				"250 STARTTLS\r\n",
				"<read>",
				"454 TLS not available\r\n",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := fakeLineServer(t, tt.script)

			done := make(chan error, 1)
			go func() { done <- startTLSSMTP(conn) }()

			select {
			case err := <-done:
				if tt.wantErr && err == nil {
					t.Error("expected an error")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("startTLSSMTP hung; it did not consume the reply correctly")
			}
		})
	}
}

// TestStartTLSIMAP_UntaggedResponses covers a compliant server that sends
// untagged data before the tagged completion of STARTTLS.
func TestStartTLSIMAP_UntaggedResponses(t *testing.T) {
	tests := []struct {
		name    string
		script  []string
		wantErr bool
	}{
		{
			name: "untagged responses before the tagged OK",
			script: []string{
				"* OK [CAPABILITY IMAP4rev1 STARTTLS] Dovecot ready\r\n",
				"<read>",
				"* CAPABILITY IMAP4rev1 STARTTLS\r\n",
				"* SOMETHING else entirely\r\n",
				"a001 OK Begin TLS negotiation now\r\n",
			},
		},
		{
			name: "server refuses",
			script: []string{
				"* OK Dovecot ready\r\n",
				"<read>",
				"a001 NO TLS is not available\r\n",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := fakeLineServer(t, tt.script)

			done := make(chan error, 1)
			go func() { done <- startTLSIMAP(conn) }()

			select {
			case err := <-done:
				if tt.wantErr && err == nil {
					t.Error("expected an error")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("startTLSIMAP hung")
			}
		})
	}
}

// TestFetchChain_ContextCancelDuringStartTLS checks that cancelling the context
// while the STARTTLS negotiation is blocked on a read returns promptly rather
// than waiting out the deadline.
func TestFetchChain_ContextCancelDuringStartTLS(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	// Accept and then go silent, so the SMTP greeting read blocks.
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_, _ = conn.Read(make([]byte, 1))
	}()

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	// A long timeout: if cancellation is not honoured, the read waits this out.
	_, err = FetchChain(ctx, listener.Addr().String(), ConnectOptions{
		StartTLS: "smtp",
		Timeout:  30 * time.Second,
	})
	if err == nil {
		t.Fatal("expected an error from the cancelled context")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v; the cancellation was not honoured during STARTTLS", elapsed)
	}
}
