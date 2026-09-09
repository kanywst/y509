package certificate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
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

// TestStartTLSFTP drives the AUTH TLS exchange from RFC 4217, including the
// multi-line greeting that most real FTP servers send.
func TestStartTLSFTP(t *testing.T) {
	tests := []struct {
		name     string
		greeting string
		reply    string
		wantErr  bool
	}{
		{
			name:     "single line greeting",
			greeting: "220 ready\r\n",
			reply:    "234 AUTH TLS OK\r\n",
		},
		{
			name: "multi-line greeting",
			// A hyphen in the fourth column continues the reply. Reading only
			// the first line would leave the rest to be misread as the answer
			// to AUTH TLS.
			greeting: "220-welcome to the server\r\n220-be nice\r\n220 ready\r\n",
			reply:    "234 AUTH TLS OK\r\n",
		},
		{
			name:     "server has no TLS",
			greeting: "220 ready\r\n",
			reply:    "500 unknown command\r\n",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			go func() {
				defer func() { _ = server.Close() }()
				if _, err := server.Write([]byte(tt.greeting)); err != nil {
					return
				}
				command, err := bufio.NewReader(server).ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(command) != "AUTH TLS" {
					t.Errorf("expected AUTH TLS, got %q", strings.TrimSpace(command))
				}
				_, _ = server.Write([]byte(tt.reply))
			}()

			done := make(chan error, 1)
			go func() { done <- startTLSFTP(client) }()

			select {
			case err := <-done:
				if tt.wantErr && err == nil {
					t.Error("expected an error")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("startTLSFTP hung; it did not consume the greeting correctly")
			}
		})
	}
}

// TestStartTLSLDAP drives the RFC 4511 extended operation against a fake
// server, checking both the request bytes and how a refusal is reported.
func TestStartTLSLDAP(t *testing.T) {
	// An ExtendedResponse carrying the given LDAP result code.
	response := func(code byte) []byte {
		body := []byte{
			0x02, 0x01, 0x01, // messageID 1
			0x78, 0x07, // [APPLICATION 24] ExtendedResponse
			0x0a, 0x01, code, // ENUMERATED resultCode
			0x04, 0x00, // matchedDN, empty
			0x04, 0x00, // diagnosticMessage, empty
		}
		return append([]byte{0x30, byte(len(body))}, body...)
	}

	tests := []struct {
		name    string
		reply   []byte
		wantErr bool
	}{
		{name: "server accepts", reply: response(0)},
		// 53 is unwillingToPerform, what a server without TLS configured says.
		{name: "server refuses", reply: response(53), wantErr: true},
		{name: "not an ExtendedResponse", reply: []byte{0x30, 0x05, 0x02, 0x01, 0x01, 0x65, 0x00}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			go func() {
				defer func() { _ = server.Close() }()
				request := make([]byte, len(ldapStartTLSRequest()))
				if _, err := io.ReadFull(server, request); err != nil {
					return
				}
				if !bytes.Contains(request, []byte(ldapStartTLSOID)) {
					t.Errorf("request does not carry the StartTLS OID: %x", request)
				}
				if request[0] != 0x30 {
					t.Errorf("request is not an LDAPMessage SEQUENCE: %x", request)
				}
				_, _ = server.Write(tt.reply)
			}()

			done := make(chan error, 1)
			go func() { done <- startTLSLDAP(client) }()

			select {
			case err := <-done:
				if tt.wantErr && err == nil {
					t.Error("expected an error")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("startTLSLDAP hung")
			}
		})
	}
}

// errPacket builds a MySQL ERR packet: the 0xff marker, a two byte error code,
// and the message, which conventionally opens with a "#" SQL state marker.
func errPacket(code uint16, message string) []byte {
	payload := []byte{0xff, 0, 0}
	binary.LittleEndian.PutUint16(payload[1:3], code)
	payload = append(payload, message...)

	return append([]byte{byte(len(payload)), 0, 0, 0}, payload...)
}

// TestStartTLSMySQL drives the SSLRequest half of the MySQL handshake.
func TestStartTLSMySQL(t *testing.T) {
	// greeting builds a v10 initial handshake packet advertising capabilities.
	greeting := func(capabilities uint32) []byte {
		payload := []byte{10}                      // protocol version
		payload = append(payload, "8.0.36\x00"...) // server version
		payload = append(payload, make([]byte, 13)...)
		lower := make([]byte, 2)
		binary.LittleEndian.PutUint16(lower, uint16(capabilities))
		payload = append(payload, lower...)
		payload = append(payload, 45, 0, 0) // charset, status flags
		upper := make([]byte, 2)
		binary.LittleEndian.PutUint16(upper, uint16(capabilities>>16))
		payload = append(payload, upper...)

		packet := []byte{byte(len(payload)), 0, 0, 0}
		return append(packet, payload...)
	}

	tests := []struct {
		name     string
		greeting []byte
		wantErr  bool
	}{
		{name: "server offers TLS", greeting: greeting(mysqlClientSSL | mysqlClientProtocol41)},
		{name: "server built without TLS", greeting: greeting(mysqlClientProtocol41), wantErr: true},
		// An ERR packet instead of a greeting: the reason belongs in the error.
		{name: "connection refused", greeting: errPacket(1129, "#08S01host blocked"), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			sent := make(chan []byte, 1)
			go func() {
				defer func() { _ = server.Close() }()
				if _, err := server.Write(tt.greeting); err != nil {
					return
				}
				request := make([]byte, 36)
				if _, err := io.ReadFull(server, request); err != nil {
					return
				}
				sent <- request
			}()

			done := make(chan error, 1)
			go func() { done <- startTLSMySQL(client) }()

			select {
			case err := <-done:
				if tt.wantErr {
					if err == nil {
						t.Error("expected an error")
					}
					return
				}
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("startTLSMySQL hung")
			}

			select {
			case request := <-sent:
				// 32 byte payload, sequence 1, and CLIENT_SSL set.
				if request[0] != 32 || request[3] != 1 {
					t.Errorf("wrong SSLRequest header: %x", request[:4])
				}
				if flags := binary.LittleEndian.Uint32(request[4:8]); flags&mysqlClientSSL == 0 {
					t.Errorf("SSLRequest does not set CLIENT_SSL: %08x", flags)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("the server never received the SSLRequest packet")
			}
		})
	}
}

// TestReadMySQLPacket_RejectsHugeLength checks that the length header alone
// cannot dictate an allocation. A hostile server can claim the 16 MiB maximum
// in four bytes and then send nothing.
func TestReadMySQLPacket_RejectsHugeLength(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		defer func() { _ = server.Close() }()
		// Length 0xffffff, sequence 0, and no payload behind it.
		_, _ = server.Write([]byte{0xff, 0xff, 0xff, 0})
	}()

	done := make(chan error, 1)
	go func() {
		_, _, err := readMySQLPacket(bufio.NewReader(client))
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the oversized length to be refused")
		}
		if !strings.Contains(err.Error(), "implausibly large") {
			t.Errorf("expected a size complaint, got: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readMySQLPacket hung, or waited for 16 MiB that never came")
	}
}

// TestParseBERElement_RejectsOversizedLength feeds the largest four-octet
// length a server can claim.
//
// Where int is 64 bits, as on every platform this is built for, 0xffffffff is
// simply larger than the buffer and the size check catches it. Where int is 32
// bits it wraps to -1, slips past that check, and panics at the slice; the
// signed guard in parseBERElement is what stops that, and this test cannot
// reach it on a 64-bit host. It is here so the input stays covered either way.
func TestParseBERElement_RejectsOversizedLength(t *testing.T) {
	// Tag, long form announcing four length octets, then 0xffffffff.
	buf := []byte{0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 0x00}

	_, _, err := parseBERElement(buf)
	if err == nil {
		t.Fatal("expected a length of 0xffffffff to be refused")
	}
}

// TestStartTLSNNTP covers RFC 4642, including the read-only greeting that a
// 200-only check would reject.
func TestStartTLSNNTP(t *testing.T) {
	tests := []struct {
		name     string
		greeting string
		reply    string
		wantErr  bool
	}{
		{
			name:     "posting allowed",
			greeting: "200 news.example.com InterNetNews ready\r\n",
			reply:    "382 Continue with TLS negotiation\r\n",
		},
		{
			// 201 is a working server that will not accept posts. Treating only
			// 200 as a greeting would fail on every read-only news server.
			name:     "read only server",
			greeting: "201 news.example.com InterNetNews (no posting)\r\n",
			reply:    "382 Continue with TLS negotiation\r\n",
		},
		{
			name:     "server without TLS",
			greeting: "200 news.example.com ready\r\n",
			reply:    "580 Can not initiate TLS negotiation\r\n",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close() })

			go func() {
				defer func() { _ = server.Close() }()
				if _, err := server.Write([]byte(tt.greeting)); err != nil {
					return
				}
				command, err := bufio.NewReader(server).ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimSpace(command) != "STARTTLS" {
					t.Errorf("expected STARTTLS, got %q", strings.TrimSpace(command))
				}
				_, _ = server.Write([]byte(tt.reply))
			}()

			done := make(chan error, 1)
			go func() { done <- startTLSNNTP(client) }()

			select {
			case err := <-done:
				if tt.wantErr && err == nil {
					t.Error("expected an error")
				}
				if !tt.wantErr && err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("startTLSNNTP hung")
			}
		})
	}
}

// TestStartTLSLMTP checks the prelude greets with LHLO rather than EHLO. A
// server speaking LMTP refuses EHLO outright, so the verb has to be exact.
func TestStartTLSLMTP(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	greeted := make(chan string, 1)
	go func() {
		defer func() { _ = server.Close() }()
		// Multi-line, as a real LMTP greeting is.
		if _, err := server.Write([]byte("220-lmtp.example.com\r\n220 ready\r\n")); err != nil {
			return
		}
		reader := bufio.NewReader(server)
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		greeted <- strings.Fields(strings.TrimSpace(line))[0]
		if _, err := server.Write([]byte("250-lmtp.example.com\r\n250 STARTTLS\r\n")); err != nil {
			return
		}
		if _, err := reader.ReadString('\n'); err != nil {
			return
		}
		_, _ = server.Write([]byte("220 go ahead\r\n"))
	}()

	done := make(chan error, 1)
	go func() { done <- startTLSLMTP(client) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startTLSLMTP hung")
	}

	select {
	case verb := <-greeted:
		if verb != "LHLO" {
			t.Errorf("greeted with %q, want LHLO", verb)
		}
	case <-time.After(time.Second):
		t.Fatal("the server never saw a greeting")
	}
}
