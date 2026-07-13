package certificate

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DefaultConnectTimeout bounds the whole handshake, including the STARTTLS
// negotiation that precedes it.
const DefaultConnectTimeout = 10 * time.Second

// DefaultTLSPort is used when the target carries no port.
const DefaultTLSPort = "443"

// ConnectOptions configures a live TLS fetch.
type ConnectOptions struct {
	// ServerName overrides the SNI value and the name the certificate is
	// checked against. It defaults to the host part of the address.
	ServerName string
	// StartTLS names the application protocol to negotiate an upgrade in
	// before the TLS handshake: smtp, imap, or postgres. Empty means the
	// connection is TLS from the first byte.
	StartTLS string
	// Timeout bounds the whole operation. Zero means DefaultConnectTimeout.
	Timeout time.Duration
}

// ConnectResult is what a server presented.
type ConnectResult struct {
	// Certificates are the certificates the server sent, in the order it sent
	// them. That order is not necessarily a valid chain, and preserving it is
	// the point: a server shipping them out of order, shipping its root, or
	// omitting an intermediate is exactly the bug worth seeing.
	Certificates []*Info
	// Address is the host:port that was dialled.
	Address string
	// ServerName is the SNI value that was sent.
	ServerName string
	// Version is the negotiated TLS version.
	Version uint16
	// CipherSuite is the negotiated cipher suite.
	CipherSuite uint16
	// OCSPStapled reports whether the server stapled an OCSP response.
	OCSPStapled bool
}

// TLSVersionName renders the negotiated version.
func (r *ConnectResult) TLSVersionName() string {
	switch r.Version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("unknown (0x%04x)", r.Version)
	}
}

// FetchChain connects to addr and returns the certificates the server presents.
//
// The handshake deliberately does not verify anything: a chain that fails to
// verify is precisely what the user is trying to look at, so rejecting it at
// the transport would defeat the purpose. Verification is a separate step, via
// VerifyChain.
func FetchChain(ctx context.Context, addr string, opts ConnectOptions) (*ConnectResult, error) {
	address, host, err := normalizeAddress(addr)
	if err != nil {
		return nil, err
	}

	// Reject an unknown protocol before dialling. Otherwise a typo in
	// --starttls surfaces as whatever the connection happens to do first, which
	// is rarely the actual problem.
	if opts.StartTLS != "" && !supportedStartTLS(opts.StartTLS) {
		return nil, fmt.Errorf("unsupported --starttls protocol %q (supported: %s)",
			opts.StartTLS, strings.Join(StartTLSProtocols, ", "))
	}

	serverName := opts.ServerName
	if serverName == "" {
		serverName = host
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultConnectTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	logger.Info("connecting",
		zap.String("address", address),
		zap.String("serverName", serverName),
		zap.String("startTLS", opts.StartTLS))

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", address, err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			logger.Warn("failed to close connection", zap.Error(closeErr))
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed to set deadline: %w", err)
		}
	}

	if opts.StartTLS != "" {
		if err := negotiateStartTLS(conn, opts.StartTLS); err != nil {
			return nil, fmt.Errorf("STARTTLS (%s) failed: %w", opts.StartTLS, err)
		}
	}

	// InsecureSkipVerify is deliberate: showing a chain the system does not
	// trust is the whole job. VerifyChain is what passes judgement.
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // see above; this tool inspects untrusted chains by design
		MinVersion:         tls.VersionTLS10,
	})

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake with %s failed: %w", address, err)
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("%s presented no certificates", address)
	}

	certs := make([]*Info, len(state.PeerCertificates))
	for i, cert := range state.PeerCertificates {
		certs[i] = &Info{
			Certificate: cert,
			Index:       i,
			Label:       generateCertificateLabel(cert, i),
		}
	}

	return &ConnectResult{
		Certificates: certs,
		Address:      address,
		ServerName:   serverName,
		Version:      state.Version,
		CipherSuite:  state.CipherSuite,
		OCSPStapled:  len(state.OCSPResponse) > 0,
	}, nil
}

// normalizeAddress turns the many ways a user names a server into a host:port
// pair, and returns the bare host for SNI. It accepts "example.com",
// "example.com:8443", "https://example.com/path", and IPv6 literals.
func normalizeAddress(addr string) (address, host string, err error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return "", "", fmt.Errorf("no address given")
	}

	// Tolerate a pasted URL.
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}
	addr = strings.TrimSuffix(addr, "/")
	if i := strings.IndexAny(addr, "/?#"); i >= 0 {
		addr = addr[:i]
	}
	if addr == "" {
		return "", "", fmt.Errorf("no host in address")
	}

	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		// No port, or an unbracketed IPv6 literal. Assume the former.
		host, port = addr, DefaultTLSPort
	}
	if host == "" {
		return "", "", fmt.Errorf("no host in address %q", addr)
	}

	return net.JoinHostPort(host, port), host, nil
}

// StartTLSProtocols are the application protocols FetchChain can upgrade.
var StartTLSProtocols = []string{"smtp", "imap", "postgres"}

// supportedStartTLS reports whether negotiateStartTLS knows the protocol.
func supportedStartTLS(protocol string) bool {
	switch strings.ToLower(protocol) {
	case "smtp", "imap", "postgres", "postgresql":
		return true
	default:
		return false
	}
}

// negotiateStartTLS performs the plaintext prelude that asks the server to
// switch to TLS. Each protocol spells this differently, which is exactly why
// openssl s_client needs a flag for it too.
func negotiateStartTLS(conn net.Conn, protocol string) error {
	switch strings.ToLower(protocol) {
	case "smtp":
		return startTLSSMTP(conn)
	case "imap":
		return startTLSIMAP(conn)
	case "postgres", "postgresql":
		return startTLSPostgres(conn)
	default:
		return fmt.Errorf("unsupported protocol %q (supported: %s)",
			protocol, strings.Join(StartTLSProtocols, ", "))
	}
}

// startTLSSMTP does the EHLO / STARTTLS exchange from RFC 3207.
func startTLSSMTP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Greeting.
	if err := expectSMTPCode(reader, "220"); err != nil {
		return err
	}

	if _, err := fmt.Fprintf(conn, "EHLO y509\r\n"); err != nil {
		return err
	}
	// EHLO answers with several 250- lines and a final 250 one.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, "250") {
			return fmt.Errorf("unexpected EHLO response: %s", strings.TrimSpace(line))
		}
		if len(line) > 3 && line[3] == ' ' {
			break
		}
	}

	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	return expectSMTPCode(reader, "220")
}

// expectSMTPCode reads one response and checks its status code.
func expectSMTPCode(reader *bufio.Reader, code string) error {
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, code) {
		return fmt.Errorf("expected %s, got: %s", code, strings.TrimSpace(line))
	}
	return nil
}

// startTLSIMAP does the STARTTLS exchange from RFC 3501.
func startTLSIMAP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Greeting, an untagged * OK line.
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "* OK") {
		return fmt.Errorf("unexpected greeting: %s", strings.TrimSpace(line))
	}

	if _, err := fmt.Fprintf(conn, "a001 STARTTLS\r\n"); err != nil {
		return err
	}
	line, err = reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "a001 OK") {
		return fmt.Errorf("server refused STARTTLS: %s", strings.TrimSpace(line))
	}
	return nil
}

// startTLSPostgres sends the SSLRequest packet from the PostgreSQL frontend
// protocol: an eight byte message whose body is the magic number 80877103.
// The server answers with a single byte, 'S' to accept or 'N' to refuse.
func startTLSPostgres(conn net.Conn) error {
	const sslRequestCode = 80877103

	packet := make([]byte, 8)
	binary.BigEndian.PutUint32(packet[0:4], 8)
	binary.BigEndian.PutUint32(packet[4:8], sslRequestCode)

	if _, err := conn.Write(packet); err != nil {
		return err
	}

	response := make([]byte, 1)
	if _, err := conn.Read(response); err != nil {
		return err
	}
	switch response[0] {
	case 'S':
		return nil
	case 'N':
		return fmt.Errorf("server does not support TLS")
	default:
		return fmt.Errorf("unexpected response to SSLRequest: %q", response[0])
	}
}
