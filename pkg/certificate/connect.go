package certificate

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
	// before the TLS handshake; see StartTLSProtocols. Empty means the
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
		// An already-closed connection is expected here: the watcher below
		// closes it on context cancellation, and a failed handshake or a remote
		// hang-up can close it too. net.ErrClosed covers all of those, so warn
		// only on some other, genuinely unexpected close error.
		if closeErr := conn.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			logger.Warn("failed to close connection", zap.Error(closeErr))
		}
	}()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed to set deadline: %w", err)
		}
	}

	// The STARTTLS negotiation below reads synchronously and does not watch the
	// context itself. The deadline bounds it, but an early cancellation would
	// otherwise wait the deadline out. Close the connection when the context is
	// done so those reads unblock at once; stop the watcher on the normal path.
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-stop:
		}
	}()

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
	// Drop any userinfo. Left in place it becomes part of the host, and both
	// the DNS lookup and the SNI name go out as "user:pass@example.com".
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		addr = addr[i+1:]
	}
	if addr == "" {
		return "", "", fmt.Errorf("no host in address")
	}

	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		// No port, or an unbracketed IPv6 literal. Assume the former.
		host, port = addr, DefaultTLSPort
		// A bracketed literal with no port ("[::1]") lands here with its
		// brackets still on. They belong to the address syntax, not the host,
		// and JoinHostPort would add a second pair.
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = host[1 : len(host)-1]
		}
	} else if port == "" {
		// A trailing colon ("example.com:") splits cleanly but leaves an empty
		// port, which would dial an invalid address. Fall back to the default.
		port = DefaultTLSPort
	}
	if host == "" {
		return "", "", fmt.Errorf("no host in address %q", addr)
	}

	return net.JoinHostPort(host, port), host, nil
}

// StartTLSProtocols are the application protocols FetchChain can upgrade, in
// the order they are offered to the user.
var StartTLSProtocols = []string{"smtp", "lmtp", "imap", "nntp", "ftp", "ldap", "mysql", "postgres"}

// startTLSNegotiators maps every accepted spelling to its prelude. One table
// rather than two switch statements, so the set --starttls advertises and the
// set it can actually negotiate cannot drift apart.
var startTLSNegotiators = map[string]func(net.Conn) error{
	"smtp":       startTLSSMTP,
	"lmtp":       startTLSLMTP,
	"imap":       startTLSIMAP,
	"nntp":       startTLSNNTP,
	"ftp":        startTLSFTP,
	"ldap":       startTLSLDAP,
	"mysql":      startTLSMySQL,
	"mariadb":    startTLSMySQL,
	"postgres":   startTLSPostgres,
	"postgresql": startTLSPostgres,
}

// supportedStartTLS reports whether negotiateStartTLS knows the protocol.
func supportedStartTLS(protocol string) bool {
	_, ok := startTLSNegotiators[strings.ToLower(protocol)]
	return ok
}

// negotiateStartTLS performs the plaintext prelude that asks the server to
// switch to TLS. Each protocol spells this differently, which is exactly why
// openssl s_client needs a flag for it too.
func negotiateStartTLS(conn net.Conn, protocol string) error {
	negotiate, ok := startTLSNegotiators[strings.ToLower(protocol)]
	if !ok {
		return fmt.Errorf("unsupported protocol %q (supported: %s)",
			protocol, strings.Join(StartTLSProtocols, ", "))
	}
	return negotiate(conn)
}

// startTLSSMTP does the EHLO / STARTTLS exchange from RFC 3207.
func startTLSSMTP(conn net.Conn) error {
	return startTLSSMTPLike(conn, "EHLO")
}

// startTLSLMTP does the same exchange for LMTP, RFC 2033, which differs from
// SMTP only in greeting with LHLO. A server that speaks LMTP refuses EHLO
// outright, so the verb has to be right rather than merely close.
func startTLSLMTP(conn net.Conn) error {
	return startTLSSMTPLike(conn, "LHLO")
}

// startTLSSMTPLike performs the SMTP-shaped prelude with the given greeting
// verb.
func startTLSSMTPLike(conn net.Conn, greeting string) error {
	reader := bufio.NewReader(conn)

	// The greeting is frequently several lines. Every one of them has to be
	// consumed here, or the leftovers are read back as the answer to EHLO.
	if err := expectReplyCode(reader, "220"); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "%s y509\r\n", greeting); err != nil {
		return err
	}
	if err := expectReplyCode(reader, "250"); err != nil {
		return fmt.Errorf("%s: %w", greeting, err)
	}

	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	if err := expectReplyCode(reader, "220"); err != nil {
		return fmt.Errorf("STARTTLS: %w", err)
	}
	return nil
}

// startTLSNNTP does the STARTTLS exchange from RFC 4642.
//
// The greeting is 200 when posting is allowed and 201 when the server is read
// only. Both are a working connection, and accepting only 200 would turn every
// read-only news server into a spurious failure.
func startTLSNNTP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	if err := expectReplyCode(reader, "200", "201"); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		return err
	}
	// 382 is "continue with TLS negotiation". A server that already has TLS on
	// the connection answers 502, and one built without it answers 580.
	if err := expectReplyCode(reader, "382"); err != nil {
		return fmt.Errorf("STARTTLS: %w", err)
	}
	return nil
}

// expectReplyCode reads a complete reply and checks its status code against the
// ones given. SMTP, LMTP, FTP and NNTP share the grammar, so they share this
// reader; more than one code is accepted because an NNTP greeting is 200 or 201
// depending on whether posting is allowed, and both are a working connection.
//
// A reply may span several lines. RFC 5321 (and RFC 959 before it) marks a
// continuation with a hyphen in the fourth column ("250-STARTTLS") and the
// final line with anything else, normally a space ("250 OK"). Reading only the
// first line leaves the rest in the buffer, where it gets mistaken for the
// answer to the next command -- so a server with a multi-line greeting broke
// the exchange before it began.
func expectReplyCode(reader *bufio.Reader, codes ...string) error {
	accepts := func(line string) bool {
		for _, code := range codes {
			if strings.HasPrefix(line, code) {
				return true
			}
		}
		return false
	}

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if !accepts(line) {
			return fmt.Errorf("expected %s, got: %s",
				strings.Join(codes, " or "), strings.TrimSpace(line))
		}
		// Anything but a hyphen in column four ends the reply. Testing for a
		// space instead would hang on a bare "250\r\n", which is legal.
		if len(line) < 4 || line[3] != '-' {
			return nil
		}
	}
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

	const tag = "a001"
	if _, err := fmt.Fprintf(conn, "%s STARTTLS\r\n", tag); err != nil {
		return err
	}

	// A server may send untagged responses -- "* CAPABILITY ...", say -- before
	// the tagged completion. Skip past them to the line that carries our tag,
	// rather than reading one line and calling anything else a refusal.
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, tag+" ") {
			continue
		}
		if !strings.HasPrefix(line, tag+" OK") {
			return fmt.Errorf("server refused STARTTLS: %s", strings.TrimSpace(line))
		}
		return nil
	}
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
	if _, err := io.ReadFull(conn, response); err != nil {
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

// startTLSFTP does the AUTH TLS exchange from RFC 4217. The reply grammar is
// SMTP's, down to the hyphen continuation, so the same reader serves both.
func startTLSFTP(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	if err := expectReplyCode(reader, "220"); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}

	if _, err := fmt.Fprintf(conn, "AUTH TLS\r\n"); err != nil {
		return err
	}
	// 234 is "security data exchange complete": the command is accepted and the
	// next byte on the wire is the TLS handshake. A server without TLS answers
	// 500 or 502, which expectReplyCode reports verbatim.
	if err := expectReplyCode(reader, "234"); err != nil {
		return fmt.Errorf("AUTH TLS: %w", err)
	}
	return nil
}

// LDAP StartTLS, RFC 4511 section 4.14. The request is an ExtendedRequest whose
// requestName is this OID; the response is an ExtendedResponse carrying an
// LDAP result code.
const ldapStartTLSOID = "1.3.6.1.4.1.1466.20037"

// startTLSLDAP sends the StartTLS extended operation and waits for a success
// result. Unlike the line protocols above, LDAP is BER-encoded, so the exchange
// is assembled and parsed byte by byte rather than read as text.
func startTLSLDAP(conn net.Conn) error {
	if _, err := conn.Write(ldapStartTLSRequest()); err != nil {
		return err
	}

	reader := bufio.NewReader(conn)
	message, err := readBERElement(reader)
	if err != nil {
		return fmt.Errorf("reading the response: %w", err)
	}
	// LDAPMessage ::= SEQUENCE { messageID, protocolOp, ... }
	if message.tag != 0x30 {
		return fmt.Errorf("expected an LDAPMessage SEQUENCE, got tag 0x%02x", message.tag)
	}

	body := message.value
	// Skip the messageID INTEGER to reach the protocolOp.
	if _, body, err = parseBERElement(body); err != nil {
		return fmt.Errorf("reading the messageID: %w", err)
	}
	// ExtendedResponse ::= [APPLICATION 24], i.e. the constructed tag 0x78.
	response, _, err := parseBERElement(body)
	if err != nil {
		return fmt.Errorf("reading the protocolOp: %w", err)
	}
	if response.tag != 0x78 {
		return fmt.Errorf("expected an ExtendedResponse, got tag 0x%02x", response.tag)
	}
	// Its first field is the resultCode, an ENUMERATED. Zero is success; every
	// other value is the server declining, and its number is the diagnosis.
	code, _, err := parseBERElement(response.value)
	if err != nil {
		return fmt.Errorf("reading the resultCode: %w", err)
	}
	if code.tag != 0x0a || len(code.value) != 1 {
		return fmt.Errorf("malformed resultCode in the ExtendedResponse")
	}
	if code.value[0] != 0 {
		return fmt.Errorf("server refused StartTLS: LDAP result code %d", code.value[0])
	}
	return nil
}

// ldapStartTLSRequest builds the LDAPMessage that asks for StartTLS. Every
// length here is short-form, because every element is far below 128 bytes.
func ldapStartTLSRequest() []byte {
	// [0] requestName, context-specific primitive, holding the OID as a string.
	requestName := append([]byte{0x80, byte(len(ldapStartTLSOID))}, ldapStartTLSOID...)
	// ExtendedRequest ::= [APPLICATION 23], the constructed tag 0x77.
	extendedRequest := append([]byte{0x77, byte(len(requestName))}, requestName...)
	// messageID INTEGER 1. Only one message is ever sent on this connection.
	messageID := []byte{0x02, 0x01, 0x01}

	body := append(messageID, extendedRequest...) //nolint:gocritic // deliberately a new slice
	return append([]byte{0x30, byte(len(body))}, body...)
}

// berElement is one parsed tag-length-value triple.
type berElement struct {
	tag   byte
	value []byte
}

// maxBERLength caps what readBERElement will allocate. A StartTLS response is
// a few dozen bytes; anything near this is a wrong or hostile server, and
// without the cap its length header alone would dictate the allocation.
const maxBERLength = 1 << 20

// readBERElement reads one definite-length BER element off the wire.
func readBERElement(reader *bufio.Reader) (berElement, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return berElement{}, err
	}

	length := int(header[1])
	if length&0x80 != 0 {
		// Long form: the low seven bits count the octets that carry the length.
		count := length & 0x7f
		if count == 0 || count > 4 {
			return berElement{}, fmt.Errorf("unsupported BER length of %d octets", count)
		}
		octets := make([]byte, count)
		if _, err := io.ReadFull(reader, octets); err != nil {
			return berElement{}, err
		}
		length = 0
		for _, b := range octets {
			length = length<<8 | int(b)
		}
	}
	// The comparison is signed: a four-octet length such as 0xffffffff wraps to
	// -1 where int is 32 bits, slips past an upper bound on its own, and panics
	// in make below.
	if length < 0 || length > maxBERLength {
		return berElement{}, fmt.Errorf("BER element of %d bytes is implausibly large", length)
	}

	value := make([]byte, length)
	if _, err := io.ReadFull(reader, value); err != nil {
		return berElement{}, err
	}
	return berElement{tag: header[0], value: value}, nil
}

// parseBERElement takes the first element off buf and returns it with the
// remainder. Only the short form appears inside a StartTLS response, but the
// long form is handled so a chatty server cannot trip the parser.
func parseBERElement(buf []byte) (berElement, []byte, error) {
	if len(buf) < 2 {
		return berElement{}, nil, fmt.Errorf("truncated element")
	}
	tag, length, rest := buf[0], int(buf[1]), buf[2:]

	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || len(rest) < count {
			return berElement{}, nil, fmt.Errorf("unsupported BER length of %d octets", count)
		}
		length = 0
		for _, b := range rest[:count] {
			length = length<<8 | int(b)
		}
		rest = rest[count:]
	}
	if length < 0 || length > len(rest) {
		return berElement{}, nil, fmt.Errorf("element claims %d bytes, %d remain", length, len(rest))
	}
	return berElement{tag: tag, value: rest[:length]}, rest[length:], nil
}

// MySQL capability flags, from the initial handshake packet. Only the two that
// decide whether an upgrade is possible are named here.
const (
	mysqlClientSSL        = 0x00000800
	mysqlClientProtocol41 = 0x00000200
)

// startTLSMySQL performs the SSLRequest half of the MySQL handshake.
//
// MySQL inverts the usual order: the *server* speaks first, with a handshake
// packet advertising its capabilities, and the client answers with a truncated
// login packet that sets CLIENT_SSL and stops before the credentials. TLS then
// starts, and the real login is replayed inside it -- which y509 never does,
// because it only wants the certificates.
func startTLSMySQL(conn net.Conn) error {
	reader := bufio.NewReader(conn)

	payload, sequence, err := readMySQLPacket(reader)
	if err != nil {
		return fmt.Errorf("reading the server greeting: %w", err)
	}
	// 0xff is an ERR packet: the server refused the connection outright, most
	// often because the host is blocked or not permitted. Its body carries the
	// reason, and reporting that beats "malformed greeting".
	if len(payload) > 0 && payload[0] == 0xff {
		return fmt.Errorf("server refused the connection: %s", mysqlErrorText(payload))
	}

	capabilities, err := mysqlCapabilities(payload)
	if err != nil {
		return err
	}
	if capabilities&mysqlClientSSL == 0 {
		return fmt.Errorf("server does not advertise CLIENT_SSL; it was built or configured without TLS")
	}

	// The SSLRequest packet continues the greeting's sequence.
	if _, err := conn.Write(mysqlSSLRequest(sequence + 1)); err != nil {
		return err
	}
	return nil
}

// maxMySQLGreeting caps what readMySQLPacket will allocate. A real initial
// handshake is a couple of hundred bytes; the header alone can ask for 16 MiB,
// and the allocation would happen before a single byte of it arrived.
const maxMySQLGreeting = 64 << 10

// readMySQLPacket reads one packet and returns its payload and sequence id.
// Every MySQL packet is a three byte little-endian length, a sequence byte,
// and that many bytes of payload.
func readMySQLPacket(reader *bufio.Reader) (payload []byte, sequence byte, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, 0, err
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length > maxMySQLGreeting {
		return nil, 0, fmt.Errorf("greeting of %d bytes is implausibly large", length)
	}

	payload = make([]byte, length)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, 0, err
	}
	return payload, header[3], nil
}

// mysqlCapabilities pulls the capability flags out of a v10 initial handshake.
//
// The layout up to that point is fixed: a protocol version byte, a
// NUL-terminated server version string, a four byte connection id, eight bytes
// of auth-plugin data, one filler byte, then the lower two capability bytes.
// The upper two arrive later, after the character set and status flags, and
// CLIENT_SSL lives in the lower half -- but both are read, so the flags this
// returns are the whole set the server advertised.
func mysqlCapabilities(payload []byte) (uint32, error) {
	if len(payload) == 0 {
		return 0, fmt.Errorf("empty greeting")
	}
	if payload[0] != 10 {
		return 0, fmt.Errorf("unsupported MySQL protocol version %d", payload[0])
	}

	end := bytes.IndexByte(payload[1:], 0)
	if end < 0 {
		return 0, fmt.Errorf("unterminated server version in the greeting")
	}
	// Past the version string: 4 (connection id) + 8 (auth data) + 1 (filler).
	offset := 1 + end + 1 + 13
	if len(payload) < offset+2 {
		return 0, fmt.Errorf("greeting truncated before the capability flags")
	}
	capabilities := uint32(binary.LittleEndian.Uint16(payload[offset : offset+2]))

	// The upper half is optional; an old or minimal server stops here.
	if upper := offset + 2 + 3; len(payload) >= upper+2 {
		capabilities |= uint32(binary.LittleEndian.Uint16(payload[upper:upper+2])) << 16
	}
	return capabilities, nil
}

// mysqlSSLRequest builds the 32 byte SSLRequest packet: capability flags, a max
// packet size, a character set, and 23 reserved zero bytes. It is exactly a
// login packet with everything from the username onwards cut off.
func mysqlSSLRequest(sequence byte) []byte {
	const (
		payloadLength = 32
		maxPacketSize = 1 << 24
		utf8mb4       = 45
	)

	packet := make([]byte, 4+payloadLength)
	packet[0] = payloadLength
	packet[3] = sequence

	binary.LittleEndian.PutUint32(packet[4:8], mysqlClientSSL|mysqlClientProtocol41)
	binary.LittleEndian.PutUint32(packet[8:12], maxPacketSize)
	packet[12] = utf8mb4
	// packet[13:36] stays zero: the reserved filler.
	return packet
}

// mysqlErrorText renders the human-readable half of an ERR packet. The body is
// the 0xff marker, a two byte error code, and then either the message or a
// nine byte SQL state marker ("#HY000") followed by the message.
func mysqlErrorText(payload []byte) string {
	if len(payload) < 3 {
		return "unknown error"
	}
	code := binary.LittleEndian.Uint16(payload[1:3])
	message := payload[3:]
	if len(message) > 6 && message[0] == '#' {
		message = message[6:]
	}
	return fmt.Sprintf("%s (error %d)", strings.TrimSpace(string(message)), code)
}
