package certificate

import (
	"crypto/tls"
	"crypto/x509"
	"time"
)

// The JSON types below are a deliberate translation layer rather than json tags
// bolted onto the internal structs.
//
// TrustLevel and ChainProblem are integer constants whose numeric values exist
// only to make iota work; marshalling them directly would publish `"level": 2`
// as an API contract and break every consumer the moment a constant is
// inserted. Everything crossing this boundary is therefore a string, a
// timestamp, or a bool, and the field set is chosen rather than inherited.

// JSONReport is the machine-readable form of a validate run.
//
// It answers the two questions validate asks, separately: whether the chain
// verifies (Trust) and whether it was served correctly (Presentation). A chain
// can be trusted and still mis-served, so a consumer that only looks at Trust
// is throwing away the finding it most likely came for.
type JSONReport struct {
	// Host is the server the chain came from, empty for a file or stdin.
	Host string `json:"host,omitempty"`
	// Trust is the verification outcome against the configured trust anchors.
	Trust JSONTrust `json:"trust"`
	// Presentation is how the chain was served, judged structurally.
	Presentation JSONPresentation `json:"presentation"`
	// Chain is the certificates in the order they were presented -- the order a
	// server sent them, or the order they appear in a file. It is not sorted,
	// because sorting is what destroys the evidence Presentation reports on.
	Chain []JSONCertificate `json:"chain"`
	// Connection describes the handshake the chain arrived over. It is absent
	// for a file or stdin, where there was no handshake and every field would
	// be an invention.
	Connection *JSONConnection `json:"connection,omitempty"`
	// Unparsed lists the CERTIFICATE blocks the input held that could not be
	// read, so a consumer can tell "this chain is fine" from "this chain is
	// fine as far as it could be read". Absent when everything parsed, which
	// keeps the common case byte-identical for existing consumers.
	Unparsed []JSONUnparsed `json:"unparsed,omitempty"`
}

// JSONUnparsed is one CERTIFICATE block that failed to parse.
//
// The error text is the parser's own and is not a stable contract; Block and
// Bytes are what a consumer can act on -- where in the input it was, and enough
// to tell an empty block from a truncated certificate.
type JSONUnparsed struct {
	// Block is the position in the input, counting every CERTIFICATE block
	// from zero including the ones that failed.
	//
	// It is deliberately not called "index": Chain[].Index is a contiguous
	// counter over the certificates that parsed, so for an input of
	// good/bad/good the chain holds indexes 0 and 1 while this block is 1, and
	// the two ones are different certificates. Two numbering spaces with one
	// name would be worse than two names.
	Block int `json:"block"`
	// Bytes is the size of the DER that could not be parsed.
	Bytes int `json:"bytes"`
	// Error is what crypto/x509 reported.
	Error string `json:"error"`
}

// NewJSONUnparsed translates parse failures for the report. Returns nil for
// none, so the field is omitted rather than marshalled as an empty array: here
// "absent" and "empty" mean the same thing, and absent keeps the output
// unchanged for the overwhelming majority of runs.
func NewJSONUnparsed(failures []ParseFailure) []JSONUnparsed {
	if len(failures) == 0 {
		return nil
	}

	out := make([]JSONUnparsed, 0, len(failures))
	for _, f := range failures {
		entry := JSONUnparsed{Block: f.Block, Bytes: len(f.Raw)}
		if f.Err != nil {
			entry.Error = f.Err.Error()
		}
		out = append(out, entry)
	}
	return out
}

// JSONConnection is what the handshake itself revealed, as opposed to what the
// certificates say.
//
// "Is anything still negotiating TLS 1.0" and "did stapling quietly stop
// working" are both questions a scheduled check wants to answer, and neither is
// visible anywhere in the chain.
type JSONConnection struct {
	// TLSVersion is the negotiated version, as "TLS 1.3" rather than 0x0304.
	TLSVersion string `json:"tlsVersion"`
	// CipherSuite is the negotiated suite by its IANA name.
	CipherSuite string `json:"cipherSuite"`
	// OCSPStapled reports whether the server stapled an OCSP response. It says
	// nothing about what that response contained; y509 does no revocation
	// checking.
	OCSPStapled bool `json:"ocspStapled"`
}

// NewJSONConnection renders a handshake for the report, or nil when there was
// none. Both fields cross the boundary as strings: Version and CipherSuite are
// uint16 on the wire, and publishing those numbers would make the constant
// values an API in exactly the way this package avoids elsewhere.
func NewJSONConnection(result *ConnectResult) *JSONConnection {
	if result == nil {
		return nil
	}
	return &JSONConnection{
		TLSVersion:  result.TLSVersionName(),
		CipherSuite: tls.CipherSuiteName(result.CipherSuite),
		OCSPStapled: result.OCSPStapled,
	}
}

// JSONTrust is the verification outcome.
type JSONTrust struct {
	// Level is "trusted", "self-anchored" or "broken".
	//
	// The distinction between the latter two is the reason this field exists:
	// both exit non-zero, so an exit code alone cannot tell an internal PKI
	// apart from a genuinely broken chain.
	Level string `json:"level"`
	// Trusted is true only for "trusted", mirroring the exit status for a
	// consumer that wants a single boolean.
	Trusted bool `json:"trusted"`
	// Anchor is the common name of the root the chain terminated at, when one
	// was found.
	Anchor string `json:"anchor,omitempty"`
	// Error is why the chain is not anchored, set for every level below
	// "trusted" -- including "self-anchored", where it explains why the chain
	// is not publicly trusted.
	Error string `json:"error,omitempty"`
}

// JSONPresentation is how the chain was served, as opposed to whether it
// verifies.
type JSONPresentation struct {
	// OK reports whether the chain was presented correctly.
	OK bool `json:"ok"`
	// Findings are the problems with how it was presented, in the order they
	// were discovered. Always an array, never null, so a consumer can range
	// over it unconditionally.
	Findings []JSONFinding `json:"findings"`
}

// JSONFinding is one presentation problem, tied to the certificate it concerns.
type JSONFinding struct {
	// Problem is the short name: "missing issuer", "redundant root",
	// "out of order", "duplicate" or "unrelated".
	Problem string `json:"problem"`
	// Subject is the common name of the certificate concerned.
	Subject string `json:"subject"`
	// Detail explains the finding in a sentence.
	Detail string `json:"detail"`
	// FetchURLs are the AIA CA-Issuers URLs that would supply a missing issuer.
	// Only set for a missing issuer.
	FetchURLs []string `json:"fetchUrls,omitempty"`
}

// JSONCertificate is one certificate, reduced to the fields a script is likely
// to gate on.
//
// It is deliberately not a full dump of x509.Certificate: this is an API
// contract, and every field added is a field that has to keep working.
type JSONCertificate struct {
	// Index is the position in the chain as presented, leaf first when the
	// sender got the order right.
	Index int `json:"index"`
	// Subject is the full RFC 2253 subject.
	Subject string `json:"subject"`
	// CommonName is the subject common name on its own, which is what the
	// human-readable output keys off.
	CommonName string `json:"commonName,omitempty"`
	// Issuer is the full RFC 2253 issuer.
	Issuer string `json:"issuer"`
	// SerialNumber is hex-encoded, matching how openssl and the CAs print it.
	SerialNumber string `json:"serialNumber"`
	// NotBefore and NotAfter are the validity window, in RFC 3339.
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	// DaysUntilExpiry counts whole days from now to NotAfter, negative once the
	// certificate has expired. This is the field an expiry monitor wants.
	DaysUntilExpiry int `json:"daysUntilExpiry"`
	// Expired reports whether NotAfter is already in the past.
	Expired bool `json:"expired"`
	// ValidityDays is the certificate's total lifetime.
	ValidityDays int `json:"validityDays"`
	// ExceedsCABMaxLifetime reports a subscriber certificate whose lifetime is
	// longer than the CA/Browser Forum maximum. CA certificates are exempt, so
	// it is always false for them.
	ExceedsCABMaxLifetime bool `json:"exceedsCabMaxLifetime"`
	// IsCA is the basic constraints CA bit.
	IsCA bool `json:"isCa"`
	// SelfSigned reports whether the subject and issuer match.
	SelfSigned bool `json:"selfSigned"`
	// DNSNames and IPAddresses are the subject alternative names, which is what
	// hostname coverage is actually checked against.
	DNSNames    []string `json:"dnsNames,omitempty"`
	IPAddresses []string `json:"ipAddresses,omitempty"`
	// KeyAlgorithm and SignatureAlgorithm name the crypto in use, so a script
	// can flag a deprecated algorithm.
	KeyAlgorithm       string `json:"keyAlgorithm"`
	SignatureAlgorithm string `json:"signatureAlgorithm"`
	// FingerprintSHA256 is the hex SHA-256 of the DER, which is how a
	// certificate is pinned and compared across runs.
	FingerprintSHA256 string `json:"fingerprintSha256"`
}

// NewJSONReport assembles the machine-readable report.
//
// report must be the analysis of the chain as presented, and result the
// verification outcome for the same chain. host is the server that was
// contacted, empty for a file or stdin.
func NewJSONReport(host string, report *ChainReport, result *VerifyResult) *JSONReport {
	out := &JSONReport{
		Host: host,
		// Findings and Chain are initialised to empty rather than left nil so
		// they marshal as [] instead of null. A consumer ranging over a null
		// gets an unhelpful surprise in most languages, and "no findings" is
		// the common case.
		Presentation: JSONPresentation{OK: true, Findings: []JSONFinding{}},
		Chain:        []JSONCertificate{},
	}

	if result != nil {
		out.Trust = JSONTrust{
			Level:   result.Level.String(),
			Trusted: result.Level == TrustAnchored,
			Anchor:  result.Anchor,
		}
		if result.Err != nil {
			out.Trust.Error = result.Err.Error()
		}
	}

	if report == nil {
		return out
	}

	out.Presentation.OK = report.OK()
	for _, finding := range report.Findings {
		out.Presentation.Findings = append(out.Presentation.Findings, JSONFinding{
			Problem:   finding.Problem.String(),
			Subject:   finding.Subject,
			Detail:    finding.Detail,
			FetchURLs: finding.FetchURLs,
		})
	}

	now := time.Now()
	for i, cert := range report.Sent {
		if cert == nil {
			continue
		}
		out.Chain = append(out.Chain, newJSONCertificate(i, cert, now))
	}

	return out
}

// newJSONCertificate reduces one certificate to the JSON contract.
func newJSONCertificate(index int, cert *x509.Certificate, now time.Time) JSONCertificate {
	entry := JSONCertificate{
		Index:                 index,
		Subject:               cert.Subject.String(),
		CommonName:            cert.Subject.CommonName,
		Issuer:                cert.Issuer.String(),
		NotBefore:             cert.NotBefore,
		NotAfter:              cert.NotAfter,
		DaysUntilExpiry:       daysUntil(cert.NotAfter, now),
		Expired:               cert.NotAfter.Before(now),
		ValidityDays:          ValidityPeriodDays(cert),
		ExceedsCABMaxLifetime: ExceedsCABMaxLifetime(cert),
		IsCA:                  cert.IsCA,
		SelfSigned:            cert.Subject.String() == cert.Issuer.String(),
		DNSNames:              cert.DNSNames,
		KeyAlgorithm:          cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm:    cert.SignatureAlgorithm.String(),
		FingerprintSHA256:     FormatFingerprint(cert),
	}

	if cert.SerialNumber != nil {
		entry.SerialNumber = cert.SerialNumber.Text(16)
	}

	for _, ip := range cert.IPAddresses {
		entry.IPAddresses = append(entry.IPAddresses, ip.String())
	}

	return entry
}

// daysUntil counts whole days from now to t, rounding towards minus infinity so
// a certificate that expires in twelve hours reports 0 rather than 1.
//
// Like ValidityPeriodDays this works in Unix seconds rather than time.Duration,
// which is int64 nanoseconds and overflows at ~292 years -- well short of the
// 9999-12-31 "no expiry" convention.
func daysUntil(t, now time.Time) int {
	const secsPerDay = 24 * 60 * 60
	secs := t.Unix() - now.Unix()
	days := secs / secsPerDay
	if secs < 0 && secs%secsPerDay != 0 {
		days--
	}
	return int(days)
}
