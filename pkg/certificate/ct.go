package certificate

import (
	"crypto/x509"
	_ "embed"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ctlogs.json is Google's CT log list trimmed to what is shown next to an SCT.
// Refresh it with `make ct-logs`; nothing here goes to the network.
//
//go:embed ctlogs.json
var ctLogsJSON []byte

// CTLog is a Certificate Transparency log as the bundled list describes it.
type CTLog struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Operator    string `json:"operator"`
	// State is the log's state in the list: usable, qualified, readonly,
	// retired, rejected or pending.
	State string `json:"state"`
	// StateSince is when the log entered State, in RFC 3339.
	StateSince string `json:"stateSince"`
	// Key is the log's public key, base64 DER SubjectPublicKeyInfo.
	Key string `json:"key"`
}

type ctLogBundle struct {
	Version   string  `json:"version"`
	Timestamp string  `json:"timestamp"`
	Logs      []CTLog `json:"logs"`
}

var (
	ctLogsOnce sync.Once
	ctLogsByID map[string]CTLog
	ctLogsList ctLogBundle
)

func loadCTLogs() {
	ctLogsOnce.Do(func() {
		ctLogsByID = map[string]CTLog{}
		// A malformed bundle is a build defect the tests catch; at run time it
		// degrades to SCTs shown by log ID rather than a crash.
		if err := json.Unmarshal(ctLogsJSON, &ctLogsList); err != nil {
			return
		}
		for _, l := range ctLogsList.Logs {
			ctLogsByID[l.ID] = l
		}
	})
}

// CTLogListVersion says which list SCTs are named from, so a log missing from
// it can be told apart from a log that does not exist.
func CTLogListVersion() string {
	loadCTLogs()
	return fmt.Sprintf("%s (%s)", ctLogsList.Version, ctLogsList.Timestamp)
}

// SCT is one Signed Certificate Timestamp embedded in a certificate.
type SCT struct {
	// LogID is the base64 SHA-256 of the log's key, as log lists write it.
	LogID string
	// Log is the log from the bundled list, nil when the list does not know it.
	Log *CTLog
	// Timestamp is when the log promised to include the certificate.
	Timestamp time.Time

	// signed is what VerifySCT needs: the signed fields and the signature.
	// It sits behind a pointer so SCT stays comparable.
	signed *sctSigned
}

type sctSigned struct {
	timestampMS uint64
	extensions  []byte
	hashAlg     byte
	sigAlg      byte
	signature   []byte
}

// Name is the log's description, or its ID when the list does not know it.
func (s SCT) Name() string {
	if s.Log == nil {
		return "unknown log " + s.LogID
	}
	if s.Log.Description != "" {
		return s.Log.Description
	}
	return s.Log.Operator + " log " + s.LogID
}

var oidSCTList = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// SCTs reads the SCTs embedded in the certificate (RFC 6962 section 3.3). It
// returns nil when there are none. SCTs a server sends in the handshake or in
// a stapled OCSP response are not in the certificate and not read here.
//
// Nothing is verified: the signatures are not checked and no log is asked
// anything. This says which logs the certificate claims, which is what decides
// whether a client's CT policy can be met.
func SCTs(cert *x509.Certificate) ([]SCT, error) {
	if cert == nil {
		return nil, nil
	}
	var raw []byte
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidSCTList) {
			raw = ext.Value
			break
		}
	}
	if raw == nil {
		return nil, nil
	}

	// The extension value is an OCTET STRING wrapping the TLS-encoded list.
	var list []byte
	if _, err := asn1.Unmarshal(raw, &list); err != nil {
		return nil, fmt.Errorf("SCT list is not an OCTET STRING: %w", err)
	}
	body, rest, err := readOpaque16(list)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("SCT list length does not match its contents")
	}

	loadCTLogs()
	var out []SCT
	for len(body) > 0 {
		var sct []byte
		sct, body, err = readOpaque16(body)
		if err != nil {
			return out, errors.New("SCT list is truncated")
		}
		parsed, err := parseSCT(sct)
		if err != nil {
			return out, err
		}
		out = append(out, parsed)
	}
	return out, nil
}

// parseSCT reads one serialized SCT (RFC 6962 section 3.2): version, log ID,
// timestamp, extensions and the digitally-signed signature.
func parseSCT(b []byte) (SCT, error) {
	const header = 1 + 32 + 8
	if len(b) < header {
		return SCT{}, errors.New("SCT is truncated")
	}
	if b[0] != 0 {
		return SCT{}, fmt.Errorf("SCT version %d is not v1", b[0])
	}
	id := base64.StdEncoding.EncodeToString(b[1:33])
	ms := binary.BigEndian.Uint64(b[33:41])
	extensions, rest, err := readOpaque16(b[header:])
	if err != nil {
		return SCT{}, errors.New("SCT extensions are truncated")
	}
	if len(rest) < 2 {
		return SCT{}, errors.New("SCT signature is truncated")
	}
	signature, rest, err := readOpaque16(rest[2:])
	if err != nil || len(rest) != 0 {
		return SCT{}, errors.New("SCT signature length does not match its contents")
	}
	sct := SCT{
		LogID:     id,
		Timestamp: time.UnixMilli(int64(ms)).UTC(),
		signed: &sctSigned{
			timestampMS: ms,
			extensions:  extensions,
			hashAlg:     b[header+2+len(extensions)],
			sigAlg:      b[header+2+len(extensions)+1],
			signature:   signature,
		},
	}
	if l, ok := ctLogsByID[id]; ok {
		sct.Log = &l
	}
	return sct, nil
}

// readOpaque16 reads a TLS opaque<0..2^16-1>: a two-byte length and that many
// bytes.
func readOpaque16(b []byte) (value, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, errors.New("truncated length")
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b)-2 < n {
		return nil, nil, errors.New("truncated value")
	}
	return b[2 : 2+n], b[2+n:], nil
}
