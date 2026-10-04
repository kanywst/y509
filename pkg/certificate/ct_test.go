package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// argon2026h1 is a log the bundled list knows (now rejected, which also
// shows a retired log is still named), by its base64 log ID.
const argon2026h1 = "DleUvPOuqT4zGyyZB7P3kN+bwj1xMiXdIaklrGHFTiE="

// serializedSCT builds one v1 SCT: version, log ID, timestamp, empty
// extensions and a stand-in signature, which is never checked.
func serializedSCT(t *testing.T, logID []byte, ts time.Time) []byte {
	t.Helper()
	b := []byte{0}
	b = append(b, logID...)
	b = binary.BigEndian.AppendUint64(b, uint64(ts.UnixMilli()))
	b = append(b, 0, 0)       // extensions
	b = append(b, 4, 3, 0, 1) // sha256/ecdsa, a one-byte signature
	return append(b, 0xaa)
}

func opaque16(b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

// certWithSCTList wraps serialized SCTs the way RFC 6962 embeds them: a TLS
// list inside an OCTET STRING inside the extension.
func certWithSCTList(t *testing.T, list []byte) *x509.Certificate {
	t.Helper()
	value, err := asn1.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{Extensions: []pkix.Extension{{Id: oidSCTList, Value: value}}}
}

func TestSCTsNamesTheLogs(t *testing.T) {
	known, _ := base64.StdEncoding.DecodeString(argon2026h1)
	unknown := make([]byte, 32)
	ts := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	cert := certWithSCTList(t, opaque16(append(
		opaque16(serializedSCT(t, known, ts)),
		opaque16(serializedSCT(t, unknown, ts.Add(time.Second)))...)))

	got, err := SCTs(cert)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d SCTs, want 2", len(got))
	}
	if got[0].Log == nil || got[0].Log.Operator != "Google" || got[0].Name() != "Google 'Argon2026h1' log" {
		t.Errorf("known log = %+v (%s)", got[0].Log, got[0].Name())
	}
	if !got[0].Timestamp.Equal(ts) {
		t.Errorf("timestamp = %v, want %v", got[0].Timestamp, ts)
	}
	if got[1].Log != nil || !strings.HasPrefix(got[1].Name(), "unknown log AAAA") {
		t.Errorf("unknown log = %+v (%s)", got[1].Log, got[1].Name())
	}
}

func TestSCTsWithoutTheExtension(t *testing.T) {
	got, err := SCTs(&x509.Certificate{})
	if err != nil || got != nil {
		t.Fatalf("no extension = %v, %v; want nil, nil", got, err)
	}
	if got, err := SCTs(nil); err != nil || got != nil {
		t.Fatalf("nil certificate = %v, %v", got, err)
	}
}

func TestSCTsRejectsDamage(t *testing.T) {
	known, _ := base64.StdEncoding.DecodeString(argon2026h1)
	good := opaque16(serializedSCT(t, known, time.Now()))

	v2 := serializedSCT(t, known, time.Now())
	v2[0] = 1

	for name, list := range map[string][]byte{
		"outer length too long": append([]byte{0xff, 0xff}, good...),
		"truncated sct":         opaque16(append(good, 0x00)),
		"short sct":             opaque16(opaque16([]byte{0, 1, 2})),
		"not v1":                opaque16(opaque16(v2)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := SCTs(certWithSCTList(t, list)); err == nil {
				t.Error("damaged SCT list read without error")
			}
		})
	}
}

// TestBundledCTLogList guards the committed file: it parses, it is not empty,
// and every ID is a SHA-256 in base64, which is what an SCT is matched on.
func TestBundledCTLogList(t *testing.T) {
	var bundle ctLogBundle
	if err := json.Unmarshal(ctLogsJSON, &bundle); err != nil {
		t.Fatalf("ctlogs.json does not parse: %v", err)
	}
	if len(bundle.Logs) < 50 || bundle.Version == "" || bundle.Timestamp == "" {
		t.Fatalf("bundle looks empty: %d logs, version %q, timestamp %q", len(bundle.Logs), bundle.Version, bundle.Timestamp)
	}
	for _, l := range bundle.Logs {
		id, err := base64.StdEncoding.DecodeString(l.ID)
		if err != nil || len(id) != 32 {
			t.Errorf("log %q has an ID that is not a base64 SHA-256: %q", l.Description, l.ID)
		}
		if l.Operator == "" {
			t.Errorf("log %q has no operator", l.ID)
		}
	}
	if !strings.Contains(CTLogListVersion(), bundle.Version) {
		t.Errorf("CTLogListVersion() = %q", CTLogListVersion())
	}
}

func TestJSONCertificateCarriesSCTs(t *testing.T) {
	known, _ := base64.StdEncoding.DecodeString(argon2026h1)
	cert := certWithSCTList(t, opaque16(opaque16(serializedSCT(t, known, time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)))))

	out, err := json.Marshal(newJSONCertificate(0, cert, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	want := `"scts":[{"logId":"` + argon2026h1 + `","log":"Google 'Argon2026h1' log","operator":"Google","logState":`
	if !strings.Contains(string(out), want) {
		t.Errorf("certificate JSON is missing %s:\n%s", want, out)
	}

	out, err = json.Marshal(newJSONCertificate(0, &x509.Certificate{}, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"scts":[]`) {
		t.Errorf("no SCTs must marshal as []: %s", out)
	}
}
