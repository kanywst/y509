package certificate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"math/big"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// ctTestLog is a synthetic log registered with the bundled list for the test,
// so the policy runs against fixed states and real signatures rather than
// whatever the list says about real logs this month.
type ctTestLog struct {
	id  []byte
	key *ecdsa.PrivateKey
}

func testLog(t *testing.T, b byte, operator, state, since string) ctTestLog {
	t.Helper()
	loadCTLogs()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// A real log ID is the SHA-256 of its key; the test only needs it unique
	// and recognisable, so it is a fill byte.
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	id := base64.StdEncoding.EncodeToString(raw)
	ctLogsByID[id] = CTLog{
		ID: id, Description: "test log " + string('A'+b), Operator: operator,
		State: state, StateSince: since, Key: base64.StdEncoding.EncodeToString(spki),
	}
	t.Cleanup(func() { delete(ctLogsByID, id) })
	return ctTestLog{id: raw, key: key}
}

// sign produces a serialized v1 SCT over entry, signed by the log.
func (l ctTestLog) sign(t *testing.T, ts time.Time, entryType uint16, entry func(*cryptobyte.Builder)) []byte {
	t.Helper()
	var signed cryptobyte.Builder
	signed.AddUint8(0)
	signed.AddUint8(0)
	signed.AddUint64(uint64(ts.UnixMilli()))
	signed.AddUint16(entryType)
	entry(&signed)
	signed.AddUint16(0) // no extensions
	digest := sha256.Sum256(signed.BytesOrPanic())
	sig, err := ecdsa.SignASN1(rand.Reader, l.key, digest[:])
	if err != nil {
		t.Fatal(err)
	}

	out := []byte{0}
	out = append(out, l.id...)
	out = binary.BigEndian.AppendUint64(out, uint64(ts.UnixMilli()))
	out = append(out, 0, 0, sctHashSHA256, sctSigECDSA)
	return append(out, opaque16(sig)...)
}

// ctFixture is an issuer and the inputs to mint leaves under it.
type ctFixture struct {
	issuer    *x509.Certificate
	issuerKey *ecdsa.PrivateKey
	leafKey   *ecdsa.PrivateKey
}

func newCTFixture(t *testing.T) ctFixture {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "CT Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(1000 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return ctFixture{issuer: issuer, issuerKey: issuerKey, leafKey: leafKey}
}

func (f ctFixture) mint(t *testing.T, lifetime time.Duration, extra []pkix.Extension) *x509.Certificate {
	t.Helper()
	notBefore := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "ct.test"},
		DNSNames:  []string{"ct.test"},
		NotBefore: notBefore, NotAfter: notBefore.Add(lifetime),
		ExtraExtensions: extra,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.issuer, &f.leafKey.PublicKey, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// leaf mints a leaf whose embedded SCTs are signed by logs, the way a CA does:
// the logs sign the precertificate (this TBS without the SCT list), and the
// final certificate carries their SCTs. ExtraExtensions are appended last, so
// removing the SCT list from the final TBS gives back the precertificate's.
func (f ctFixture) leaf(t *testing.T, lifetime time.Duration, ts time.Time, logs ...ctTestLog) *x509.Certificate {
	t.Helper()
	precert := f.mint(t, lifetime, nil)
	issuerKeyHash := sha256.Sum256(f.issuer.RawSubjectPublicKeyInfo)

	var list []byte
	for _, l := range logs {
		sct := l.sign(t, ts, 1, func(b *cryptobyte.Builder) {
			b.AddBytes(issuerKeyHash[:])
			b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(precert.RawTBSCertificate) })
		})
		list = append(list, opaque16(sct)...)
	}
	value, err := asn1.Marshal(opaque16(list))
	if err != nil {
		t.Fatal(err)
	}
	return f.mint(t, lifetime, []pkix.Extension{{Id: oidSCTList, Value: value}})
}

// delivered is an SCT as a server sends it in the TLS extension: over the
// final certificate itself.
func delivered(t *testing.T, l ctTestLog, leaf *x509.Certificate, ts time.Time) []byte {
	t.Helper()
	return l.sign(t, ts, 0, func(b *cryptobyte.Builder) {
		b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(leaf.Raw) })
	})
}

func TestCTPolicyFinding(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	issued := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	short := 90 * 24 * time.Hour
	long := 200 * 24 * time.Hour

	googleA := testLog(t, 1, "Google", "usable", "")
	googleB := testLog(t, 2, "Google", "usable", "")
	digicert := testLog(t, 3, "DigiCert", "usable", "")
	sectigo := testLog(t, 4, "Sectigo", "readonly", "")
	retiredAfter := testLog(t, 5, "Let's Encrypt", "retired", "2026-09-15T00:00:00Z")
	retiredBefore := testLog(t, 6, "Let's Encrypt", "retired", "2026-08-01T00:00:00Z")
	rejected := testLog(t, 7, "Cloudflare", "rejected", "2026-07-01T00:00:00Z")
	ipng := testLog(t, 8, "IPng", "retired", "2026-09-20T00:00:00Z")
	keyless := testLog(t, 15, "HARICA", "pending", "2026-09-01T00:00:00Z")
	keylessID := base64.StdEncoding.EncodeToString(keyless.id)
	entry := ctLogsByID[keylessID]
	entry.Key = ""
	ctLogsByID[keylessID] = entry

	f := newCTFixture(t)
	bare := f.mint(t, short, nil)

	tests := []struct {
		name      string
		leaf      *x509.Certificate
		issuer    *x509.Certificate
		delivered [][]byte
		want      bool
	}{
		{"two operators, short", f.leaf(t, short, issued, googleA, digicert), f.issuer, nil, false},
		{"one operator only", f.leaf(t, short, issued, googleA, googleB), f.issuer, nil, true},
		{"one SCT", f.leaf(t, short, issued, googleA), f.issuer, nil, true},
		{"long lifetime needs three", f.leaf(t, long, issued, googleA, digicert), f.issuer, nil, true},
		{"long lifetime with three", f.leaf(t, long, issued, googleA, googleB, digicert), f.issuer, nil, false},
		{"readonly counts", f.leaf(t, short, issued, googleA, sectigo), f.issuer, nil, false},
		// An SCT issued before the log retired still counts; one after does not.
		{"retired after the SCT", f.leaf(t, short, issued, googleA, retiredAfter), f.issuer, nil, false},
		{"retired before the SCT", f.leaf(t, short, issued, googleA, retiredBefore), f.issuer, nil, true},
		// At least one has to come from a log that is still live.
		{"only retired logs", f.leaf(t, short, issued, retiredAfter, ipng), f.issuer, nil, true},
		{"rejected log does not count", f.leaf(t, short, issued, googleA, rejected), f.issuer, nil, true},
		{"TLS-delivered SCTs meet it", bare, f.issuer, [][]byte{delivered(t, googleA, bare, issued), delivered(t, digicert, bare, issued)}, false},
		// Retired logs do not count on the TLS path.
		{"TLS path ignores retired", bare, f.issuer, [][]byte{delivered(t, googleA, bare, issued), delivered(t, retiredAfter, bare, issued)}, true},
		// Not judged: nothing to go on, a log the list does not know, no
		// issuer to check an embedded SCT against, or a damaged list.
		{"no SCTs at all", bare, f.issuer, nil, false},
		{"unknown log", f.leaf(t, short, issued, googleA, ctTestLog{id: make([]byte, 32), key: googleA.key}), f.issuer, nil, false},
		{"no issuer", f.leaf(t, short, issued, googleA), nil, nil, false},
		{"known log without a key", f.leaf(t, short, issued, googleA, keyless), f.issuer, nil, false},
		{"damaged list", certWithSCTList(t, opaque16(opaque16([]byte{0, 1}))), f.issuer, nil, false},
		{"nil leaf", nil, nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CTPolicyFinding(tt.leaf, tt.issuer, tt.delivered, now)
			if (got != nil) != tt.want {
				t.Fatalf("finding = %+v, want reported=%v", got, tt.want)
			}
			if got != nil && (got.Problem != ProblemInsufficientSCTs || !strings.Contains(got.Detail, "Chrome requires")) {
				t.Errorf("finding = %+v", got)
			}
		})
	}
}

// TestCTPolicyCountsOnlyVerifiedSCTs is the reason signatures are checked: a
// server, or a damaged certificate, can name two good logs in SCTs no log ever
// signed, and that must not satisfy the policy.
func TestCTPolicyCountsOnlyVerifiedSCTs(t *testing.T) {
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	issued := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	google := testLog(t, 12, "Google", "usable", "")
	digicert := testLog(t, 13, "DigiCert", "usable", "")
	f := newCTFixture(t)
	bare := f.mint(t, 90*24*time.Hour, nil)

	forged := func(l ctTestLog) []byte {
		sct := delivered(t, l, bare, issued)
		sct[len(sct)-1] ^= 0xff // flip a signature byte
		return sct
	}
	got := CTPolicyFinding(bare, f.issuer, [][]byte{forged(google), forged(digicert)}, now)
	if got == nil {
		t.Fatal("forged TLS SCTs satisfied the policy")
	}
	if !strings.Contains(got.Detail, "2 SCTs whose signature does not verify") || !strings.Contains(got.Detail, "have the server send enough SCTs") {
		t.Errorf("detail should count the forged SCTs and point at the server: %s", got.Detail)
	}

	// Embedded SCTs signed over a different precertificate do not verify
	// against this one either.
	other := newCTFixture(t)
	foreign := other.leaf(t, 90*24*time.Hour, issued, google, digicert)
	if CTPolicyFinding(foreign, f.issuer, nil, now) == nil {
		t.Error("embedded SCTs checked against the wrong issuer satisfied the policy")
	}
	if CTPolicyFinding(foreign, other.issuer, nil, now) != nil {
		t.Error("the same SCTs against their own issuer should verify")
	}
}

// TestCTPolicyNotJudgedOnAStaleList mirrors Chrome, which stops enforcing CT
// when its list is more than 70 days old.
func TestCTPolicyNotJudgedOnAStaleList(t *testing.T) {
	google := testLog(t, 11, "Google", "usable", "")
	listed, err := time.Parse(time.RFC3339, ctLogsList.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	f := newCTFixture(t)
	leaf := f.leaf(t, 90*24*time.Hour, listed, google)
	if CTPolicyFinding(leaf, f.issuer, nil, listed.Add(69*24*time.Hour)) == nil {
		t.Error("one SCT is reported while the list is fresh")
	}
	if got := CTPolicyFinding(leaf, f.issuer, nil, listed.Add(71*24*time.Hour)); got != nil {
		t.Errorf("judged against a list 71 days old: %+v", got)
	}
}

func TestCTPolicyFindingNamesWhatItCounted(t *testing.T) {
	googleA := testLog(t, 9, "Google", "usable", "")
	googleB := testLog(t, 10, "Google", "usable", "")
	issued := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	f := newCTFixture(t)
	got := CTPolicyFinding(f.leaf(t, 90*24*time.Hour, issued, googleA, googleB), f.issuer, nil, issued)
	if got == nil || !strings.Contains(got.Detail, "SCTs from 2 distinct logs") || !strings.Contains(got.Detail, "has 2 counting embedded (Google)") || !strings.Contains(got.Detail, "ask the CA to reissue") {
		t.Fatalf("detail should say what was required and what was counted: %+v", got)
	}
}

func TestTBSWithoutSCTListRoundTrips(t *testing.T) {
	google := testLog(t, 14, "Google", "usable", "")
	f := newCTFixture(t)
	issued := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	precert := f.mint(t, 90*24*time.Hour, nil)
	final := f.leaf(t, 90*24*time.Hour, issued, google)

	got, err := tbsWithoutSCTList(final.RawTBSCertificate)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(precert.RawTBSCertificate) {
		t.Error("removing the SCT list did not give back the precertificate's TBS")
	}
	if _, err := tbsWithoutSCTList([]byte{0x30, 0x05}); err == nil {
		t.Error("a truncated TBS parsed")
	}
}
