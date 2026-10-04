package certificate

import (
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// testLog registers a synthetic log with the bundled list for the duration of
// the test, so the policy is exercised against fixed states rather than
// whatever the list says about real logs this month.
func testLog(t *testing.T, b byte, operator, state, since string) []byte {
	t.Helper()
	loadCTLogs()
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = b
	}
	id := base64.StdEncoding.EncodeToString(raw)
	ctLogsByID[id] = CTLog{ID: id, Description: "test log " + string('A'+b), Operator: operator, State: state, StateSince: since}
	t.Cleanup(func() { delete(ctLogsByID, id) })
	return raw
}

func leafWithSCTs(t *testing.T, lifetime time.Duration, scts ...[]byte) *x509.Certificate {
	t.Helper()
	var list []byte
	for _, s := range scts {
		list = append(list, opaque16(s)...)
	}
	cert := certWithSCTList(t, opaque16(list))
	cert.NotBefore = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	cert.NotAfter = cert.NotBefore.Add(lifetime)
	return cert
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

	sct := func(logID []byte) []byte { return serializedSCT(t, logID, issued) }

	tests := []struct {
		name      string
		leaf      *x509.Certificate
		delivered [][]byte
		want      bool
	}{
		{"two operators, short", leafWithSCTs(t, short, sct(googleA), sct(digicert)), nil, false},
		{"one operator only", leafWithSCTs(t, short, sct(googleA), sct(googleB)), nil, true},
		{"one SCT", leafWithSCTs(t, short, sct(googleA)), nil, true},
		{"long lifetime needs three", leafWithSCTs(t, long, sct(googleA), sct(digicert)), nil, true},
		{"long lifetime with three", leafWithSCTs(t, long, sct(googleA), sct(googleB), sct(digicert)), nil, false},
		{"readonly counts", leafWithSCTs(t, short, sct(googleA), sct(sectigo)), nil, false},
		// An SCT issued before the log retired still counts...
		{"retired after the SCT", leafWithSCTs(t, short, sct(googleA), sct(retiredAfter)), nil, false},
		// ...one issued after does not.
		{"retired before the SCT", leafWithSCTs(t, short, sct(googleA), sct(retiredBefore)), nil, true},
		// At least one has to come from a log that is still live.
		{"only retired logs", leafWithSCTs(t, short, sct(retiredAfter), sct(testLog(t, 8, "IPng", "retired", "2026-09-20T00:00:00Z"))), nil, true},
		{"rejected log does not count", leafWithSCTs(t, short, sct(googleA), sct(rejected)), nil, true},
		{"TLS-delivered SCTs meet it", leafWithSCTs(t, long, sct(googleA)), [][]byte{sct(googleB), sct(digicert)}, false},
		// Retired logs do not count on the TLS path.
		{"TLS path ignores retired", &x509.Certificate{NotAfter: issued.Add(short), NotBefore: issued}, [][]byte{sct(googleA), sct(retiredAfter)}, true},
		// Not judged: nothing to go on, or a log the list does not know.
		{"no SCTs at all", &x509.Certificate{NotBefore: issued, NotAfter: issued.Add(short)}, nil, false},
		{"unknown log", leafWithSCTs(t, short, sct(googleA), sct(make([]byte, 32))), nil, false},
		{"damaged list", certWithSCTList(t, opaque16(opaque16([]byte{0, 1}))), nil, false},
		{"nil leaf", nil, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CTPolicyFinding(tt.leaf, tt.delivered, now)
			if (got != nil) != tt.want {
				t.Fatalf("finding = %+v, want reported=%v", got, tt.want)
			}
			if got != nil && (got.Problem != ProblemInsufficientSCTs || !strings.Contains(got.Detail, "Chrome requires")) {
				t.Errorf("finding = %+v", got)
			}
		})
	}
}

// TestCTPolicyNotJudgedOnAStaleList mirrors Chrome, which stops enforcing CT
// when its list is more than 70 days old.
func TestCTPolicyNotJudgedOnAStaleList(t *testing.T) {
	googleA := testLog(t, 11, "Google", "usable", "")
	listed, err := time.Parse(time.RFC3339, ctLogsList.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	leaf := leafWithSCTs(t, 90*24*time.Hour, serializedSCT(t, googleA, listed))
	if CTPolicyFinding(leaf, nil, listed.Add(69*24*time.Hour)) == nil {
		t.Error("one SCT is reported while the list is fresh")
	}
	if got := CTPolicyFinding(leaf, nil, listed.Add(71*24*time.Hour)); got != nil {
		t.Errorf("judged against a list 71 days old: %+v", got)
	}
}

func TestCTPolicyFindingNamesWhatItCounted(t *testing.T) {
	googleA := testLog(t, 9, "Google", "usable", "")
	googleB := testLog(t, 10, "Google", "usable", "")
	issued := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	got := CTPolicyFinding(leafWithSCTs(t, 90*24*time.Hour, serializedSCT(t, googleA, issued), serializedSCT(t, googleB, issued)), nil, issued)
	if got == nil || !strings.Contains(got.Detail, "SCTs from 2 distinct logs") || !strings.Contains(got.Detail, "has 2 counting SCTs from Google") {
		t.Fatalf("detail should say what was required and what was counted: %+v", got)
	}
}
