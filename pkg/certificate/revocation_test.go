package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func stapledResult(staple *Staple, stapleErr error) *ConnectResult {
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(0x2a),
		Subject:      pkix.Name{CommonName: "staple.test"},
	}
	return &ConnectResult{
		Certificates: []*Info{{Certificate: leaf}},
		OCSPStapled:  true,
		Staple:       staple,
		StapleErr:    stapleErr,
	}
}

func problems(findings []RevocationFinding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Problem)
	}
	return out
}

func TestStapleFindings(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name   string
		result *ConnectResult
		want   []string
	}{
		{"no handshake", nil, nil},
		{"nothing stapled", &ConnectResult{Certificates: []*Info{{}}}, nil},
		{"good and fresh", stapledResult(&Staple{Status: "good", Verified: true, NextUpdate: now.Add(time.Hour)}, nil), nil},
		{"good without nextUpdate", stapledResult(&Staple{Status: "good", Verified: true}, nil), nil},
		// The issuer was not sent, so nothing could be checked. That is the
		// missing-issuer presentation finding, not a staple problem.
		{"unverified for want of an issuer", stapledResult(&Staple{Status: "good"}, nil), nil},
		{"revoked", stapledResult(&Staple{Status: "revoked", Verified: true, RevokedAt: now.Add(-time.Hour), RevocationReason: "key compromise"}, nil), []string{ProblemRevoked}},
		{"unknown", stapledResult(&Staple{Status: "unknown", Verified: true}, nil), []string{ProblemUnknownStatus}},
		{"stale", stapledResult(&Staple{Status: "good", Verified: true, NextUpdate: now.Add(-time.Minute)}, nil), []string{ProblemStaleStaple}},
		{"thisUpdate inside the clock-skew slop", stapledResult(&Staple{Status: "good", Verified: true, ThisUpdate: now.Add(23 * time.Hour)}, nil), nil},
		{"thisUpdate past the slop", stapledResult(&Staple{Status: "good", Verified: true, ThisUpdate: now.Add(25 * time.Hour)}, nil), []string{ProblemFutureStaple}},
		{"bad signature", stapledResult(&Staple{Status: "good", VerifyErr: errors.New("bad signature")}, nil), []string{ProblemBadStapleSig}},
		{"unreadable", stapledResult(nil, errors.New("asn1: syntax error")), []string{ProblemUnreadableStaple}},
		{"revoked, stale and badly signed", stapledResult(&Staple{Status: "revoked", VerifyErr: errors.New("bad signature"), NextUpdate: now.Add(-time.Minute)}, nil),
			[]string{ProblemRevoked, ProblemBadStapleSig, ProblemStaleStaple}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StapleFindings(tt.result, now)
			if strings.Join(problems(got), ",") != strings.Join(tt.want, ",") {
				t.Fatalf("problems = %v, want %v", problems(got), tt.want)
			}
			for _, f := range got {
				if f.Subject != "staple.test" {
					t.Errorf("subject = %q, want the leaf", f.Subject)
				}
				if f.Detail == "" {
					t.Errorf("%s has no detail", f.Problem)
				}
			}
		})
	}
}

func TestStapleFindingsRevokedNamesWhenAndWhy(t *testing.T) {
	at := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	got := StapleFindings(stapledResult(&Staple{Status: "revoked", RevokedAt: at, RevocationReason: "key compromise"}, nil), at.Add(time.Hour))
	if len(got) != 1 || !strings.Contains(got[0].Detail, "2026-09-01T00:00:00Z") || !strings.Contains(got[0].Detail, "key compromise") {
		t.Fatalf("revoked detail should say when and why: %+v", got)
	}
}

// TestJSONRevocationShape pins the contract: absent without a handshake,
// ok with an empty array when nothing is wrong, never null.
func TestJSONRevocationShape(t *testing.T) {
	if NewJSONRevocation(nil, time.Now()) != nil {
		t.Fatal("a file or stdin must not report a revocation verdict")
	}

	out, err := json.Marshal(NewJSONRevocation(&ConnectResult{}, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"ok":true,"findings":[]}` {
		t.Errorf("no staple = %s, want ok with an empty array", out)
	}

	rev := NewJSONRevocation(stapledResult(&Staple{Status: "revoked"}, nil), time.Now())
	if rev.OK || len(rev.Findings) != 1 || rev.Findings[0].Problem != "revoked" || rev.Findings[0].Subject != "staple.test" {
		t.Errorf("revoked staple = %+v", rev)
	}
}

func TestFormatStapleFindings(t *testing.T) {
	if FormatStapleFindings(nil) != "" {
		t.Error("no findings should print nothing")
	}
	got := FormatStapleFindings([]RevocationFinding{{Problem: ProblemStaleStaple, Subject: "staple.test", Detail: "why"}})
	if !strings.HasPrefix(got, "Stapled OCSP response:\n") || !strings.Contains(got, "• stale staple: staple.test") {
		t.Errorf("unexpected text:\n%s", got)
	}
}
