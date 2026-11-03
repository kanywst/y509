package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func pointerCert(mod func(*x509.Certificate)) *x509.Certificate {
	nb := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	cert := conformanceCert(func(c *x509.Certificate) {
		c.NotBefore = nb
		c.NotAfter = nb.AddDate(0, 0, 90)
		c.IssuingCertificateURL = []string{"http://ca.test/int.der"}
		c.CRLDistributionPoints = []string{"http://ca.test/int.crl"}
	})
	if mod != nil {
		mod(cert)
	}
	return cert
}

func advisoryProblems(advisories []Advisory) string {
	out := make([]string, 0, len(advisories))
	for _, a := range advisories {
		out = append(out, a.Problem)
	}
	return strings.Join(out, ",")
}

func TestRevocationPointerAdvisories(t *testing.T) {
	sevenDaysFrom := func(c *x509.Certificate, nb time.Time, extra time.Duration) {
		c.CRLDistributionPoints = nil
		c.NotBefore = nb
		c.NotAfter = nb.Add(7*24*time.Hour - time.Second + extra)
	}
	tests := []struct {
		name string
		mod  func(*x509.Certificate)
		want string
	}{
		{"clean", nil, ""},
		{"no AIA", func(c *x509.Certificate) { c.IssuingCertificateURL = nil }, ProblemNoAIA},
		{"no CRL, no OCSP", func(c *x509.Certificate) { c.CRLDistributionPoints = nil }, ProblemNoCRL},
		{"no CRL but OCSP", func(c *x509.Certificate) {
			c.CRLDistributionPoints = nil
			c.OCSPServer = []string{"http://ocsp.ca.test"}
		}, ""},
		{"no OCSP alone is never a finding", func(c *x509.Certificate) { c.OCSPServer = nil }, ""},
		{"neither", func(c *x509.Certificate) {
			c.IssuingCertificateURL = nil
			c.CRLDistributionPoints = nil
		}, ProblemNoAIA + "," + ProblemNoCRL},
		// 7 days inclusive of both ends is exactly the limit from 2026-03-15.
		{"short-lived at the 7-day limit", func(c *x509.Certificate) {
			sevenDaysFrom(c, time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC), 0)
		}, ""},
		{"one second over 7 days", func(c *x509.Certificate) {
			sevenDaysFrom(c, time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC), time.Second)
		}, ProblemNoCRL},
		// Before 2026-03-15 the limit was 10 days.
		{"9 days issued in 2025", func(c *x509.Certificate) {
			sevenDaysFrom(c, time.Date(2025, time.June, 1, 0, 0, 0, 0, time.UTC), 2*24*time.Hour)
		}, ""},
		{"8 days issued at the 7-day cutover", func(c *x509.Certificate) {
			sevenDaysFrom(c, time.Date(2026, time.March, 15, 0, 0, 0, 0, time.UTC), 24*time.Hour)
		}, ProblemNoCRL},
		{"8 days issued a second before the cutover", func(c *x509.Certificate) {
			sevenDaysFrom(c, time.Date(2026, time.March, 14, 23, 59, 59, 0, time.UTC), 24*time.Hour)
		}, ""},
		{"10 days issued in 2025", func(c *x509.Certificate) {
			sevenDaysFrom(c, time.Date(2025, time.June, 1, 0, 0, 0, 0, time.UTC), 3*24*time.Hour)
		}, ""},
		{"one second over 10 days in 2025", func(c *x509.Certificate) {
			sevenDaysFrom(c, time.Date(2025, time.June, 1, 0, 0, 0, 0, time.UTC), 3*24*time.Hour+time.Second)
		}, ProblemNoCRL},
		{"short-lived exemption is for subscribers only", func(c *x509.Certificate) {
			sevenDaysFrom(c, time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC), 0)
			c.IsCA = true
		}, ProblemNoCRL},
		{"far-future NotAfter", func(c *x509.Certificate) {
			c.CRLDistributionPoints = nil
			c.NotAfter = time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
		}, ProblemNoCRL},
		{"self-issued is skipped", func(c *x509.Certificate) {
			c.Issuer = c.Subject
			c.IssuingCertificateURL = nil
			c.CRLDistributionPoints = nil
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := advisoryProblems(RevocationPointerAdvisories([]*x509.Certificate{pointerCert(tt.mod)}))
			if got != tt.want {
				t.Errorf("problems = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRevocationPointerAdvisoriesSkipsNil(t *testing.T) {
	if got := RevocationPointerAdvisories([]*x509.Certificate{nil}); len(got) != 0 {
		t.Errorf("got %v, want none", got)
	}
}

func TestFormatAdvisories(t *testing.T) {
	if got := FormatAdvisories(nil); got != "" {
		t.Errorf("empty: got %q", got)
	}
	cert := pointerCert(func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: "svc.internal"}
		c.CRLDistributionPoints = nil
	})
	got := FormatAdvisories(RevocationPointerAdvisories([]*x509.Certificate{cert}))
	for _, want := range []string{"Advisories", "no CRL pointer: svc.internal"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// Advisories must always marshal as an array, and must not touch any ok.
func TestJSONAdvisories(t *testing.T) {
	cert := pointerCert(func(c *x509.Certificate) { c.IssuingCertificateURL = nil })
	report := NewJSONReport("", AnalyzeChain([]*x509.Certificate{cert}), nil)
	if len(report.Advisories) != 1 || report.Advisories[0].Problem != ProblemNoAIA {
		t.Fatalf("advisories = %+v", report.Advisories)
	}
	if !report.Conformance.OK {
		t.Error("an advisory changed conformance.ok")
	}

	raw, err := json.Marshal(NewJSONReport("", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"advisories":[]`) {
		t.Errorf("empty advisories not an array: %s", raw)
	}

	inspection := NewJSONInspection("", AnalyzeChain([]*x509.Certificate{cert}))
	if len(inspection.Advisories) != 1 {
		t.Errorf("inspection advisories = %+v", inspection.Advisories)
	}
}
