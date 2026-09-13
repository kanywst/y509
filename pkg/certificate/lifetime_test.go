package certificate

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestCABMaxValidityDaysAt(t *testing.T) {
	day := func(y int, m time.Month, d int) time.Time {
		return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
	}

	tests := []struct {
		name   string
		issued time.Time
		want   int
	}{
		{"before the glidepath", day(2025, time.June, 1), 398},
		{"the day before the first step", day(2026, time.March, 14), 398},
		{"the day the first step lands", day(2026, time.March, 15), 200},
		{"inside the 200-day tranche", day(2026, time.September, 13), 200},
		{"the day before the second step", day(2027, time.March, 14), 200},
		{"the day the second step lands", day(2027, time.March, 15), 100},
		{"the day before the third step", day(2029, time.March, 14), 100},
		{"the day the third step lands", day(2029, time.March, 15), 47},
		{"well past the schedule", day(2035, time.January, 1), 47},
		// A zero time is what an unparsed or absent NotBefore looks like; the
		// oldest, most permissive limit is the safe answer, since the
		// alternative is flagging a certificate on no evidence.
		{"the zero time", time.Time{}, 398},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CABMaxValidityDaysAt(tt.issued); got != tt.want {
				t.Errorf("CABMaxValidityDaysAt(%s) = %d, want %d", tt.issued.Format(time.DateOnly), got, tt.want)
			}
		})
	}
}

// TestExceedsCABMaxLifetimeUsesTheLimitAtIssuance is the point of the schedule:
// the limit that governs a certificate is the one in force when it was issued,
// so a compliant certificate must not turn non-compliant when the next step
// lands.
func TestExceedsCABMaxLifetimeUsesTheLimitAtIssuance(t *testing.T) {
	issued := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)

	// 150 days, inside the 200-day limit that applied in June 2026 and outside
	// the 100-day limit that applies from March 2027.
	compliant := &x509.Certificate{
		NotBefore: issued,
		NotAfter:  issued.Add(150 * 24 * time.Hour),
	}
	if ExceedsCABMaxLifetime(compliant) {
		t.Error("a 150-day certificate issued in June 2026 was flagged; the limit then was 200 days")
	}

	// The same lifetime issued after the next step is over the line.
	later := time.Date(2027, time.June, 1, 0, 0, 0, 0, time.UTC)
	nonCompliant := &x509.Certificate{
		NotBefore: later,
		NotAfter:  later.Add(150 * 24 * time.Hour),
	}
	if !ExceedsCABMaxLifetime(nonCompliant) {
		t.Error("a 150-day certificate issued in June 2027 was not flagged; the limit then was 100 days")
	}

	if got := CABMaxLifetimeFor(nonCompliant); got != 100 {
		t.Errorf("CABMaxLifetimeFor = %d, want the 100 days in force at issuance", got)
	}
}

func TestExceedsCABMaxLifetimeExemptsCAs(t *testing.T) {
	issued := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{
		NotBefore: issued,
		NotAfter:  issued.Add(3650 * 24 * time.Hour),
		IsCA:      true,
	}

	if ExceedsCABMaxLifetime(ca) {
		t.Error("a ten-year CA certificate was flagged; the subscriber limit does not apply to CAs")
	}
	// And the helper says the limit does not cover it, rather than quoting a
	// number that was never applied.
	if got := CABMaxLifetimeFor(ca); got != 0 {
		t.Errorf("CABMaxLifetimeFor(CA) = %d, want 0", got)
	}
	if got := CABMaxLifetimeFor(nil); got != 0 {
		t.Errorf("CABMaxLifetimeFor(nil) = %d, want 0", got)
	}
}
