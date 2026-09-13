package certificate

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestExpiryWarningDaysFor(t *testing.T) {
	cert := func(lifetimeDays int) *x509.Certificate {
		now := time.Now()
		return &x509.Certificate{
			NotBefore: now,
			NotAfter:  now.Add(time.Duration(lifetimeDays) * 24 * time.Hour),
		}
	}

	tests := []struct {
		name       string
		cert       *x509.Certificate
		configured int
		want       int
	}{
		{
			// The shape the fixed window was written for: a third of 90 days
			// is exactly the default, so nothing moves for a Let's Encrypt
			// certificate of the current default lifetime.
			name: "a 90-day certificate keeps the 30-day window",
			cert: cert(90), configured: 30, want: 30,
		},
		{
			// The case the fixed window breaks on: a 6-day certificate is
			// inside a 30-day window from the moment it is issued.
			name: "a 6-day certificate gets two days",
			cert: cert(6), configured: 30, want: 2,
		},
		{
			name: "a 47-day certificate, the 2029 maximum",
			cert: cert(47), configured: 30, want: 16,
		},
		{
			// The ceiling still applies: a third of a ten-year CA is three
			// years of warning, which is no warning at all in the other
			// direction.
			name: "a ten-year certificate keeps the ceiling",
			cert: cert(3650), configured: 30, want: 30,
		},
		{
			name: "a one-day certificate still gets a window",
			cert: cert(1), configured: 30, want: 1,
		},
		{
			name: "a configured ceiling below the share wins",
			cert: cert(365), configured: 7, want: 7,
		},
		{
			name: "a non-positive ceiling falls back to the default",
			cert: cert(365), configured: 0, want: defaultExpiryWarningDays,
		},
		{
			name: "no certificate keeps the configured ceiling",
			cert: nil, configured: 14, want: 14,
		},
		{
			// NotAfter before NotBefore says nothing about a sensible window.
			name:       "a malformed validity period keeps the ceiling",
			cert:       &x509.Certificate{NotBefore: time.Now(), NotAfter: time.Now().Add(-time.Hour)},
			configured: 30, want: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExpiryWarningDaysFor(tt.cert, tt.configured); got != tt.want {
				t.Errorf("ExpiryWarningDaysFor() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestShortLivedCertificatesAreNotBornExpiring is the behaviour the derived
// window exists for. Let's Encrypt's 6-day certificate has been generally
// available since January 2026, and against a fixed 30-day window every one of
// them warns from the moment it is issued -- which is the same as no warning.
func TestShortLivedCertificatesAreNotBornExpiring(t *testing.T) {
	now := time.Now()
	fresh := &x509.Certificate{
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(6*24*time.Hour - time.Hour),
	}

	if IsExpiringSoonWithin(fresh, 30) {
		t.Error("a freshly issued 6-day certificate is reported as expiring soon")
	}

	// It still warns once it is genuinely near the end of its own life.
	nearlyDone := &x509.Certificate{
		NotBefore: now.Add(-5 * 24 * time.Hour),
		NotAfter:  now.Add(24 * time.Hour),
	}
	if !IsExpiringSoonWithin(nearlyDone, 30) {
		t.Error("a 6-day certificate with one day left is not reported as expiring soon")
	}
}
