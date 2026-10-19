package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"
)

func TestIDNForm(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"ACE to Unicode", "xn--r8jz45g.jp", "例え.jp"},
		{"uppercase ACE", "XN--R8JZ45G.JP", "例え.jp"},
		{"wildcard", "*.xn--r8jz45g.jp", "*.例え.jp"},
		{"homograph", "xn--80ak6aa92e.com", "аррӏе.com"},
		{"Unicode to ACE", "例え.jp", "xn--r8jz45g.jp"},
		{"plain ASCII", "example.com", ""},
		{"undecodable label", "xn--zz.com", ""},
		{"not a hostname", "Acme 株式会社", ""},
		{"empty", "", ""},
		{"bare wildcard", "*.", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IDNForm(tt.in); got != tt.want {
				t.Errorf("IDNForm(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestIDNsListsEachNameOnce(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "例え.jp"},
		DNSNames: []string{"xn--r8jz45g.jp", "example.com", "*.xn--r8jz45g.jp"},
	}
	got := IDNs(cert)
	want := []IDNPair{
		{ASCII: "xn--r8jz45g.jp", Unicode: "例え.jp"},
		{ASCII: "*.xn--r8jz45g.jp", Unicode: "*.例え.jp"},
	}
	if len(got) != len(want) {
		t.Fatalf("IDNs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("IDNs[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestIDNsReachTheSANTextAndJSON(t *testing.T) {
	cert := &x509.Certificate{DNSNames: []string{"xn--r8jz45g.jp"}}

	if san := FormatSAN(cert); !strings.Contains(san, "xn--r8jz45g.jp (例え.jp)") {
		t.Errorf("FormatSAN does not show the Unicode form:\n%s", san)
	}

	entry := newJSONCertificate(0, cert, time.Now())
	if len(entry.IDNs) != 1 || entry.IDNs[0] != (JSONIDN{ASCII: "xn--r8jz45g.jp", Unicode: "例え.jp"}) {
		t.Errorf("idns = %v", entry.IDNs)
	}
}
