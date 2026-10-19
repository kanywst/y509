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
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "ACE to Unicode", in: "xn--r8jz45g.jp", want: "例え.jp"},
		{name: "uppercase ACE", in: "XN--R8JZ45G.JP", want: "例え.JP"},
		{name: "wildcard", in: "*.xn--r8jz45g.jp", want: "*.例え.jp"},
		{name: "underscore elsewhere", in: "_acme.xn--r8jz45g.jp", want: "_acme.例え.jp"},
		{name: "homograph", in: "xn--80ak6aa92e.com", want: "аррӏе.com"},
		{name: "Unicode to ACE", in: "例え.jp", want: "xn--r8jz45g.jp"},
		{name: "Unicode wildcard to ACE", in: "*.例え.jp", want: "*.xn--r8jz45g.jp"},
		{name: "Unicode with an underscore elsewhere", in: "_acme.例え.jp", want: "_acme.xn--r8jz45g.jp"},
		{name: "plain ASCII", in: "example.com"},
		{name: "not a hostname", in: "Acme 株式会社"},
		{name: "empty", in: ""},
		{name: "bad punycode", in: "xn--zz.com", wantErr: true},
		{name: "decodes to a C1 control", in: "xn--a.com", wantErr: true},
		{name: "empty A-label", in: "xn--.com", wantErr: true},
		{name: "Unicode hostname with a control character", in: "例え\a.jp", wantErr: true},
		{name: "Unicode hostname breaking the bidi rule", in: "1مثال.com", wantErr: true},
		{name: "Unicode without a dot", in: "株式会社テスト"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IDNForm(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IDNForm(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("IDNForm(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestWithIDNFormLabelsAnInvalidName(t *testing.T) {
	if got := WithIDNForm("xn--zz.com"); got != "xn--zz.com (invalid IDN)" {
		t.Errorf("WithIDNForm = %q", got)
	}
}

func TestIDNsListsEachNameOnce(t *testing.T) {
	cert := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "1مثال.com"},
		DNSNames: []string{"xn--r8jz45g.jp", "example.com", "*.xn--r8jz45g.jp", "xn--zz.com", "XN--R8JZ45G.jp"},
	}
	got := IDNs(cert)
	want := []IDNPair{
		{Unicode: "1مثال.com", Error: `idna: invalid label "1مثال"`},
		{ASCII: "xn--r8jz45g.jp", Unicode: "例え.jp"},
		{ASCII: "*.xn--r8jz45g.jp", Unicode: "*.例え.jp"},
		{ASCII: "xn--zz.com", Error: `idna: invalid label "zz"`},
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
