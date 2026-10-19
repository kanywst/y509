package certificate

import (
	"crypto/x509"
	"strings"

	"golang.org/x/net/idna"
)

// IDNForm returns the other spelling of an internationalized domain name: the
// Unicode form of a name with an xn-- label, or the xn-- form of one written
// in Unicode. It returns "" when there is none: plain ASCII, a common name
// that is not a hostname, or a label that does not decode.
//
// The Lookup profile rejects control characters, so a hostile label cannot
// decode to an escape sequence on the terminal.
func IDNForm(name string) string {
	// The profile rejects "*", so a wildcard is converted without it.
	prefix, host := "", name
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		prefix, host = "*.", rest
	}
	if host == "" {
		return ""
	}

	if isASCII(host) {
		if !hasACELabel(host) {
			return ""
		}
		u, err := idna.Lookup.ToUnicode(host)
		if err != nil || u == strings.ToLower(host) {
			return ""
		}
		return prefix + u
	}

	a, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return ""
	}
	return prefix + a
}

// WithIDNForm is name followed by its other spelling in parentheses, or name
// alone when it has none.
func WithIDNForm(name string) string {
	if alt := IDNForm(name); alt != "" {
		return name + " (" + alt + ")"
	}
	return name
}

// IDNPair is one internationalized name in both spellings.
type IDNPair struct {
	ASCII   string
	Unicode string
}

// IDNs lists the subject common name and dNSName SANs that are
// internationalized, each once, in the order the certificate carries them.
func IDNs(cert *x509.Certificate) []IDNPair {
	var out []IDNPair
	seen := map[string]bool{}
	names := append([]string{cert.Subject.CommonName}, cert.DNSNames...)
	for _, name := range names {
		alt := IDNForm(name)
		if alt == "" {
			continue
		}
		p := IDNPair{ASCII: name, Unicode: alt}
		if !isASCII(name) {
			p = IDNPair{ASCII: alt, Unicode: name}
		}
		key := strings.ToLower(p.ASCII)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

func hasACELabel(host string) bool {
	for label := range strings.SplitSeq(host, ".") {
		if len(label) >= 4 && strings.EqualFold(label[:4], "xn--") {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
