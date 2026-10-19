package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/net/idna"
)

// IDNForm returns the other spelling of an internationalized domain name: the
// Unicode form of a name with an xn-- label, or the xn-- form of one written
// in Unicode. It returns "" when there is none: plain ASCII, or a common name
// that is not a hostname. It returns an error for a name that is an IDN but
// fails IDNA validation, which is worth showing rather than passing over.
//
// The Lookup profile rejects control characters, so a hostile label cannot
// decode to an escape sequence on the terminal.
func IDNForm(name string) (string, error) {
	convert := idna.Lookup.ToUnicode
	if isASCII(name) {
		if !hasACELabel(name) {
			return "", nil
		}
	} else {
		// A common name like "Acme 株式会社" is not a hostname and has no
		// other spelling. One that looks like a hostname and fails is reported.
		if !strings.Contains(name, ".") || strings.ContainsFunc(name, unicode.IsSpace) {
			return "", nil
		}
		convert = idna.Lookup.ToASCII
	}

	// Label by label, so a wildcard or an underscore elsewhere in the name,
	// which the profile rejects, gets the same verdict in either spelling.
	labels := strings.Split(name, ".")
	for i, label := range labels {
		if isASCII(label) && !isACELabel(label) {
			continue
		}
		out, err := convert(label)
		if err == nil && out == "" {
			err = fmt.Errorf("idna: invalid label %q", label)
		}
		if err != nil {
			return "", err
		}
		labels[i] = out
	}
	return strings.Join(labels, "."), nil
}

// WithIDNForm is name followed by its other spelling in parentheses, or by
// "invalid IDN" when it fails IDNA validation.
func WithIDNForm(name string) string {
	alt, err := IDNForm(name)
	switch {
	case err != nil:
		return name + " (invalid IDN)"
	case alt != "":
		return name + " (" + alt + ")"
	}
	return name
}

// IDNPair is one internationalized name in both spellings. For one that fails
// IDNA validation, only the spelling the certificate carries is set and Error
// says why.
type IDNPair struct {
	ASCII   string
	Unicode string
	Error   string
}

// IDNs lists the subject common name and dNSName SANs that are
// internationalized, each once, in the order the certificate carries them.
func IDNs(cert *x509.Certificate) []IDNPair {
	var out []IDNPair
	seen := map[string]bool{}
	names := append([]string{cert.Subject.CommonName}, cert.DNSNames...)
	for _, name := range names {
		alt, err := IDNForm(name)
		var p IDNPair
		switch {
		case err != nil && isASCII(name):
			p = IDNPair{ASCII: name, Error: err.Error()}
		case err != nil:
			p = IDNPair{Unicode: name, Error: err.Error()}
		case alt == "":
			continue
		case isASCII(name):
			p = IDNPair{ASCII: name, Unicode: alt}
		default:
			p = IDNPair{ASCII: alt, Unicode: name}
		}
		key := strings.ToLower(p.ASCII + "\x00" + p.Unicode)
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
		if isACELabel(label) {
			return true
		}
	}
	return false
}

func isACELabel(label string) bool {
	return len(label) >= 4 && strings.EqualFold(label[:4], "xn--")
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
