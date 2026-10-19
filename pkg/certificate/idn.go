package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// IDNForm returns the other spelling of an internationalized domain name: the
// Unicode form of a name with an xn-- label, or the xn-- form of one written
// in Unicode. It returns "" when there is none: plain ASCII, or a common name
// that is not a hostname. It returns an error for an xn-- label that does not
// decode, which is worth showing rather than passing over.
//
// The Lookup profile rejects control characters, so a hostile label cannot
// decode to an escape sequence on the terminal.
func IDNForm(name string) (string, error) {
	if isASCII(name) {
		if !hasACELabel(name) {
			return "", nil
		}
		// Label by label, so an underscore or a wildcard elsewhere in the
		// name, which the profile rejects, does not stop the xn-- labels.
		labels := strings.Split(name, ".")
		for i, label := range labels {
			if !isACELabel(label) {
				continue
			}
			u, err := idna.Lookup.ToUnicode(label)
			if err == nil && u == "" {
				err = fmt.Errorf("idna: invalid label %q", label)
			}
			if err != nil {
				return "", err
			}
			labels[i] = u
		}
		return strings.Join(labels, "."), nil
	}

	// The profile rejects "*", so a wildcard is converted without it.
	prefix, host := "", name
	if rest, ok := strings.CutPrefix(name, "*."); ok {
		prefix, host = "*.", rest
	}
	a, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return "", nil
	}
	return prefix + a, nil
}

// WithIDNForm is name followed by its other spelling in parentheses, or by
// "undecodable IDN" when an xn-- label does not decode.
func WithIDNForm(name string) string {
	alt, err := IDNForm(name)
	switch {
	case err != nil:
		return name + " (undecodable IDN)"
	case alt != "":
		return name + " (" + alt + ")"
	}
	return name
}

// IDNPair is one internationalized name in both spellings. For an xn-- name
// that does not decode, Unicode is empty and Error says why.
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
		case err != nil:
			p = IDNPair{ASCII: name, Error: err.Error()}
		case alt == "":
			continue
		case isASCII(name):
			p = IDNPair{ASCII: name, Unicode: alt}
		default:
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
