package certificate

import (
	"crypto/x509"
	"fmt"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// ErrPKCS12Password reports a PKCS#12 file that needs a password, or was given
// the wrong one.
//
// It is a distinct error because the caller has to be able to tell "this needs
// a password" from "this is not a PKCS#12 file" -- only the first is worth
// asking the user about.
var ErrPKCS12Password = fmt.Errorf("pkcs12: incorrect password")

// ParsePKCS12 extracts the certificates from a PKCS#12 file, which is what a
// Windows export and most client-certificate bundles are.
//
// Only the certificates come back. A .p12 usually carries a private key too,
// and y509 has no use for one: reading it would mean holding key material in a
// process that exists to print things on a terminal.
func ParsePKCS12(data []byte, password string) ([]*Info, error) {
	// DecodeChain returns the leaf and the CA certificates separately, which is
	// what the file itself distinguishes, and in that order -- leaf first,
	// which is the order everything downstream expects.
	_, leaf, cas, err := pkcs12.DecodeChain(data, password)
	if err == nil {
		certs := make([]*x509.Certificate, 0, 1+len(cas))
		if leaf != nil {
			certs = append(certs, leaf)
		}
		certs = append(certs, cas...)
		return pkcs12Infos(certs)
	}

	// A truststore holds CA certificates and no key, which DecodeChain refuses.
	// Try it before giving up, or every CA bundle in this format would be
	// reported as a broken file.
	if trust, trustErr := pkcs12.DecodeTrustStore(data, password); trustErr == nil {
		return pkcs12Infos(trust)
	}

	if isPKCS12PasswordError(err) {
		return nil, ErrPKCS12Password
	}
	return nil, fmt.Errorf("not a PKCS#12 container: %w", err)
}

// isPKCS12PasswordError reports whether the failure was the password rather
// than the format. The library returns a sentinel for this, which is the only
// reliable way to tell the two apart.
func isPKCS12PasswordError(err error) bool {
	return err == pkcs12.ErrIncorrectPassword
}

func pkcs12Infos(certs []*x509.Certificate) ([]*Info, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("PKCS#12 container carries no certificates")
	}

	out := make([]*Info, len(certs))
	for i, cert := range certs {
		out[i] = &Info{
			Certificate: cert,
			Index:       i,
			Label:       generateCertificateLabel(cert, i),
		}
	}
	return out, nil
}
