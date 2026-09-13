package certificate

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// This file reads the two containers people most often have a chain inside but
// cannot hand to a tool that only understands PEM and DER: a PKCS#7 bundle, and
// a Kubernetes TLS secret.
//
// Both stay within the "no second certificate parser" line: each one is opened
// far enough to find the certificates, which are then handed to
// crypto/x509 exactly as a PEM block would be.

var (
	// oidSignedData is the PKCS#7 signedData content type.
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// pkcs7ContentInfo is the outer PKCS#7 wrapper.
type pkcs7ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// parsePKCS7 extracts the certificates from a PKCS#7 bundle -- a .p7b or .p7c,
// which is what Windows and several CAs hand out when asked for a chain.
//
// The certificates come back in the order the bundle carries them, which for
// this format is not necessarily leaf-first and is exactly the evidence the
// rest of the tool reads.
func parsePKCS7(data []byte) ([]*Info, error) {
	var outer pkcs7ContentInfo
	if _, err := asn1.Unmarshal(data, &outer); err != nil {
		return nil, fmt.Errorf("not a PKCS#7 container: %w", err)
	}
	if !outer.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("PKCS#7 container holds %s, not signed data", outer.ContentType)
	}

	if len(outer.Content.Bytes) == 0 {
		return nil, fmt.Errorf("PKCS#7 container carries no content")
	}

	// Bytes, not FullBytes: the field is explicitly tagged, so FullBytes is
	// the [0] wrapper and Bytes is the SignedData SEQUENCE inside it.
	raw, err := pkcs7Certificates(outer.Content.Bytes)
	if err != nil {
		return nil, err
	}

	// The certificates field is a SET OF Certificate, whose contents are the
	// DER certificates one after another -- which is what ParseCertificates
	// reads.
	certs, err := x509.ParseCertificates(raw)
	if err != nil {
		return nil, fmt.Errorf("PKCS#7 certificates did not parse: %w", err)
	}

	return wrapCertificates(certs), nil
}

// pkcs7Certificates finds the certificates field inside a SignedData.
//
// It walks the SEQUENCE rather than unmarshalling into a struct, because a
// struct has to name every field before the one it wants and get each of their
// types right. SignedData carries several this code has no use for -- the
// digest algorithms, the content, the CRLs, the signers -- and a container that
// encodes any of them a little differently would then fail for a reason that
// has nothing to do with the certificates. The certificates are the [0]
// constructed element; that is the only thing worth asserting.
func pkcs7Certificates(der []byte) ([]byte, error) {
	var seq asn1.RawValue
	if _, err := asn1.Unmarshal(der, &seq); err != nil {
		return nil, fmt.Errorf("PKCS#7 signed data did not parse: %w", err)
	}
	if !seq.IsCompound || seq.Class != asn1.ClassUniversal || seq.Tag != asn1.TagSequence {
		return nil, fmt.Errorf("PKCS#7 signed data is not a sequence")
	}

	rest := seq.Bytes
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, fmt.Errorf("PKCS#7 signed data did not parse: %w", err)
		}
		if field.Class == asn1.ClassContextSpecific && field.Tag == 0 && field.IsCompound {
			if len(field.Bytes) == 0 {
				break
			}
			return field.Bytes, nil
		}
	}

	return nil, fmt.Errorf("PKCS#7 container carries no certificates")
}

// k8sSecret is the shape of `kubectl get secret -o json` that matters here.
type k8sSecret struct {
	Kind string            `json:"kind"`
	Type string            `json:"type"`
	Data map[string]string `json:"data"`
}

// k8sCertificateKeys are the keys a TLS secret keeps certificates under, in the
// order they should be read: the served chain first, then the CA bundle, so a
// secret carrying both lists the leaf first.
var k8sCertificateKeys = []string{"tls.crt", "ca.crt"}

// parseKubernetesSecret extracts the certificates from a Kubernetes TLS secret
// as `kubectl get secret -o json` prints it.
//
// This is the shape people actually have: a chain inside a base64 field inside
// JSON, which otherwise takes a jq and a base64 to get at before y509 can see
// it at all.
func parseKubernetesSecret(data []byte) ([]*Info, error) {
	var secret k8sSecret
	if err := json.Unmarshal(data, &secret); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	if secret.Kind != "" && secret.Kind != "Secret" {
		return nil, fmt.Errorf("JSON input is a %s, not a Secret", secret.Kind)
	}
	if len(secret.Data) == 0 {
		return nil, fmt.Errorf("secret carries no data")
	}

	var pemData []byte
	for _, key := range k8sCertificateKeys {
		encoded, ok := secret.Data[key]
		if !ok {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("secret key %q is not base64: %w", key, err)
		}
		pemData = append(pemData, decoded...)
	}

	if len(pemData) == 0 {
		return nil, fmt.Errorf("secret carries no %v", k8sCertificateKeys)
	}

	certs, _, sawPEM := parsePEMCertificates(pemData)
	if len(certs) == 0 {
		if sawPEM {
			return nil, fmt.Errorf("secret holds PEM data with no CERTIFICATE blocks")
		}
		return nil, fmt.Errorf("secret holds no certificates")
	}
	return certs, nil
}

// wrapCertificates attaches the metadata the rest of the package expects.
func wrapCertificates(certs []*x509.Certificate) []*Info {
	out := make([]*Info, len(certs))
	for i, cert := range certs {
		out[i] = &Info{
			Certificate: cert,
			Index:       i,
			Label:       generateCertificateLabel(cert, i),
		}
	}
	return out
}
