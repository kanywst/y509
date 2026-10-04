package certificate

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

// pqcAlgorithmNames names the post-quantum signature OIDs crypto/x509 does not
// decode. ML-DSA is not here: Go 1.27 names it, as x509.MLDSA44 and friends.
//
// The SLH-DSA OIDs are NIST's (CSOR, id-slh-dsa-*), as RFC 9909 uses them for
// X.509. Composite ML-DSA is left out until its OIDs leave draft: naming a
// draft OID would label a certificate with what the draft said that month.
var pqcAlgorithmNames = map[string]string{
	"2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
	"2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
	"2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
	"2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
	"2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
	"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
	"2.16.840.1.101.3.4.3.26": "SLH-DSA-SHAKE-128s",
	"2.16.840.1.101.3.4.3.27": "SLH-DSA-SHAKE-128f",
	"2.16.840.1.101.3.4.3.28": "SLH-DSA-SHAKE-192s",
	"2.16.840.1.101.3.4.3.29": "SLH-DSA-SHAKE-192f",
	"2.16.840.1.101.3.4.3.30": "SLH-DSA-SHAKE-256s",
	"2.16.840.1.101.3.4.3.31": "SLH-DSA-SHAKE-256f",
}

// SignatureAlgorithmName names the algorithm the certificate was signed with.
//
// crypto/x509 prints an algorithm it does not know as "0", which says nothing.
// For those this reads the AlgorithmIdentifier itself (RawSignatureAlgorithm,
// Go 1.27) and names it, or at least gives its OID.
func SignatureAlgorithmName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		return cert.SignatureAlgorithm.String()
	}
	return nameAlgorithmIdentifier(cert.RawSignatureAlgorithm)
}

// PublicKeyAlgorithmName names the subject public key's algorithm, reading the
// SubjectPublicKeyInfo when crypto/x509 does not know it.
func PublicKeyAlgorithmName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		return cert.PublicKeyAlgorithm.String()
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return "unknown"
	}
	return nameOID(spki.Algorithm.Algorithm)
}

// nameAlgorithmIdentifier names a DER AlgorithmIdentifier by its OID.
func nameAlgorithmIdentifier(der []byte) string {
	var ai pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(der, &ai); err != nil {
		return "unknown"
	}
	return nameOID(ai.Algorithm)
}

func nameOID(oid asn1.ObjectIdentifier) string {
	if name, ok := pqcAlgorithmNames[oid.String()]; ok {
		return name
	}
	return fmt.Sprintf("unknown (OID %s)", oid)
}
