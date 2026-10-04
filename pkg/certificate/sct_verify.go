package certificate

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// RFC 5246 hash and signature algorithm numbers an SCT can carry. RFC 6962
// logs use SHA-256 with ECDSA or RSA.
const (
	sctHashSHA256 = 4
	sctSigRSA     = 1
	sctSigECDSA   = 3
)

// VerifySCT checks an SCT's signature against its log's key.
//
// An embedded SCT signs the precertificate: the leaf's TBSCertificate with the
// SCT list removed, plus a hash of the issuer's key, so issuer is required. An
// SCT delivered in the TLS extension signs the certificate itself.
func VerifySCT(sct SCT, leaf, issuer *x509.Certificate, embedded bool) error {
	if sct.Log == nil || sct.Log.Key == "" {
		return errors.New("the log is not in the bundled list")
	}
	if leaf == nil {
		return errors.New("no certificate to check against")
	}
	der, err := base64.StdEncoding.DecodeString(sct.Log.Key)
	if err != nil {
		return fmt.Errorf("the bundled key for %s is not base64: %w", sct.Name(), err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return fmt.Errorf("the bundled key for %s does not parse: %w", sct.Name(), err)
	}

	var b cryptobyte.Builder
	b.AddUint8(0) // sct_version v1
	b.AddUint8(0) // signature_type certificate_timestamp
	b.AddUint64(sct.timestampMS)
	if embedded {
		if issuer == nil {
			return errors.New("an embedded SCT needs the issuer to check")
		}
		tbs, err := tbsWithoutSCTList(leaf.RawTBSCertificate)
		if err != nil {
			return err
		}
		issuerKeyHash := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		b.AddUint16(1) // precert_entry
		b.AddBytes(issuerKeyHash[:])
		b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(tbs) })
	} else {
		b.AddUint16(0) // x509_entry
		b.AddUint24LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(leaf.Raw) })
	}
	b.AddUint16LengthPrefixed(func(c *cryptobyte.Builder) { c.AddBytes(sct.extensions) })
	signed, err := b.Bytes()
	if err != nil {
		return err
	}

	if sct.hashAlg != sctHashSHA256 {
		return fmt.Errorf("SCT hash algorithm %d is not SHA-256", sct.hashAlg)
	}
	digest := sha256.Sum256(signed)
	switch pub := key.(type) {
	case *ecdsa.PublicKey:
		if sct.sigAlg != sctSigECDSA {
			return errors.New("SCT signature algorithm does not match the log's ECDSA key")
		}
		if !ecdsa.VerifyASN1(pub, digest[:], sct.signature) {
			return errors.New("SCT signature does not verify")
		}
	case *rsa.PublicKey:
		if sct.sigAlg != sctSigRSA {
			return errors.New("SCT signature algorithm does not match the log's RSA key")
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sct.signature); err != nil {
			return errors.New("SCT signature does not verify")
		}
	default:
		return fmt.Errorf("the log's key is a %T, which RFC 6962 does not use", key)
	}
	return nil
}

// tbsWithoutSCTList re-encodes a TBSCertificate with the SCT list extension
// removed, which is what the log signed for an embedded SCT (RFC 6962 section
// 3.2: the precertificate's TBS is the final one without that extension).
func tbsWithoutSCTList(raw []byte) ([]byte, error) {
	input := cryptobyte.String(raw)
	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cbasn1.SEQUENCE) || !input.Empty() {
		return nil, errors.New("TBSCertificate does not parse")
	}

	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(out *cryptobyte.Builder) {
		for !tbs.Empty() {
			var element cryptobyte.String
			var tag cbasn1.Tag
			if !tbs.ReadAnyASN1Element(&element, &tag) {
				out.SetError(errors.New("TBSCertificate field does not parse"))
				return
			}
			if tag != cbasn1.Tag(3).Constructed().ContextSpecific() {
				out.AddBytes(element)
				continue
			}
			// [3] EXPLICIT Extensions: keep every extension but the SCT list.
			var explicit, extensions cryptobyte.String
			if !element.ReadASN1(&explicit, tag) || !explicit.ReadASN1(&extensions, cbasn1.SEQUENCE) {
				out.SetError(errors.New("extensions do not parse"))
				return
			}
			out.AddASN1(tag, func(e *cryptobyte.Builder) {
				e.AddASN1(cbasn1.SEQUENCE, func(list *cryptobyte.Builder) {
					for !extensions.Empty() {
						var ext, inner cryptobyte.String
						var oid asn1.ObjectIdentifier
						if !extensions.ReadASN1Element(&ext, cbasn1.SEQUENCE) {
							list.SetError(errors.New("extension does not parse"))
							return
						}
						body := ext
						if !body.ReadASN1(&inner, cbasn1.SEQUENCE) || !inner.ReadASN1ObjectIdentifier(&oid) {
							list.SetError(errors.New("extension does not parse"))
							return
						}
						if oid.Equal(oidSCTList) {
							continue
						}
						list.AddBytes(ext)
					}
				})
			})
		}
	})
	return b.Bytes()
}
