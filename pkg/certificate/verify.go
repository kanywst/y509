package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// TrustLevel says how far a chain could actually be verified.
//
// The distinction matters because a bundle that links up is not the same thing
// as a bundle a client would accept: an internal PKI chain and a public one are
// both "internally consistent", but only one of them terminates at a root the
// operating system trusts. Collapsing the two into a single boolean is what let
// y509 report a lone self-signed certificate as a valid chain.
type TrustLevel int

const (
	// TrustBroken means the chain does not link up: a certificate is expired, a
	// signature does not verify, or an issuer is missing entirely.
	TrustBroken TrustLevel = iota
	// TrustSelfAnchored means the chain links up to a root supplied in the
	// input itself, but that root is not a trust anchor. This is the expected
	// result for an internal PKI, and it is also what a public chain looks like
	// when its root is not in the trust store.
	TrustSelfAnchored
	// TrustAnchored means the chain verifies against the configured trust
	// anchors (the system store unless overridden). A TLS client would accept
	// this chain.
	TrustAnchored
)

// String renders the trust level as a short label.
func (t TrustLevel) String() string {
	switch t {
	case TrustAnchored:
		return "trusted"
	case TrustSelfAnchored:
		return "self-anchored"
	default:
		return "broken"
	}
}

// VerifyOptions configures chain verification.
type VerifyOptions struct {
	// ExtraRoots are additional trust anchors, typically loaded from a --roots
	// file. Certificates in the chain under test are never trusted implicitly,
	// which is the whole point.
	ExtraRoots []*x509.Certificate
	// SkipSystemRoots omits the operating system's trust store, leaving
	// ExtraRoots as the only trust anchors.
	SkipSystemRoots bool
	// DNSName, when set, also checks that the leaf is valid for this hostname.
	DNSName string
	// CurrentTime overrides the verification time. The zero value means now.
	CurrentTime time.Time
}

// VerifyResult reports the outcome of verifying a chain.
type VerifyResult struct {
	// Level is how far the chain verified.
	Level TrustLevel
	// Anchor is the common name of the root the chain terminated at, when one
	// was found.
	Anchor string
	// Err is the verification error against the configured trust anchors. It is
	// set for every level below TrustAnchored, including TrustSelfAnchored,
	// where it explains why the chain is not publicly trusted.
	Err error
}

// VerifyChain verifies a chain against real trust anchors.
//
// certs is the bundle as loaded, leaf first. Every certificate after the leaf
// is offered as an intermediate; none of them is trusted implicitly. If that
// fails, the chain is retried with the input's own self-signed certificates
// promoted to anchors, which tells "internally consistent but not trusted"
// apart from "broken".
func VerifyChain(certs []*x509.Certificate, opts VerifyOptions) (*VerifyResult, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}

	leaf := certs[0]

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}

	roots, err := trustAnchors(opts)
	if err != nil {
		return nil, err
	}

	verifyOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		DNSName:       opts.DNSName,
		CurrentTime:   opts.CurrentTime,
	}

	chains, trustErr := leaf.Verify(verifyOpts)
	if trustErr == nil {
		return &VerifyResult{Level: TrustAnchored, Anchor: anchorName(chains)}, nil
	}

	// Not trusted. Retry with the input's own self-signed certificates as
	// anchors to find out whether the bundle at least hangs together.
	selfAnchors := selfSignedFrom(certs)
	if selfAnchors == nil {
		return &VerifyResult{Level: TrustBroken, Err: trustErr}, nil
	}

	verifyOpts.Roots = selfAnchors
	chains, selfErr := leaf.Verify(verifyOpts)
	if selfErr != nil {
		return &VerifyResult{Level: TrustBroken, Err: trustErr}, nil
	}

	return &VerifyResult{Level: TrustSelfAnchored, Anchor: anchorName(chains), Err: trustErr}, nil
}

// trustAnchors builds the root pool: the system trust store unless it was
// skipped, plus any roots the caller supplied.
func trustAnchors(opts VerifyOptions) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	if !opts.SkipSystemRoots {
		system, err := x509.SystemCertPool()
		if err != nil {
			// A platform with no readable trust store is not a fatal error as
			// long as the caller brought their own anchors.
			if len(opts.ExtraRoots) == 0 {
				return nil, fmt.Errorf("failed to load the system trust store: %w", err)
			}
			logger.Warn("failed to load the system trust store", zap.Error(err))
		} else {
			// SystemCertPool returns a copy, so adding to it is safe.
			pool = system
		}
	}

	for _, root := range opts.ExtraRoots {
		pool.AddCert(root)
	}

	return pool, nil
}

// selfSignedFrom returns a pool of the genuinely self-signed certificates in
// certs, or nil if there are none. A matching Issuer and Subject is not enough:
// the signature has to check out against the certificate's own key.
func selfSignedFrom(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	found := false

	for _, cert := range certs {
		if cert.Issuer.String() != cert.Subject.String() {
			continue
		}
		if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
			continue
		}
		pool.AddCert(cert)
		found = true
	}

	if !found {
		return nil
	}
	return pool
}

// anchorName returns the common name of the root that the first verified chain
// terminates at.
func anchorName(chains [][]*x509.Certificate) string {
	if len(chains) == 0 || len(chains[0]) == 0 {
		return ""
	}
	last := chains[0][len(chains[0])-1]
	return last.Subject.CommonName
}

// FormatVerifyResult renders a verification result for the terminal.
func FormatVerifyResult(result *VerifyResult) string {
	if result == nil {
		return "❌ Certificate chain could not be verified."
	}

	switch result.Level {
	case TrustAnchored:
		if result.Anchor != "" {
			return fmt.Sprintf("✅ Certificate chain is valid.\nTrust anchor: %s", result.Anchor)
		}
		return "✅ Certificate chain is valid."

	case TrustSelfAnchored:
		var sb strings.Builder
		sb.WriteString("⚠️  Certificate chain is self-anchored.\n\n")
		sb.WriteString("The chain links up correctly, but it terminates at a root that is not\n")
		sb.WriteString("a trust anchor, so a TLS client would reject it.\n")
		if result.Anchor != "" {
			fmt.Fprintf(&sb, "\nAnchored at: %s (supplied in the input, not trusted)\n", result.Anchor)
		}
		if result.Err != nil {
			fmt.Fprintf(&sb, "Trust store said: %v\n", result.Err)
		}
		sb.WriteString("\nIf this is an internal PKI, pass --roots with your CA to verify it properly.")
		return sb.String()

	default:
		var sb strings.Builder
		sb.WriteString("❌ Certificate chain is broken.\n")
		if result.Err != nil {
			fmt.Fprintf(&sb, "\n%v", result.Err)
		}
		return sb.String()
	}
}
