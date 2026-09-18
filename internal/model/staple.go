package model

import (
	"fmt"
	"time"

	"github.com/kanywst/y509/pkg/certificate"
)

// stapleTimeFormat is minute precision in UTC. A staple's freshness is the
// question here, and seconds add width without answering it.
const stapleTimeFormat = "2006-01-02 15:04 MST"

// isPresentedLeaf reports whether cert is the one the server led with.
//
// The staple covers that certificate, and the handshake facts arrived with it.
// It is matched by identity rather than by list position because a filter or a
// search reorders what is on screen and selects position zero, which would
// otherwise put the handshake under whatever happened to survive the predicate.
//
// The certificate the server sent first is used rather than the sorted leaf: a
// server presenting its chain out of order is the bug this tool exists to find,
// and in that case the two are not the same certificate. The handshake belongs
// to what was actually served.
func (m Model) isPresentedLeaf(cert *certificate.Info) bool {
	if m.conn == nil || cert == nil || cert.Certificate == nil {
		return false
	}
	if len(m.conn.Certificates) == 0 || m.conn.Certificates[0] == nil {
		return false
	}
	presented := m.conn.Certificates[0].Certificate
	return presented != nil && presented.Equal(cert.Certificate)
}

// renderStaple writes what a stapled OCSP response said, through the caller's
// aligned key/value writer.
//
// Nothing is written when no response was stapled. The absence is not a
// finding and not worth a row: a stapled response is optional for every
// subscriber certificate now, and a growing share of servers will never send
// one, so "OCSP staple: none" would report the norm as if it were news.
func (m Model) renderStaple(kv func(key, value string)) {
	if m.conn == nil {
		return
	}

	// Bytes that would not parse are a fact about the server, so they are said
	// out loud rather than dropped.
	if m.conn.StapleErr != nil {
		kv("OCSP Staple", "unreadable: "+m.conn.StapleErr.Error())
		return
	}

	staple := m.conn.Staple
	if staple == nil {
		return
	}

	status := staple.Status
	// An unverified response was read but not authenticated, which is a claim
	// about the server rather than about the certificate. The two ways that
	// happens deserve different words: an absent issuer is the ordinary
	// missing-intermediate case, while a response that fails against the issuer
	// the server itself presented is a much louder signal, and an operator told
	// the first when it was the second would go and fix the wrong thing.
	switch {
	case staple.Verified:
	case staple.VerifyErr != nil:
		status += " (SIGNATURE DID NOT VERIFY against the presented issuer: " + staple.VerifyErr.Error() + ")"
	default:
		status += " (signature not checked: issuer not in the chain)"
	}
	kv("OCSP Staple", status)

	if staple.SerialNumber != "" {
		kv("  For Serial", staple.SerialNumber)
	}
	if !staple.ThisUpdate.IsZero() {
		kv("  This Update", staple.ThisUpdate.UTC().Format(stapleTimeFormat))
	}
	switch {
	case staple.NextUpdate.IsZero():
		// Not the same as never expiring: the responder is saying the response
		// must not be cached.
		kv("  Next Update", "none given (do not cache)")
	case staple.Expired(time.Now()):
		kv("  Next Update", staple.NextUpdate.UTC().Format(stapleTimeFormat)+" (stale)")
	default:
		kv("  Next Update", staple.NextUpdate.UTC().Format(stapleTimeFormat))
	}

	if !staple.RevokedAt.IsZero() {
		kv("  Revoked", fmt.Sprintf("%s (%s)",
			staple.RevokedAt.UTC().Format(stapleTimeFormat), staple.RevocationReason))
	}
	kv("  Responder", staple.Responder)
}
