package model

import (
	"fmt"
	"time"
)

// stapleTimeFormat is minute precision in UTC. A staple's freshness is the
// question here, and seconds add width without answering it.
const stapleTimeFormat = "2006-01-02 15:04 MST"

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
	// about the server rather than about the certificate. Saying so next to the
	// status keeps the two apart.
	if !staple.Verified {
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
