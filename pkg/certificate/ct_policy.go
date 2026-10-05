package certificate

import (
	"crypto/x509"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ProblemInsufficientSCTs is the conformance problem for a certificate that
// does not meet Chrome's CT policy.
const ProblemInsufficientSCTs = "insufficient SCTs"

// ctLongLifetime is the lifetime above which Chrome wants a third SCT.
const ctLongLifetime = 180 * 24 * time.Hour

// ctListMaxAge mirrors Chrome, which stops enforcing CT when its log list is
// more than 70 days old. Past that the bundled states may be wrong, so the
// policy is not judged at all.
const ctListMaxAge = 70 * 24 * time.Hour

// CTPolicyFinding judges a publicly trusted leaf against Chrome's CT policy
// (googlechrome.github.io/CertificateTransparency/ct_policy.html), using the
// SCTs embedded in it and any the server delivered in the TLS extension. Only
// SCTs whose signature verifies against their log's key count, as in Chrome;
// issuer is the leaf's issuer, which an embedded SCT's signature covers.
//
// It returns nil when the policy is met, and also when it cannot be judged
// fairly:
//
//   - no SCTs at all. An enterprise root added to the system store looks the
//     same as a public one from here, and Chrome does not enforce CT on it, so
//     a certificate with no SCTs is not reported.
//   - an SCT from a log the bundled list does not know, or knows without a
//     key. The list may simply be
//     older than the log, and counting that SCT as missing would blame the
//     certificate for the list's age.
//   - an embedded SCT list that does not parse, which sctError reports.
//   - embedded SCTs and no issuer to check them against.
//   - a bundled log list more than 70 days older than now, as Chrome does.
//
// SCTs in a stapled OCSP response are not read; a server relying only on those
// would be reported.
func CTPolicyFinding(leaf, issuer *x509.Certificate, delivered [][]byte, now time.Time) *ConformanceFinding {
	if leaf == nil || ctListStale(now) {
		return nil
	}
	embedded, err := SCTs(leaf)
	if err != nil {
		return nil
	}
	var tls []SCT
	for _, raw := range delivered {
		sct, err := parseSCT(raw)
		if err != nil {
			continue
		}
		tls = append(tls, sct)
	}
	if len(embedded)+len(tls) == 0 {
		return nil
	}
	if len(embedded) > 0 && issuer == nil {
		return nil
	}
	// A log the list does not know, or knows without a key, cannot be judged
	// either way. Counting its SCT as invalid would blame the certificate for
	// the list.
	for _, sct := range append(append([]SCT{}, embedded...), tls...) {
		if sct.Log == nil || sct.Log.Key == "" {
			return nil
		}
	}

	// Only what verifies counts. A forged or corrupted SCT is not evidence of
	// logging, and Chrome ignores it too.
	invalid := 0
	verified := func(scts []SCT, isEmbedded bool) []SCT {
		var out []SCT
		for _, sct := range scts {
			if VerifySCT(sct, leaf, issuer, isEmbedded) != nil {
				invalid++
				continue
			}
			out = append(out, sct)
		}
		return out
	}
	embedded = verified(embedded, true)
	tls = verified(tls, false)

	need := 2
	if leaf.NotAfter.Sub(leaf.NotBefore) > ctLongLifetime {
		need = 3
	}
	if embeddedMeetsPolicy(embedded, need) || deliveredMeetsPolicy(tls) {
		return nil
	}

	embeddedLogs, embeddedOps := countEmbedded(embedded)
	detail := fmt.Sprintf("Chrome requires embedded SCTs from %d distinct logs run by at least two operators, at least one from a log still accepting, or two SCTs sent in the TLS handshake from distinct live logs and operators; this certificate has %d counting embedded (%s)",
		need, embeddedLogs, operatorList(embeddedOps))
	if len(delivered) > 0 {
		tlsLogs, tlsOps := countDelivered(tls)
		detail += fmt.Sprintf(" and %d counting from the handshake (%s)", tlsLogs, operatorList(tlsOps))
	}
	if invalid > 0 {
		detail += fmt.Sprintf(", and %d SCTs whose signature does not verify", invalid)
	}
	detail += ", so Chrome rejects it; "
	if len(delivered) > 0 {
		detail += "have the server send enough SCTs, or ask the CA to reissue it with enough embedded"
	} else {
		detail += "ask the CA to reissue it with enough SCTs"
	}
	return &ConformanceFinding{Problem: ProblemInsufficientSCTs, Subject: displayName(leaf), Detail: detail}
}

func ctListStale(now time.Time) bool {
	loadCTLogs()
	listed, err := time.Parse(time.RFC3339, ctLogsList.Timestamp)
	return err != nil || now.Sub(listed) > ctListMaxAge
}

// logCounts reports whether an SCT counts towards the embedded requirement:
// its log is live, or retired after the SCT was issued.
func logCounts(sct SCT) bool {
	switch sct.Log.State {
	case "qualified", "usable", "readonly":
		return true
	case "retired":
		retired, err := time.Parse(time.RFC3339, sct.Log.StateSince)
		return err == nil && sct.Timestamp.Before(retired)
	}
	return false
}

func logLive(sct SCT) bool {
	switch sct.Log.State {
	case "qualified", "usable", "readonly":
		return true
	}
	return false
}

// countEmbedded counts the distinct logs whose SCTs count, and their operators.
func countEmbedded(scts []SCT) (int, map[string]bool) {
	logs := map[string]bool{}
	operators := map[string]bool{}
	for _, sct := range scts {
		if logCounts(sct) {
			logs[sct.LogID] = true
			operators[sct.Log.Operator] = true
		}
	}
	return len(logs), operators
}

func embeddedMeetsPolicy(scts []SCT, need int) bool {
	live := false
	for _, sct := range scts {
		if logLive(sct) {
			live = true
		}
	}
	logs, operators := countEmbedded(scts)
	return live && logs >= need && len(operators) >= 2
}

// countDelivered counts the distinct live logs among TLS-delivered SCTs, and
// their operators. Retired logs do not count on this path.
func countDelivered(scts []SCT) (int, map[string]bool) {
	logs := map[string]bool{}
	operators := map[string]bool{}
	for _, sct := range scts {
		if logLive(sct) {
			logs[sct.LogID] = true
			operators[sct.Log.Operator] = true
		}
	}
	return len(logs), operators
}

// deliveredMeetsPolicy is the TLS path: two SCTs from distinct live logs and
// operators, whatever the lifetime.
func deliveredMeetsPolicy(scts []SCT) bool {
	logs, operators := countDelivered(scts)
	return logs >= 2 && len(operators) >= 2
}

func operatorList(operators map[string]bool) string {
	if len(operators) == 0 {
		return "no operator"
	}
	names := make([]string, 0, len(operators))
	for name := range operators {
		names = append(names, name)
	}
	slices.Sort(names)
	return strings.Join(names, ", ")
}
