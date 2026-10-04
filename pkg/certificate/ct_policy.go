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
// SCTs embedded in it and any the server delivered in the TLS extension. It
// returns nil when the policy is met, and also when it cannot be judged fairly:
//
//   - no SCTs at all. An enterprise root added to the system store looks the
//     same as a public one from here, and Chrome does not enforce CT on it, so
//     a certificate with no SCTs is not reported.
//   - an SCT from a log the bundled list does not know. The list may simply be
//     older than the log, and counting that SCT as missing would blame the
//     certificate for the list's age.
//   - an embedded SCT list that does not parse, which sctError reports.
//   - a bundled log list more than 70 days older than now, as Chrome does.
//
// SCTs in a stapled OCSP response are not read; a server relying only on those
// would be reported.
func CTPolicyFinding(leaf *x509.Certificate, delivered [][]byte, now time.Time) *ConformanceFinding {
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
	for _, sct := range append(append([]SCT{}, embedded...), tls...) {
		if sct.Log == nil {
			return nil
		}
	}

	need := 2
	if leaf.NotAfter.Sub(leaf.NotBefore) > ctLongLifetime {
		need = 3
	}
	if embeddedMeetsPolicy(embedded, need) || deliveredMeetsPolicy(tls) {
		return nil
	}

	counted, operators := countEmbedded(embedded)
	return &ConformanceFinding{
		Problem: ProblemInsufficientSCTs,
		Subject: displayName(leaf),
		Detail: fmt.Sprintf("Chrome requires embedded SCTs from %d distinct logs run by at least two operators for a certificate of this lifetime, at least one from a log still accepting; this one has %d counting SCTs from %s, so Chrome rejects it; ask the CA to reissue it with enough SCTs",
			need, counted, operatorList(operators)),
	}
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

// deliveredMeetsPolicy is the TLS path: two SCTs from distinct live logs and
// operators, whatever the lifetime. Retired logs do not count here.
func deliveredMeetsPolicy(scts []SCT) bool {
	logs := map[string]bool{}
	operators := map[string]bool{}
	for _, sct := range scts {
		if logLive(sct) {
			logs[sct.LogID] = true
			operators[sct.Log.Operator] = true
		}
	}
	return len(logs) >= 2 && len(operators) >= 2
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
