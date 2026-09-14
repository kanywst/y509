package certificate

import (
	"crypto/x509"
	"fmt"
	"strings"
)

// ChainChange is what happened to one certificate between two chains.
type ChainChange int

const (
	// ChangeUnchanged means the same certificate is present in both.
	ChangeUnchanged ChainChange = iota
	// ChangeAdded means the certificate is only in the second chain.
	ChangeAdded
	// ChangeRemoved means the certificate is only in the first chain.
	ChangeRemoved
	// ChangeMoved means the same certificate is in both, at a different
	// position.
	ChangeMoved
)

// String names the change.
func (c ChainChange) String() string {
	switch c {
	case ChangeUnchanged:
		return "unchanged"
	case ChangeAdded:
		return "added"
	case ChangeRemoved:
		return "removed"
	case ChangeMoved:
		return "moved"
	default:
		return "unknown"
	}
}

// ChainDiffEntry is one certificate and what became of it.
type ChainDiffEntry struct {
	// Change is what happened.
	Change ChainChange
	// Subject names the certificate.
	Subject string
	// Fingerprint is the SHA-256 of the DER, which is what identity means
	// here: two certificates with the same subject and different bytes are
	// different certificates, and that is usually the interesting case.
	Fingerprint string
	// From and To are the positions in the first and second chain, -1 where
	// the certificate is absent.
	From int
	To   int
}

// ChainDiff compares two chains as they were presented.
type ChainDiff struct {
	Entries []ChainDiffEntry
	// LeafChanges describes what differs about the leaf when both chains have
	// one and they are not the same certificate. Empty otherwise.
	LeafChanges []string
}

// Same reports whether the two chains are byte-identical, in the same order.
func (d *ChainDiff) Same() bool {
	for _, e := range d.Entries {
		if e.Change != ChangeUnchanged {
			return false
		}
	}
	return true
}

// DiffChains compares two chains as presented.
//
// Identity is the SHA-256 of the DER, not the subject: a renewed certificate
// keeps its subject and changes everything else, and treating those as the same
// certificate would hide the only thing that happened. Position is reported
// separately, so a chain that was merely reordered does not read as a chain
// that was replaced -- which is the difference between a server reconfigured
// and a certificate rotated.
func DiffChains(before, after []*x509.Certificate) *ChainDiff {
	diff := &ChainDiff{Entries: []ChainDiffEntry{}}

	beforeAt := positionsByFingerprint(before)
	afterAt := positionsByFingerprint(after)

	// Walk the first chain, then anything in the second that was not in the
	// first. This keeps the output in the order the chains were presented,
	// which is the order everything else in the tool reports.
	for i, cert := range before {
		if cert == nil {
			continue
		}
		fp := FormatFingerprint(cert)
		entry := ChainDiffEntry{
			Subject:     displayName(cert),
			Fingerprint: fp,
			From:        i,
			To:          -1,
		}
		if to, ok := afterAt[fp]; ok {
			entry.To = to
			entry.Change = ChangeUnchanged
			if to != i {
				entry.Change = ChangeMoved
			}
		} else {
			entry.Change = ChangeRemoved
		}
		diff.Entries = append(diff.Entries, entry)
	}

	for i, cert := range after {
		if cert == nil {
			continue
		}
		fp := FormatFingerprint(cert)
		if _, ok := beforeAt[fp]; ok {
			continue
		}
		diff.Entries = append(diff.Entries, ChainDiffEntry{
			Change:      ChangeAdded,
			Subject:     displayName(cert),
			Fingerprint: fp,
			From:        -1,
			To:          i,
		})
	}

	diff.LeafChanges = leafChanges(before, after)
	return diff
}

// positionsByFingerprint indexes a chain by certificate identity. A duplicate
// keeps its first position, which matches how the duplicate itself is reported
// elsewhere.
func positionsByFingerprint(certs []*x509.Certificate) map[string]int {
	at := make(map[string]int, len(certs))
	for i, cert := range certs {
		if cert == nil {
			continue
		}
		fp := FormatFingerprint(cert)
		if _, seen := at[fp]; !seen {
			at[fp] = i
		}
	}
	return at
}

// leafChanges describes what differs about the leaf, for the common case of a
// renewal: same name, same issuer, everything else new. Listing the whole
// certificate as removed and another added is accurate and tells the reader
// nothing about what actually changed.
func leafChanges(before, after []*x509.Certificate) []string {
	if len(before) == 0 || len(after) == 0 {
		return nil
	}
	old, current := before[0], after[0]
	if old == nil || current == nil || FormatFingerprint(old) == FormatFingerprint(current) {
		return nil
	}

	var changes []string
	add := func(field, from, to string) {
		if from != to {
			changes = append(changes, fmt.Sprintf("%s: %s -> %s", field, from, to))
		}
	}

	add("subject", old.Subject.String(), current.Subject.String())
	add("issuer", old.Issuer.String(), current.Issuer.String())
	add("serial", old.SerialNumber.String(), current.SerialNumber.String())
	add("not before", old.NotBefore.UTC().Format("2006-01-02"), current.NotBefore.UTC().Format("2006-01-02"))
	add("not after", old.NotAfter.UTC().Format("2006-01-02"), current.NotAfter.UTC().Format("2006-01-02"))
	add("key algorithm", old.PublicKeyAlgorithm.String(), current.PublicKeyAlgorithm.String())
	add("signature algorithm", old.SignatureAlgorithm.String(), current.SignatureAlgorithm.String())
	add("dns names", strings.Join(old.DNSNames, ", "), strings.Join(current.DNSNames, ", "))

	return changes
}

// FormatChainDiff renders a diff for a terminal.
func FormatChainDiff(diff *ChainDiff) string {
	if diff == nil {
		return ""
	}
	if diff.Same() {
		return "The two chains are identical."
	}

	var sb strings.Builder
	sb.WriteString("Chain differences:\n")

	for _, e := range diff.Entries {
		switch e.Change {
		case ChangeUnchanged:
			fmt.Fprintf(&sb, "    %s\n", e.Subject)
		case ChangeAdded:
			fmt.Fprintf(&sb, "  + %s\n", e.Subject)
		case ChangeRemoved:
			fmt.Fprintf(&sb, "  - %s\n", e.Subject)
		case ChangeMoved:
			fmt.Fprintf(&sb, "  ~ %s (position %d -> %d)\n", e.Subject, e.From, e.To)
		}
	}

	if len(diff.LeafChanges) > 0 {
		sb.WriteString("\nThe leaf was replaced:\n")
		for _, change := range diff.LeafChanges {
			fmt.Fprintf(&sb, "  • %s\n", change)
		}
	}

	return strings.TrimRight(sb.String(), "\n")
}
