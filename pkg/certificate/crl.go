package certificate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// The fixed vocabulary for the CRL findings, which join the staple findings
// under revocation. A certificate a CRL lists is a different claim from a
// revoked staple: the staple is always about the leaf, a CRL can be about any
// certificate in the path.
const (
	ProblemRevokedInCRL    = "revoked in CRL"
	ProblemStaleCRL        = "stale CRL"
	ProblemBadCRLSignature = "CRL signature invalid"
	ProblemCRLUnavailable  = "CRL unavailable"
	ProblemCRLOutOfScope   = "CRL out of scope"
)

// The status a CRLCheck ends in.
const (
	CRLGood    = "good"
	CRLRevoked = "revoked"
	// CRLUnchecked means no CRL could be read and verified for the
	// certificate. It is never silent: Err says why.
	CRLUnchecked = "unchecked"
)

// maxCRLSize bounds a download. The largest public CRLs run to a few tens of
// megabytes; anything past this is more likely a misdirected URL than a CRL.
const maxCRLSize = 64 << 20

// crlCacheMaxAge bounds how long a cached CRL is reused, however far off its
// nextUpdate. A CA republishes as soon as it revokes something, and nextUpdate
// is often a week away: a gate that trusted the cache that long would read a
// fresh revocation as good.
const crlCacheMaxAge = time.Hour

// crlDirPerm keeps the cache private: other accounts on the host must not be
// able to plant a CRL that says a revoked certificate is good.
const crlDirPerm = 0o700

// CRLCheck is what the CRL said about one certificate in the path.
type CRLCheck struct {
	// Subject is the certificate checked.
	Subject string
	// URL is the distribution point the answer came from, or the last one
	// tried when none answered. Empty when the certificate names none.
	URL string
	// Status is CRLGood, CRLRevoked or CRLUnchecked.
	Status string
	// Cached reports an answer read from the on-disk cache rather than
	// fetched now.
	Cached bool
	// ThisUpdate and NextUpdate are the CRL's own freshness.
	ThisUpdate time.Time
	NextUpdate time.Time
	// RevokedAt and RevocationReason are set only for a revoked certificate.
	RevokedAt        time.Time
	RevocationReason string
	// Err is why the certificate is unchecked.
	Err error
	// failure says which kind of fix Err calls for: an endpoint that is down,
	// a CRL that does not verify, or one that does not cover the certificate.
	failure crlFailure
}

type crlFailure int

const (
	crlFetchFailed crlFailure = iota
	crlBadSignature
	crlOutOfScope
)

// fetched is one URL's outcome within a run, failures included, so a fleet of
// targets behind one unreachable distribution point waits out its timeout once.
type fetched struct {
	der    []byte
	cached bool
	err    error
}

// CRLFetcher downloads CRLs, caching each for up to crlCacheMaxAge.
//
// The cache lives in memory for the run, so several targets sharing an
// intermediate fetch its CRL once, and on disk under Dir, so a scheduled check
// does not download a CA's whole CRL every time it runs. A cached CRL is
// verified against the issuer each time it is used, exactly like a fresh one.
type CRLFetcher struct {
	// Client does the fetching. Nil means a client with DefaultConnectTimeout.
	Client *http.Client
	// Dir is the on-disk cache. Empty disables it.
	Dir string
	// Now is the clock, for tests. Nil means time.Now.
	Now func() time.Time

	mem map[string]fetched
}

// DefaultCRLCacheDir is where CRLs are cached when the user has a private
// cache directory, or "" when there is none. The temp directory is not a
// fallback for the same reason it is not one for the log: it is shared.
func DefaultCRLCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "y509", "crl")
}

func (f *CRLFetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

// fetch returns the DER at url and whether it came from the disk cache. A
// cached copy is used only while the CRL inside it is not past nextUpdate.
// Nothing is written to the cache here: only a CRL that verified is, by
// checkCRL, so a bad answer cannot pin itself on disk until a far nextUpdate.
func (f *CRLFetcher) fetch(ctx context.Context, url string) fetched {
	if r, ok := f.mem[url]; ok {
		return r
	}
	r := fetched{}
	if der := f.readCache(url); der != nil {
		r = fetched{der: der, cached: true}
	} else {
		r.der, r.err = f.download(ctx, url)
	}
	f.remember(url, r)
	return r
}

func (f *CRLFetcher) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	client := f.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultConnectTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %s", resp.Status)
	}
	der, err := io.ReadAll(io.LimitReader(resp.Body, maxCRLSize+1))
	if err != nil {
		return nil, err
	}
	if len(der) > maxCRLSize {
		return nil, fmt.Errorf("larger than %d MiB", maxCRLSize>>20)
	}
	return der, nil
}

func (f *CRLFetcher) remember(url string, r fetched) {
	if f.mem == nil {
		f.mem = map[string]fetched{}
	}
	f.mem[url] = r
}

// evict forgets a cached copy that did not verify, so the next fetch goes to
// the network.
func (f *CRLFetcher) evict(url string) {
	delete(f.mem, url)
	if f.Dir != "" {
		_ = os.Remove(f.cachePath(url))
	}
}

func (f *CRLFetcher) cachePath(url string) string {
	sum := sha256.Sum256([]byte(url))
	return filepath.Join(f.Dir, hex.EncodeToString(sum[:])+".crl")
}

// readCache returns the cached DER for url while it is still current -- fetched
// within crlCacheMaxAge and not past its nextUpdate -- or nil.
// Anything unreadable is treated as a miss rather than an error: the cache is
// an optimisation, and a fetch replaces whatever is there.
func (f *CRLFetcher) readCache(url string) []byte {
	if f.Dir == "" {
		return nil
	}
	path := f.cachePath(url)
	info, err := os.Stat(path)
	if err != nil || f.now().Sub(info.ModTime()) > crlCacheMaxAge {
		return nil
	}
	der, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil || crl.NextUpdate.IsZero() || !f.now().Before(crl.NextUpdate) {
		return nil
	}
	return der
}

// writeCache stores der best-effort, through a rename so a reader never sees
// half a file.
func (f *CRLFetcher) writeCache(url string, der []byte) {
	if f.Dir == "" {
		return
	}
	if err := os.MkdirAll(f.Dir, crlDirPerm); err != nil {
		return
	}
	tmp, err := os.CreateTemp(f.Dir, ".crl-*")
	if err != nil {
		return
	}
	_, werr := tmp.Write(der)
	cerr := tmp.Close()
	if werr != nil || cerr != nil || os.Rename(tmp.Name(), f.cachePath(url)) != nil {
		_ = os.Remove(tmp.Name())
	}
}

// CheckCRLs checks every certificate in a verified path against the CRL its
// distribution point names. path is leaf first, anchor last, as VerifyChain
// returns it; the anchor is not checked, since nothing above it signs a CRL
// about it.
//
// This is the one place y509 goes to the network for something the server did
// not send. It is opt-in for that reason, and it fills no gap: a CRL adds a
// fact about a certificate that is already in the chain.
func CheckCRLs(ctx context.Context, path []*x509.Certificate, f *CRLFetcher) []CRLCheck {
	if len(path) < 2 {
		return nil
	}
	out := make([]CRLCheck, 0, len(path)-1)
	for i := 0; i < len(path)-1; i++ {
		cert, issuer := path[i], path[i+1]
		if cert == nil || issuer == nil {
			continue
		}
		out = append(out, checkCRL(ctx, cert, issuer, f))
	}
	return out
}

func checkCRL(ctx context.Context, cert, issuer *x509.Certificate, f *CRLFetcher) CRLCheck {
	check := CRLCheck{Subject: displayName(cert), Status: CRLUnchecked}

	var urls []string
	for _, u := range cert.CRLDistributionPoints {
		u = strings.TrimSpace(u)
		// ldap:// and the rest are left alone: no client in scope fetches them.
		lower := strings.ToLower(u)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			urls = append(urls, u)
		}
	}
	if len(urls) == 0 {
		// Not a finding: the advisories already say "no CRL pointer" where it
		// matters, and a short-lived certificate needs none.
		check.Err = errors.New("no HTTP CRL distribution point")
		return check
	}

	now := f.now()
	// A stale "good" is kept in hand while the next distribution point is
	// tried: a current CRL there could say otherwise.
	var stale *CRLCheck
	for _, url := range urls {
		check.URL = url
		r := f.fetch(ctx, url)
		crl, failure, err := judgeCRL(r, cert, issuer, url, now)
		if err != nil && r.cached {
			// A cached copy that no longer verifies is not evidence about
			// the distribution point. Drop it and ask the network once.
			f.evict(url)
			r = f.fetch(ctx, url)
			crl, failure, err = judgeCRL(r, cert, issuer, url, now)
		}
		if err != nil {
			check.Err, check.failure = err, failure
			continue
		}
		if r.err == nil && !r.cached {
			f.writeCache(url, r.der)
		}

		answer := check
		answer.Err = nil
		answer.Cached = r.cached
		answer.ThisUpdate, answer.NextUpdate = crl.ThisUpdate, crl.NextUpdate
		answer.Status = CRLGood
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				answer.Status = CRLRevoked
				answer.RevokedAt = entry.RevocationTime
				answer.RevocationReason = revocationReasonName(entry.ReasonCode)
				break
			}
		}
		// Revocation is permanent, so a stale CRL that lists it still counts.
		if answer.Status == CRLGood && !crl.NextUpdate.IsZero() && now.After(crl.NextUpdate) {
			if stale == nil {
				stale = &answer
			}
			continue
		}
		return answer
	}
	if stale != nil {
		return *stale
	}
	return check
}

// judgeCRL parses a fetch and decides whether its CRL may answer for cert.
func judgeCRL(r fetched, cert, issuer *x509.Certificate, url string, now time.Time) (*x509.RevocationList, crlFailure, error) {
	if r.err != nil {
		return nil, crlFetchFailed, r.err
	}
	crl, err := x509.ParseRevocationList(r.der)
	if err != nil {
		return nil, crlFetchFailed, fmt.Errorf("not a CRL: %w", err)
	}
	if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) {
		return nil, crlBadSignature, errors.New("issued by a different CA")
	}
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return nil, crlBadSignature, err
	}
	if err := crlScope(crl, cert, url); err != nil {
		return nil, crlOutOfScope, err
	}
	// The same slop as a staple: past it a client rejects the CRL, and short
	// of it the difference is clock skew.
	if crl.ThisUpdate.After(now.Add(futureStapleSlop)) {
		return nil, crlOutOfScope, fmt.Errorf("the CRL's thisUpdate is %s, more than a day ahead",
			crl.ThisUpdate.UTC().Format(time.RFC3339))
	}
	return crl, 0, nil
}

var (
	oidDeltaCRLIndicator        = asn1.ObjectIdentifier{2, 5, 29, 27}
	oidIssuingDistributionPoint = asn1.ObjectIdentifier{2, 5, 29, 28}
	oidReasonCode               = asn1.ObjectIdentifier{2, 5, 29, 21}
	oidInvalidityDate           = asn1.ObjectIdentifier{2, 5, 29, 24}
)

// crlScope checks the CRL covers cert, as RFC 5280 6.3.3 (b) requires. A CA
// that shards its CRLs marks each with an issuing distribution point, and the
// signature alone cannot tell one shard from another: a revoked certificate
// would read as good against a shard it is not on. crypto/x509 does not parse
// the extension, so it is read here.
//
// Anything that narrows the CRL in a way this check does not follow -- a delta
// CRL, an indirect CRL, a reason-partitioned one -- is out of scope rather than
// guessed at.
func crlScope(crl *x509.RevocationList, cert *x509.Certificate, url string) error {
	// RFC 5280 5.3: a CRL with a critical entry extension this does not
	// process cannot answer for any certificate, listed or not.
	for _, entry := range crl.RevokedCertificateEntries {
		for _, ext := range entry.Extensions {
			if ext.Critical && !ext.Id.Equal(oidReasonCode) && !ext.Id.Equal(oidInvalidityDate) {
				return fmt.Errorf("the CRL has an entry with an unhandled critical extension (OID %s)", ext.Id)
			}
		}
	}
	for _, ext := range crl.Extensions {
		switch {
		case ext.Critical && !ext.Id.Equal(oidDeltaCRLIndicator) && !ext.Id.Equal(oidIssuingDistributionPoint):
			return fmt.Errorf("the CRL has an unhandled critical extension (OID %s)", ext.Id)
		case ext.Id.Equal(oidDeltaCRLIndicator):
			return errors.New("the CRL is a delta CRL, only half the answer")
		case ext.Id.Equal(oidIssuingDistributionPoint):
			idp, err := parseIDP(ext.Value)
			if err != nil {
				return fmt.Errorf("the CRL has an unreadable issuing distribution point: %w", err)
			}
			switch {
			case idp.indirect:
				return errors.New("the CRL is an indirect CRL")
			case idp.someReasons:
				return errors.New("the CRL covers only some revocation reasons")
			case idp.onlyAttribute:
				return errors.New("the CRL covers only attribute certificates")
			case idp.onlyUser && cert.IsCA:
				return errors.New("the CRL covers only end-entity certificates")
			case idp.onlyCA && !cert.IsCA:
				return errors.New("the CRL covers only CA certificates")
			case idp.relativeName:
				return errors.New("the CRL names its distribution point relative to the issuer")
			case idp.named && len(idp.uris) == 0:
				return errors.New("the CRL names its distribution point without a URI")
			case len(idp.uris) > 0 && !containsString(idp.uris, url):
				return fmt.Errorf("the CRL is the one for %s", strings.Join(idp.uris, ", "))
			}
		}
	}
	return nil
}

type issuingDistributionPoint struct {
	uris                                    []string
	named, relativeName                     bool
	onlyUser, onlyCA, someReasons, indirect bool
	onlyAttribute                           bool
}

// parseIDP reads RFC 5280's IssuingDistributionPoint, whose fields are all
// implicitly tagged and optional.
func parseIDP(der []byte) (issuingDistributionPoint, error) {
	var out issuingDistributionPoint
	input := cryptobyte.String(der)
	var seq cryptobyte.String
	if !input.ReadASN1(&seq, cbasn1.SEQUENCE) || !input.Empty() {
		return out, errors.New("not a SEQUENCE")
	}

	var dp cryptobyte.String
	var present bool
	if !seq.ReadOptionalASN1(&dp, &present, cbasn1.Tag(0).ContextSpecific().Constructed()) {
		return out, errors.New("bad distributionPoint")
	}
	if present {
		var names cryptobyte.String
		switch {
		case dp.PeekASN1Tag(cbasn1.Tag(0).ContextSpecific().Constructed()):
			if !dp.ReadASN1(&names, cbasn1.Tag(0).ContextSpecific().Constructed()) {
				return out, errors.New("bad fullName")
			}
			out.named = true
			for !names.Empty() {
				var name cryptobyte.String
				var tag cbasn1.Tag
				if !names.ReadAnyASN1(&name, &tag) {
					return out, errors.New("bad GeneralName")
				}
				if tag == cbasn1.Tag(6).ContextSpecific() {
					out.uris = append(out.uris, string(name))
				}
			}
		default:
			out.relativeName = true
		}
	}

	flag := func(n int, dst *bool) bool {
		var v cryptobyte.String
		var ok bool
		if !seq.ReadOptionalASN1(&v, &ok, cbasn1.Tag(n).ContextSpecific()) {
			return false
		}
		if !ok {
			return true
		}
		// DER BOOLEAN: one byte, 0x00 or 0xff. Anything else is malformed,
		// not absent.
		if len(v) != 1 || (v[0] != 0x00 && v[0] != 0xff) {
			return false
		}
		*dst = v[0] == 0xff
		return true
	}
	if !flag(1, &out.onlyUser) || !flag(2, &out.onlyCA) {
		return out, errors.New("bad flags")
	}
	var reasons cryptobyte.String
	if !seq.ReadOptionalASN1(&reasons, &out.someReasons, cbasn1.Tag(3).ContextSpecific()) {
		return out, errors.New("bad onlySomeReasons")
	}
	if !flag(4, &out.indirect) || !flag(5, &out.onlyAttribute) || !seq.Empty() {
		return out, errors.New("bad flags")
	}
	return out, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// CRLFindings turns the checks into revocation findings, as of now. A good
// answer from a current CRL is no finding at all.
func CRLFindings(checks []CRLCheck, now time.Time) []RevocationFinding {
	var out []RevocationFinding
	for _, c := range checks {
		finding := func(problem, detail string) {
			out = append(out, RevocationFinding{Problem: problem, Subject: c.Subject, Detail: detail})
		}
		switch c.Status {
		case CRLRevoked:
			detail := "the CRL at " + c.URL + " lists this certificate as revoked"
			if !c.RevokedAt.IsZero() {
				detail += fmt.Sprintf(" (since %s, %s)", c.RevokedAt.UTC().Format(time.RFC3339), c.RevocationReason)
			}
			finding(ProblemRevokedInCRL, detail+"; every client that checks CRLs refuses the chain, so replace the certificate")
		case CRLUnchecked:
			if c.URL == "" {
				continue
			}
			switch c.failure {
			case crlBadSignature:
				finding(ProblemBadCRLSignature,
					"the CRL at "+c.URL+" does not verify against the issuer in the path ("+c.Err.Error()+
						"); clients discard it, so check the distribution point serves the issuing CA's CRL")
				continue
			case crlOutOfScope:
				finding(ProblemCRLOutOfScope,
					"the CRL at "+c.URL+" does not cover this certificate ("+c.Err.Error()+
						"); clients cannot use it, so check the distribution point the certificate names")
				continue
			}
			finding(ProblemCRLUnavailable,
				"no CRL could be fetched from "+c.URL+" ("+c.Err.Error()+
					"); a client that hard-fails on revocation refuses the chain, so check the CA's CRL endpoint is reachable")
		}
		if c.Status != CRLUnchecked && !c.NextUpdate.IsZero() && now.After(c.NextUpdate) {
			finding(ProblemStaleCRL,
				fmt.Sprintf("the CRL at %s passed its nextUpdate at %s; clients treat it as no answer, so the CA has stopped publishing it",
					c.URL, c.NextUpdate.UTC().Format(time.RFC3339)))
		}
	}
	return out
}

// FormatCRLChecks renders the checks for the terminal, or an empty string when
// there are none. Every certificate is listed, good ones included, since what
// was fetched and from where is the point of asking.
func FormatCRLChecks(checks []CRLCheck, now time.Time) string {
	if len(checks) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("CRL check:\n")
	for _, c := range checks {
		switch c.Status {
		case CRLUnchecked:
			if c.URL != "" {
				// The finding below says why.
				fmt.Fprintf(&sb, "  • %s: unchecked (%s)\n", c.Subject, c.URL)
				continue
			}
			fmt.Fprintf(&sb, "  • %s: unchecked (%s)\n", c.Subject, c.Err)
		default:
			source := c.URL
			if c.Cached {
				source += ", cached"
			}
			fmt.Fprintf(&sb, "  • %s: %s (%s)\n", c.Subject, c.Status, source)
		}
	}
	for _, f := range CRLFindings(checks, now) {
		fmt.Fprintf(&sb, "  • %s: %s\n", f.Problem, f.Subject)
		fmt.Fprintf(&sb, "    %s\n", f.Detail)
	}
	return strings.TrimRight(sb.String(), "\n")
}
