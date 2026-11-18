package certificate

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type crlFixture struct {
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	leaf    *x509.Certificate
	other   *x509.Certificate // a second CA, for a CRL from the wrong issuer
	otherK  *ecdsa.PrivateKey
}

func crlCert(t *testing.T, cn string, serial int64, isCA bool, crlURLs []string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: true,
		CRLDistributionPoints: crlURLs,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func newCRLFixture(t *testing.T, crlURLs ...string) crlFixture {
	t.Helper()
	root, rootKey := crlCert(t, "CRL Test Root", 1, true, nil, nil, nil)
	leaf, _ := crlCert(t, "crl.test", 0x2a, false, crlURLs, root, rootKey)
	other, otherK := crlCert(t, "Other Root", 2, true, nil, nil, nil)
	return crlFixture{root: root, rootKey: rootKey, leaf: leaf, other: other, otherK: otherK}
}

func makeCRL(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, next time.Time, revoked ...int64) []byte {
	t.Helper()
	tmpl := &x509.RevocationList{
		Number:     big.NewInt(1),
		ThisUpdate: next.Add(-48 * time.Hour),
		NextUpdate: next,
	}
	for _, s := range revoked {
		tmpl.RevokedCertificateEntries = append(tmpl.RevokedCertificateEntries, x509.RevocationListEntry{
			SerialNumber:   big.NewInt(s),
			RevocationTime: next.Add(-72 * time.Hour),
			ReasonCode:     1, // key compromise
		})
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, issuer, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// crlServer serves body at /ca.crl and counts the requests.
func crlServer(t *testing.T, status int, body []byte) (string, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/ca.crl", &hits
}

func crlProblems(checks []CRLCheck, now time.Time) []string {
	return problems(CRLFindings(checks, now))
}

func TestCheckCRLs(t *testing.T) {
	now := time.Now()
	future := now.Add(24 * time.Hour)
	f0 := newCRLFixture(t)

	tests := []struct {
		name     string
		status   int
		body     func(f crlFixture) []byte
		want     string
		problems []string
	}{
		{"good", http.StatusOK,
			func(f crlFixture) []byte { return makeCRL(t, f.root, f.rootKey, future, 7) },
			CRLGood, nil},
		{"revoked", http.StatusOK,
			func(f crlFixture) []byte { return makeCRL(t, f.root, f.rootKey, future, 7, 0x2a) },
			CRLRevoked, []string{ProblemRevokedInCRL}},
		{"stale", http.StatusOK,
			func(f crlFixture) []byte { return makeCRL(t, f.root, f.rootKey, now.Add(-time.Hour)) },
			CRLGood, []string{ProblemStaleCRL}},
		{"wrong issuer", http.StatusOK,
			func(f crlFixture) []byte { return makeCRL(t, f.other, f.otherK, future) },
			CRLUnchecked, []string{ProblemBadCRLSignature}},
		{"forged signature", http.StatusOK,
			// Same issuer name, signed by a different key.
			func(f crlFixture) []byte {
				forged := *f.other
				forged.RawSubject = f.root.RawSubject
				forged.Subject = f.root.Subject
				return makeCRL(t, &forged, f.otherK, future)
			},
			CRLUnchecked, []string{ProblemBadCRLSignature}},
		{"not found", http.StatusNotFound,
			func(crlFixture) []byte { return nil },
			CRLUnchecked, []string{ProblemCRLUnavailable}},
		{"not a CRL", http.StatusOK,
			func(crlFixture) []byte { return []byte("<html>") },
			CRLUnchecked, []string{ProblemCRLUnavailable}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url, _ := crlServer(t, tt.status, tt.body(f0))
			f := newCRLFixture(t, url)
			// Same CA as f0, so bodies built from f0 apply.
			f.root, f.rootKey = f0.root, f0.rootKey
			leaf, _ := crlCert(t, "crl.test", 0x2a, false, []string{url}, f.root, f.rootKey)

			checks := CheckCRLs(context.Background(), []*x509.Certificate{leaf, f.root}, &CRLFetcher{})
			if len(checks) != 1 {
				t.Fatalf("got %d checks, want 1 (the anchor is not checked)", len(checks))
			}
			if checks[0].Status != tt.want {
				t.Errorf("status = %q, want %q (err %v)", checks[0].Status, tt.want, checks[0].Err)
			}
			if got := crlProblems(checks, now); strings.Join(got, ",") != strings.Join(tt.problems, ",") {
				t.Errorf("problems = %v, want %v", got, tt.problems)
			}
		})
	}
}

func TestCheckCRLsNoDistributionPointIsNoFinding(t *testing.T) {
	f := newCRLFixture(t, "ldap://ldap.test/cn=crl")
	checks := CheckCRLs(context.Background(), []*x509.Certificate{f.leaf, f.root}, &CRLFetcher{})
	if len(checks) != 1 || checks[0].Status != CRLUnchecked || checks[0].Err == nil {
		t.Fatalf("checks = %+v, want one unchecked with a reason", checks)
	}
	if got := CRLFindings(checks, time.Now()); len(got) != 0 {
		t.Errorf("findings = %v, want none: the advisories already cover a missing pointer", got)
	}
}

func TestCheckCRLsTriesTheNextDistributionPoint(t *testing.T) {
	f0 := newCRLFixture(t)
	dead, _ := crlServer(t, http.StatusInternalServerError, nil)
	live, _ := crlServer(t, http.StatusOK, makeCRL(t, f0.root, f0.rootKey, time.Now().Add(time.Hour)))
	leaf, _ := crlCert(t, "crl.test", 0x2a, false, []string{dead, live}, f0.root, f0.rootKey)

	checks := CheckCRLs(context.Background(), []*x509.Certificate{leaf, f0.root}, &CRLFetcher{})
	if checks[0].Status != CRLGood || checks[0].URL != live {
		t.Errorf("check = %+v, want good from %s", checks[0], live)
	}
}

func TestCRLFetcherCachesUntilNextUpdate(t *testing.T) {
	f0 := newCRLFixture(t)
	now := time.Now()
	url, hits := crlServer(t, http.StatusOK, makeCRL(t, f0.root, f0.rootKey, now.Add(time.Hour)))
	leaf, _ := crlCert(t, "crl.test", 0x2a, false, []string{url}, f0.root, f0.rootKey)
	path := []*x509.Certificate{leaf, f0.root}
	dir := t.TempDir() + "/crl"

	first := CheckCRLs(context.Background(), path, &CRLFetcher{Dir: dir})
	if first[0].Cached || hits.Load() != 1 {
		t.Fatalf("first run: cached=%v hits=%d, want a fetch", first[0].Cached, hits.Load())
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != crlDirPerm {
		t.Errorf("cache dir: %v, %v; want mode %o", info, err, crlDirPerm)
	}

	// A new fetcher, as a second run of the binary would have.
	second := CheckCRLs(context.Background(), path, &CRLFetcher{Dir: dir})
	if !second[0].Cached || second[0].Status != CRLGood || hits.Load() != 1 {
		t.Errorf("second run: cached=%v status=%s hits=%d, want the cached copy", second[0].Cached, second[0].Status, hits.Load())
	}

	// Past nextUpdate the cached copy is not used.
	later := now.Add(2 * time.Hour)
	third := CheckCRLs(context.Background(), path, &CRLFetcher{Dir: dir, Now: func() time.Time { return later }})
	if third[0].Cached || hits.Load() != 2 {
		t.Errorf("after nextUpdate: cached=%v hits=%d, want a refetch", third[0].Cached, hits.Load())
	}
}

func TestCRLFetcherReplacesACachedCopyThatDoesNotVerify(t *testing.T) {
	f0 := newCRLFixture(t)
	url, hits := crlServer(t, http.StatusOK, makeCRL(t, f0.root, f0.rootKey, time.Now().Add(time.Hour)))
	dir := t.TempDir()
	fetcher := &CRLFetcher{Dir: dir}
	// Plant another CA's CRL, with a far nextUpdate, where this URL's would be.
	fetcher.writeCache(url, makeCRL(t, f0.other, f0.otherK, time.Now().Add(365*24*time.Hour)))

	leaf, _ := crlCert(t, "crl.test", 0x2a, false, []string{url}, f0.root, f0.rootKey)
	checks := CheckCRLs(context.Background(), []*x509.Certificate{leaf, f0.root}, fetcher)
	if checks[0].Status != CRLGood || checks[0].Cached || hits.Load() != 1 {
		t.Errorf("status=%s cached=%v hits=%d, want good from one refetch", checks[0].Status, checks[0].Cached, hits.Load())
	}
}

func TestCRLFetcherDoesNotCacheACRLThatDoesNotVerify(t *testing.T) {
	f0 := newCRLFixture(t)
	url, _ := crlServer(t, http.StatusOK, makeCRL(t, f0.other, f0.otherK, time.Now().Add(time.Hour)))
	fetcher := &CRLFetcher{Dir: t.TempDir()}
	leaf, _ := crlCert(t, "crl.test", 0x2a, false, []string{url}, f0.root, f0.rootKey)
	CheckCRLs(context.Background(), []*x509.Certificate{leaf, f0.root}, fetcher)
	if _, err := os.Stat(fetcher.cachePath(url)); err == nil {
		t.Error("a CRL from the wrong issuer was written to the cache")
	}
}

func TestCRLFetcherRemembersWithinARun(t *testing.T) {
	f0 := newCRLFixture(t)
	dead, deadHits := crlServer(t, http.StatusServiceUnavailable, nil)
	live, _ := crlServer(t, http.StatusOK, makeCRL(t, f0.root, f0.rootKey, time.Now().Add(time.Hour)))
	dir := t.TempDir()
	leaf, _ := crlCert(t, "crl.test", 0x2a, false, []string{live}, f0.root, f0.rootKey)
	CheckCRLs(context.Background(), []*x509.Certificate{leaf, f0.root}, &CRLFetcher{Dir: dir})

	// A second run: the first target reads the disk cache, the second reuses
	// that answer and must still say it was cached.
	fetcher := &CRLFetcher{Dir: dir}
	for i := 0; i < 2; i++ {
		c := CheckCRLs(context.Background(), []*x509.Certificate{leaf, f0.root}, fetcher)
		if !c[0].Cached {
			t.Errorf("target %d: cached=false for an answer read from disk", i)
		}
	}

	// A dead endpoint is asked once per run, however many targets name it.
	down, _ := crlCert(t, "down.test", 0x2b, false, []string{dead}, f0.root, f0.rootKey)
	for i := 0; i < 3; i++ {
		CheckCRLs(context.Background(), []*x509.Certificate{down, f0.root}, fetcher)
	}
	if deadHits.Load() != 1 {
		t.Errorf("dead endpoint asked %d times, want 1", deadHits.Load())
	}
}

// idp builds an IssuingDistributionPoint extension.
func idp(t *testing.T, uris []string, onlyCA bool) pkix.Extension {
	t.Helper()
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		if len(uris) > 0 {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(0).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
					for _, u := range uris {
						b.AddASN1(cbasn1.Tag(6).ContextSpecific(), func(b *cryptobyte.Builder) {
							b.AddBytes([]byte(u))
						})
					}
				})
			})
		}
		if onlyCA {
			b.AddASN1(cbasn1.Tag(2).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddUint8(0xff) })
		}
	})
	der, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return pkix.Extension{Id: oidIssuingDistributionPoint, Critical: true, Value: der}
}

func TestCheckCRLsHonoursTheIssuingDistributionPoint(t *testing.T) {
	f0 := newCRLFixture(t)
	tests := []struct {
		name string
		ext  func(url string) pkix.Extension
		want string
	}{
		{"this shard", func(url string) pkix.Extension { return idp(t, []string{url}, false) }, CRLGood},
		{"another shard", func(string) pkix.Extension { return idp(t, []string{"http://ca.test/shard2.crl"}, false) }, CRLUnchecked},
		{"CA certificates only", func(string) pkix.Extension { return idp(t, nil, true) }, CRLUnchecked},
		{"delta", func(string) pkix.Extension {
			return pkix.Extension{Id: oidDeltaCRLIndicator, Critical: true, Value: []byte{0x02, 0x01, 0x01}}
		}, CRLUnchecked},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
			t.Cleanup(srv.Close)
			url := srv.URL + "/shard1.crl"
			der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
				Number:          big.NewInt(1),
				ThisUpdate:      time.Now().Add(-time.Hour),
				NextUpdate:      time.Now().Add(time.Hour),
				ExtraExtensions: []pkix.Extension{tt.ext(url)},
			}, f0.root, f0.rootKey)
			if err != nil {
				t.Fatal(err)
			}
			body = der

			leaf, _ := crlCert(t, "crl.test", 0x2a, false, []string{url}, f0.root, f0.rootKey)
			checks := CheckCRLs(context.Background(), []*x509.Certificate{leaf, f0.root}, &CRLFetcher{})
			if checks[0].Status != tt.want {
				t.Fatalf("status = %s (%v), want %s", checks[0].Status, checks[0].Err, tt.want)
			}
			if tt.want == CRLUnchecked {
				if got := crlProblems(checks, time.Now()); len(got) != 1 || got[0] != ProblemCRLOutOfScope {
					t.Errorf("problems = %v, want [%s]", got, ProblemCRLOutOfScope)
				}
			}
		})
	}
}

func TestAddCRLChecksJSON(t *testing.T) {
	now := time.Now()
	checks := []CRLCheck{
		{Subject: "crl.test", URL: "http://ca.test/ca.crl", Status: CRLRevoked, RevokedAt: now.Add(-time.Hour), RevocationReason: "key compromise", NextUpdate: now.Add(time.Hour)},
	}
	rev := AddCRLChecks(nil, checks, now)
	raw, err := json.Marshal(rev)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got["ok"] != false {
		t.Errorf("ok = %v, want false", got["ok"])
	}
	crl := got["crl"].([]any)[0].(map[string]any)
	if crl["status"] != "revoked" || crl["revocationReason"] != "key compromise" {
		t.Errorf("crl entry = %v", crl)
	}
	if f := got["findings"].([]any)[0].(map[string]any); f["problem"] != ProblemRevokedInCRL {
		t.Errorf("finding = %v", f)
	}

	// Asked for, nothing to check: the key is there, and empty.
	raw, _ = json.Marshal(AddCRLChecks(nil, []CRLCheck{}, now))
	if !strings.Contains(string(raw), `"crl":[]`) {
		t.Errorf("empty checks marshalled as %s, want crl: []", raw)
	}
	// Not asked for: nothing changes.
	if AddCRLChecks(nil, nil, now) != nil {
		t.Error("nil checks created a revocation object")
	}
}
