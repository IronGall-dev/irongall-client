package revocationserver_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/IronGall-dev/irongall-client/revocationserver"
	"golang.org/x/crypto/ssh"
)

// The revocation server is tested over HTTP, as a client meets it. Every
// record here is made with the protocol package, as a client makes one, and
// what the server serves is checked with it again.

// who is an identity: its key, its document and its address.
type who struct {
	signer ssh.Signer
	doc    []byte
	addr   protocol.Address
}

func newWho(t *testing.T) *who {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return whoOf(t, priv)
}

func whoOf(t *testing.T, key any) *who {
	t.Helper()
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.IdentityOf(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	return &who{signer: signer, doc: id.Document(), addr: id.Address()}
}

// revocation returns the record that revokes the address.
func (p *who) revocation(t *testing.T) *protocol.Revocations {
	t.Helper()
	sig, err := protocol.SignRevocation(p.signer, p.addr)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Revocations{Identity: p.doc, Revocation: sig}
}

// list returns the record that carries a list of the address's revoked
// certificates: the serials first to last, under a version.
func (p *who) list(t *testing.T, version, first, last uint64) *protocol.Revocations {
	t.Helper()
	l, err := protocol.NewRevokedCertificates(p.addr, version, []protocol.SerialRange{{First: first, Last: last}})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.SignRevokedCertificates(p.signer, l)
	if err != nil {
		t.Fatal(err)
	}
	return &protocol.Revocations{Identity: p.doc, RevokedCertificates: l.Statement(), RevokedCertificatesSignature: sig}
}

// clock is a clock a test sets.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// server is a revocation server over a directory, served on loopback.
type server struct {
	t     *testing.T
	x     *revocationserver.Server
	srv   *httptest.Server
	clock *clock
	dir   string
}

// start opens a revocation server with no write limit, unless set says
// otherwise.
func start(t *testing.T, set func(*revocationserver.Options)) *server {
	t.Helper()
	s := &server{t: t, clock: &clock{t: time.Unix(1_800_000_000, 0)}, dir: t.TempDir()}
	s.open(set)
	t.Cleanup(s.close)
	return s
}

func (s *server) open(set func(*revocationserver.Options)) {
	s.t.Helper()
	opt := revocationserver.Options{Dir: s.dir, WritesPerHour: -1, Now: s.clock.Now}
	if set != nil {
		set(&opt)
	}
	x, err := revocationserver.Open(opt)
	if err != nil {
		s.t.Fatalf("open: %v", err)
	}
	s.x, s.srv = x, httptest.NewServer(x.Handler())
}

func (s *server) close() {
	if s.srv != nil {
		s.srv.Close()
		_ = s.x.Close()
		s.srv = nil
	}
}

// answer is what a call returned.
type answer struct {
	status int
	code   protocol.Code
	header http.Header
	body   []byte
}

func (s *server) do(method, path string, body []byte, hdr ...string) answer {
	s.t.Helper()
	req, err := http.NewRequest(method, s.srv.URL+path, bytes.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read fully below
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatal(err)
	}
	a := answer{status: resp.StatusCode, header: resp.Header, body: data}
	if resp.StatusCode > 299 {
		var p protocol.Problem
		_ = json.Unmarshal(data, &p)
		a.code = p.Code
	}
	return a
}

func path(a protocol.Address) string { return "/v1/" + a.String() + "/revocations" }

func (s *server) put(a protocol.Address, rec *protocol.Revocations, hdr ...string) answer {
	s.t.Helper()
	j, err := json.Marshal(rec)
	if err != nil {
		s.t.Fatal(err)
	}
	return s.do(http.MethodPut, path(a), j, hdr...)
}

// held returns the record the server serves for a, or nil when it answers
// that it holds none.
func (s *server) held(a protocol.Address) *protocol.Revocations {
	s.t.Helper()
	got := s.do(http.MethodGet, path(a), nil)
	if got.status == http.StatusNotFound && got.code == protocol.CodeNotRevoked {
		return nil
	}
	if got.status != http.StatusOK {
		s.t.Fatalf("GET: %d %s", got.status, got.code)
	}
	var rec protocol.Revocations
	if err := json.Unmarshal(got.body, &rec); err != nil {
		s.t.Fatal(err)
	}
	return &rec
}

func want(t *testing.T, got answer, status int, code protocol.Code) {
	t.Helper()
	if got.status != status || got.code != code {
		t.Fatalf("got %d %q, want %d %q (%s)", got.status, got.code, status, code, got.body)
	}
}

func TestARevocationIsKeptAndServed(t *testing.T) {
	s := start(t, nil)
	p := newWho(t)

	// Nothing held is an answer of its own, and never "no such mailbox": a
	// revocation server has no boxes.
	got := s.do(http.MethodGet, path(p.addr), nil)
	want(t, got, http.StatusNotFound, protocol.CodeNotRevoked)
	if cc := got.header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("a 404 that a cache may keep: Cache-Control %q", cc)
	}

	rec := p.revocation(t)
	want(t, s.put(p.addr, rec), http.StatusCreated, "")
	served := s.held(p.addr)
	if served == nil {
		t.Fatal("kept, and not served")
	}
	if _, err := protocol.VerifyRevocation(p.addr, served.Identity, served.Revocation); err != nil {
		t.Fatalf("what the server serves does not verify: %v", err)
	}
	if got := s.do(http.MethodGet, path(p.addr), nil); got.header.Get("Cache-Control") != "no-store" {
		t.Fatal("a record a cache may keep")
	}
	// The same record again changes nothing.
	want(t, s.put(p.addr, rec), http.StatusOK, "")
	// An address in capitals is the same address.
	if got := s.do(http.MethodGet, "/v1/"+strings.ToUpper(p.addr.String())+"/revocations", nil); got.status != http.StatusOK {
		t.Fatalf("the address in capitals: %d", got.status)
	}

	// It is on disk: a server opened again on the directory serves it.
	s.close()
	s.open(nil)
	if s.x.Held() != 1 {
		t.Fatalf("after a restart the server holds %d addresses, want 1", s.x.Held())
	}
	if served := s.held(p.addr); served == nil || !bytes.Equal(served.Revocation, rec.Revocation) {
		t.Fatal("a restart lost the record")
	}
}

func TestWhatDoesNotVerifyIsNotKept(t *testing.T) {
	s := start(t, nil)
	p, other := newWho(t), newWho(t)

	// Another identity's signature over this address's statement.
	sig, err := protocol.SignRevocation(other.signer, p.addr)
	if err != nil {
		t.Fatal(err)
	}
	want(t, s.put(p.addr, &protocol.Revocations{Identity: p.doc, Revocation: sig}), http.StatusBadRequest, protocol.CodeBadRevocation)
	// A record of another address, good in itself.
	want(t, s.put(p.addr, other.revocation(t)), http.StatusBadRequest, protocol.CodeIdentityMismatch)
	// A good revocation with a list whose signature is not the list's:
	// everything is checked before anything is kept.
	both := p.revocation(t)
	both.RevokedCertificates = p.list(t, 1, 1, 3).RevokedCertificates
	both.RevokedCertificatesSignature = p.list(t, 2, 1, 3).RevokedCertificatesSignature
	want(t, s.put(p.addr, both), http.StatusBadRequest, protocol.CodeBadRevocation)
	// A good list with a revocation that is not one.
	both = p.list(t, 1, 1, 3)
	both.Revocation = sig
	want(t, s.put(p.addr, both), http.StatusBadRequest, protocol.CodeBadRevocation)

	if s.held(p.addr) != nil || s.x.Held() != 0 {
		t.Fatal("something that did not verify was kept")
	}
}

func TestWhatIsNotARecordIsRefused(t *testing.T) {
	s := start(t, func(o *revocationserver.Options) { o.MaxBody = 4096 })
	p := newWho(t)
	good, err := json.Marshal(p.revocation(t))
	if err != nil {
		t.Fatal(err)
	}
	list := p.list(t, 1, 1, 3)
	for name, c := range map[string]struct {
		body string
		code protocol.Code
	}{
		"no identity":            {`{"revocation":"AAAA"}`, protocol.CodeBadRequest},
		"nothing signed":         {`{"identity":"AAAA"}`, protocol.CodeBadRequest},
		"a list, no signature":   {`{"identity":"AAAA","revoked_certificates":"AAAA"}`, protocol.CodeBadRequest},
		"a signature, no list":   {`{"identity":"AAAA","revoked_certificates_signature":"AAAA"}`, protocol.CodeBadRequest},
		"an unknown member":      {`{"identity":"AAAA","revocation":"AAAA","reason":"x"}`, protocol.CodeBadRequest},
		"two values":             {string(good) + string(good), protocol.CodeBadRequest},
		"not JSON":               {`revoke it`, protocol.CodeBadRequest},
		"not base64":             {`{"identity":"!","revocation":"AAAA"}`, protocol.CodeBadEncoding},
		"over the largest body":  {`{"identity":"` + strings.Repeat("A", 8192) + `"}`, protocol.CodeTooLarge},
		"an empty list is a bad": {`{"identity":"` + b64(p.doc) + `","revoked_certificates":"","revoked_certificates_signature":"` + b64(list.RevokedCertificatesSignature) + `"}`, protocol.CodeBadRevocation},
	} {
		got := s.do(http.MethodPut, path(p.addr), []byte(c.body))
		if got.status != c.code.Status() || got.code != c.code {
			t.Errorf("%s: got %d %q, want %d %q", name, got.status, got.code, c.code.Status(), c.code)
		}
	}
	want(t, s.do(http.MethodPut, "/v1/not-an-address/revocations", good), http.StatusBadRequest, protocol.CodeBadAddress)
	want(t, s.do(http.MethodGet, "/v1/not-an-address/revocations", nil), http.StatusBadRequest, protocol.CodeBadAddress)
	if s.x.Held() != 0 {
		t.Fatal("something that is no record was kept")
	}
}

func b64(b []byte) string {
	j, _ := json.Marshal(protocol.Bytes(b))
	return strings.Trim(string(j), `"`)
}

func TestAListTheHighestVersionStands(t *testing.T) {
	s := start(t, nil)
	p := newWho(t)

	v1, v2 := p.list(t, 1, 1, 3), p.list(t, 2, 1, 5)
	want(t, s.put(p.addr, v1), http.StatusOK, "")
	served := s.held(p.addr)
	if served == nil || served.Revocation != nil {
		t.Fatal("a list alone: the address goes on, and the list is served")
	}
	l, err := protocol.VerifyRevokedCertificates(p.addr, served.Identity, served.RevokedCertificates, served.RevokedCertificatesSignature)
	if err != nil || l.Version != 1 || !l.Revokes(3) || l.Revokes(4) {
		t.Fatalf("the list served: %v, %+v", err, l)
	}
	want(t, s.put(p.addr, v2), http.StatusOK, "")
	// An older list never replaces a newer one, and neither does another
	// list of the version held.
	want(t, s.put(p.addr, v1), http.StatusConflict, protocol.CodeConflict)
	want(t, s.put(p.addr, p.list(t, 2, 1, 9)), http.StatusConflict, protocol.CodeConflict)
	// The list held, again, changes nothing.
	want(t, s.put(p.addr, v2), http.StatusOK, "")
	if served := s.held(p.addr); !bytes.Equal(served.RevokedCertificates, v2.RevokedCertificates) || !bytes.Equal(served.RevokedCertificatesSignature, v2.RevokedCertificatesSignature) {
		t.Fatal("the list held is not version 2 as it was signed")
	}
}

// What is held is answered again with nothing checked, and only that: a part
// sent empty is no part held, whatever is or is not held beside it.
func TestAnEmptyPartIsNotAPartHeld(t *testing.T) {
	s := start(t, nil)
	p, q := newWho(t), newWho(t)
	want(t, s.put(p.addr, p.list(t, 1, 1, 3)), http.StatusOK, "")
	want(t, s.put(q.addr, q.revocation(t)), http.StatusCreated, "")
	rev := b64(q.revocation(t).Revocation)
	for name, c := range map[string]struct {
		addr protocol.Address
		body string
	}{
		"an empty revocation, of an address with a list held":         {p.addr, `{"identity":"` + b64(p.doc) + `","revocation":""}`},
		"an empty list, with the revocation held":                     {q.addr, `{"identity":"` + b64(q.doc) + `","revocation":"` + rev + `","revoked_certificates":"","revoked_certificates_signature":""}`},
		"an empty signature on the list held":                         {p.addr, `{"identity":"` + b64(p.doc) + `","revoked_certificates":"` + b64(p.list(t, 1, 1, 3).RevokedCertificates) + `","revoked_certificates_signature":""}`},
		"an empty revocation beside the list held, signature and all": {p.addr, `{"identity":"` + b64(p.doc) + `","revocation":"","revoked_certificates":"` + b64(p.list(t, 1, 1, 3).RevokedCertificates) + `","revoked_certificates_signature":"` + b64(p.list(t, 1, 1, 3).RevokedCertificatesSignature) + `"}`},
	} {
		got := s.do(http.MethodPut, path(c.addr), []byte(c.body))
		if got.status != http.StatusBadRequest || got.code != protocol.CodeBadRevocation {
			t.Errorf("%s: got %d %q, want 400 bad_revocation", name, got.status, got.code)
		}
	}
	if served := s.held(p.addr); served.Revocation != nil {
		t.Fatal("an empty revocation was kept")
	}
}

func TestARevokedAddressTakesNoList(t *testing.T) {
	s := start(t, nil)
	p := newWho(t)

	// A list first, then the revocation: both are held, as a mailbox server
	// holds both.
	want(t, s.put(p.addr, p.list(t, 1, 1, 3)), http.StatusOK, "")
	want(t, s.put(p.addr, p.revocation(t)), http.StatusCreated, "")
	if served := s.held(p.addr); served.Revocation == nil || served.RevokedCertificates == nil {
		t.Fatal("the revocation replaced the list")
	}
	// A list for a revoked address, whether or not it verifies.
	want(t, s.put(p.addr, p.list(t, 2, 1, 5)), http.StatusGone, protocol.CodeRevoked)
	junk := p.list(t, 3, 1, 5)
	junk.RevokedCertificatesSignature = []byte("no signature")
	want(t, s.put(p.addr, junk), http.StatusGone, protocol.CodeRevoked)
	// With the revocation beside it the body is taken, and the list is not.
	both := p.list(t, 2, 1, 5)
	both.Revocation = p.revocation(t).Revocation
	want(t, s.put(p.addr, both), http.StatusOK, "")
	l, err := protocol.ParseRevokedCertificates(s.held(p.addr).RevokedCertificates)
	if err != nil || l.Version != 1 {
		t.Fatalf("a revoked address took a list: %v, %+v", err, l)
	}
}

func TestOneBodyMayCarryBoth(t *testing.T) {
	s := start(t, nil)
	p := newWho(t)
	both := p.list(t, 1, 1, 3)
	both.Revocation = p.revocation(t).Revocation
	want(t, s.put(p.addr, both), http.StatusCreated, "")
	served := s.held(p.addr)
	if served.Revocation == nil || served.RevokedCertificates == nil {
		t.Fatal("one body with both, and not both kept")
	}
}

func TestAP256IdentitysRecord(t *testing.T) {
	s := start(t, nil)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := whoOf(t, key)
	want(t, s.put(p.addr, p.revocation(t)), http.StatusCreated, "")
	// Another signature of the same key over the same statement is other
	// bytes, and as good: it is checked, and changes nothing.
	again := p.revocation(t)
	want(t, s.put(p.addr, again), http.StatusOK, "")
	if served := s.held(p.addr); bytes.Equal(served.Revocation, again.Revocation) {
		t.Fatal("a second signature replaced the one kept")
	}
}

func TestWritesAreLimitedForEachCaller(t *testing.T) {
	s := start(t, func(o *revocationserver.Options) {
		o.WritesPerHour = 2
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}
		o.ClientIPHeader = "X-Caller"
	})
	a, b, c, d := newWho(t), newWho(t), newWho(t), newWho(t)
	one := []string{"X-Caller", "192.0.2.1"}

	// What does not verify counts as what does: each costs a check.
	junk := a.revocation(t)
	junk.Revocation = []byte("no signature")
	want(t, s.put(a.addr, junk, one...), http.StatusBadRequest, protocol.CodeBadRevocation)
	want(t, s.put(a.addr, a.revocation(t), one...), http.StatusCreated, "")
	got := s.put(b.addr, b.revocation(t), one...)
	want(t, got, http.StatusTooManyRequests, protocol.CodeRateLimited)
	if got.header.Get("Retry-After") != "3600" {
		t.Fatalf("Retry-After %q, want the hour the caller's window has left", got.header.Get("Retry-After"))
	}
	if s.held(b.addr) != nil {
		t.Fatal("a record past the limit was kept")
	}
	// What is held, sent again, is answered with nothing checked, so it is
	// not counted and not refused.
	want(t, s.put(a.addr, a.revocation(t), one...), http.StatusOK, "")
	// Another caller has its own count, and so has each IPv6 /64.
	want(t, s.put(b.addr, b.revocation(t), "X-Caller", "192.0.2.2"), http.StatusCreated, "")
	want(t, s.put(c.addr, c.revocation(t), "X-Caller", "2001:db8:0:1::1"), http.StatusCreated, "")
	want(t, s.put(c.addr, c.list(t, 1, 1, 2), "X-Caller", "2001:db8:0:1::2"), http.StatusGone, protocol.CodeRevoked)
	want(t, s.put(d.addr, d.list(t, 1, 1, 2), "X-Caller", "2001:db8:0:1::3"), http.StatusOK, "")
	want(t, s.put(d.addr, d.list(t, 2, 1, 2), "X-Caller", "2001:db8:0:1:ffff::4"), http.StatusTooManyRequests, protocol.CodeRateLimited)
	want(t, s.put(d.addr, d.list(t, 2, 1, 2), "X-Caller", "2001:db8:0:2::1"), http.StatusOK, "")
	// The window closes an hour after the caller's first.
	s.clock.Add(time.Hour - time.Second)
	want(t, s.put(d.addr, d.list(t, 3, 1, 2), one...), http.StatusTooManyRequests, protocol.CodeRateLimited)
	s.clock.Add(time.Second)
	want(t, s.put(d.addr, d.list(t, 3, 1, 2), one...), http.StatusOK, "")
}

func TestACallersNameIsTakenOnlyFromATrustedProxy(t *testing.T) {
	// The peer is loopback, and here it is not trusted: whatever the header
	// says, every call counts against the peer.
	s := start(t, func(o *revocationserver.Options) {
		o.WritesPerHour = 1
		o.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
		o.ClientIPHeader = "X-Caller"
	})
	a, b := newWho(t), newWho(t)
	want(t, s.put(a.addr, a.revocation(t), "X-Caller", "192.0.2.1"), http.StatusCreated, "")
	want(t, s.put(b.addr, b.revocation(t), "X-Caller", "192.0.2.2"), http.StatusTooManyRequests, protocol.CodeRateLimited)
}

func TestAFullServerTakesOnlyWhatItHolds(t *testing.T) {
	s := start(t, func(o *revocationserver.Options) { o.MaxAddresses = 1 })
	a, b := newWho(t), newWho(t)
	want(t, s.put(a.addr, a.list(t, 1, 1, 3)), http.StatusOK, "")
	got := s.put(b.addr, b.revocation(t))
	want(t, got, http.StatusServiceUnavailable, protocol.CodeUnavailable)
	if got.header.Get("Retry-After") == "" {
		t.Fatal("a 503 with no Retry-After")
	}
	if s.held(b.addr) != nil {
		t.Fatal("a full server kept another address")
	}
	// An address it holds is still served and still updated: its revocation
	// is the one that must never be turned away.
	want(t, s.put(a.addr, a.list(t, 2, 1, 5)), http.StatusOK, "")
	want(t, s.put(a.addr, a.revocation(t)), http.StatusCreated, "")
	if served := s.held(a.addr); served == nil || served.Revocation == nil {
		t.Fatal("a full server did not take the revocation of an address it holds")
	}
}

func TestAFileThatIsNoRecordIsAnError(t *testing.T) {
	s := start(t, nil)
	p := newWho(t)
	want(t, s.put(p.addr, p.revocation(t)), http.StatusCreated, "")
	name := filepath.Join(s.dir, p.addr.String()[:2], p.addr.String()+".json")
	if err := os.WriteFile(name, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Never a quiet "nothing held": the server held one.
	want(t, s.do(http.MethodGet, path(p.addr), nil), http.StatusServiceUnavailable, protocol.CodeUnavailable)
	want(t, s.put(p.addr, p.list(t, 1, 1, 3)), http.StatusServiceUnavailable, protocol.CodeUnavailable)
}

func TestOnlyItsOwnFilesAreRecords(t *testing.T) {
	dir := t.TempDir()
	p := newWho(t)
	h := p.addr.String()
	// A record's name in the wrong directory, and a name that is no address.
	for _, n := range []string{filepath.Join("zz", h+".json"), filepath.Join(h[:2], "notes.json")} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(n)), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	x, err := revocationserver.Open(revocationserver.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer x.Close() //nolint:errcheck // a test
	if x.Held() != 0 {
		t.Fatalf("the server counts %d addresses in a directory that holds no record", x.Held())
	}
}

func TestOneProcessToADirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no flock")
	}
	s := start(t, nil)
	if x, err := revocationserver.Open(revocationserver.Options{Dir: s.dir}); err == nil {
		_ = x.Close()
		t.Fatal("a second server opened a directory in use")
	}
}

func TestTheRootSaysWhatItIs(t *testing.T) {
	s := start(t, nil)
	got := s.do(http.MethodGet, "/", nil)
	if got.status != http.StatusOK || !strings.Contains(string(got.body), "revocation server") || !strings.Contains(string(got.body), "lists nothing") {
		t.Fatalf("GET /: %d %s", got.status, got.body)
	}
	// It lists nothing: there is no other route.
	p := newWho(t)
	want(t, s.put(p.addr, p.revocation(t)), http.StatusCreated, "")
	for _, path := range []string{"/v1/", "/v1/revocations", "/v1/" + p.addr.String(), "/v1/" + p.addr.String() + "/identity"} {
		if got := s.do(http.MethodGet, path, nil); got.status != http.StatusNotFound || strings.Contains(string(got.body), p.addr.String()) {
			t.Errorf("GET %s: %d %s", path, got.status, got.body)
		}
	}
	if got := s.do(http.MethodDelete, path(p.addr), nil); got.status != http.StatusMethodNotAllowed {
		t.Errorf("DELETE of a record: %d", got.status)
	}
	if s.held(p.addr) == nil {
		t.Fatal("the record is gone")
	}
}

// The address of a record is the hash of its identity document: a test that
// made its own would prove nothing.
func TestTheAddressIsTheDocumentsHash(t *testing.T) {
	p := newWho(t)
	if protocol.Address(sha256.Sum256(p.doc)) != p.addr {
		t.Fatal("the test's identity is not its address")
	}
}
