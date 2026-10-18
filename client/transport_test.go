package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A box calls a server over https, or over http only on this machine, and
// follows no redirect (PROTOCOL.md §0): neither its pass nor the address a
// lookup asks about goes in the clear, or anywhere a server points.

// elsewhere is a second server, on another port of this machine, that
// keeps what reaches it: where a redirect points.
type elsewhere struct {
	URL  string
	mu   sync.Mutex
	seen []string
}

func newElsewhere(t *testing.T) *elsewhere {
	t.Helper()
	x := &elsewhere{}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		x.mu.Lock()
		x.seen = append(x.seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		x.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	t.Cleanup(s.Close)
	x.URL = s.URL
	return x
}

func (x *elsewhere) reached() []string {
	x.mu.Lock()
	defer x.mu.Unlock()
	return append([]string(nil), x.seen...)
}

// redirect answers each request whose method and path match with a
// redirect of the given status to the same path at to.
func redirect(e *env, status int, to, method string, match func(path string) bool) {
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == method && match(r.URL.Path) {
			http.Redirect(w, r, to+r.URL.RequestURI(), status)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isRedirect reports whether err is the redirect a box was answered, which
// it did not follow.
func isRedirect(err error, status int) bool {
	var apiErr *client.APIError
	return errors.As(err, &apiErr) && apiErr.Status == status && strings.Contains(err.Error(), "a redirect, which this client never follows")
}

// The issue's repro: a 307 from a box's list, to another port of the same
// host, which Go's own policy would follow with the box's pass. Nothing
// reaches the other server, whether the box made its HTTP client or was
// handed one, and the client it was handed is left as it was.
func TestARedirectIsNeverFollowed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	x := newElsewhere(t)
	redirect(e, http.StatusTemporaryRedirect, x.URL, http.MethodGet, func(p string) bool { return strings.HasSuffix(p, "/messages") })
	if _, err := b.Receive(ctx); !isRedirect(err, http.StatusTemporaryRedirect) {
		t.Fatalf("a drain answered with a redirect: %v", err)
	}
	given := &http.Client{}
	opt := e.opts()
	opt.HTTPClient = given
	handed, err := client.Open(b.Dir(), opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handed.Receive(ctx); !isRedirect(err, http.StatusTemporaryRedirect) {
		t.Fatalf("a drain by a box handed an HTTP client that follows redirects: %v", err)
	}
	if given.CheckRedirect != nil {
		t.Fatal("the HTTP client the box was handed was changed")
	}
	if got := x.reached(); len(got) != 0 {
		t.Fatalf("a redirect was followed: %q", got)
	}
}

// Every call a box makes is held to it: the read of a recipient before a
// send, and the send itself, for each status a redirect has. A send that
// is redirected posts nothing anywhere, and waits in the outbox.
func TestNoCallOfABoxFollowsARedirect(t *testing.T) {
	ctx := context.Background()
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		e := newEnv(t)
		a, r := e.box(protocol.Classic), e.box(protocol.Classic)
		x := newElsewhere(t)
		redirect(e, status, x.URL, http.MethodGet, func(p string) bool { return p == "/v1/"+r.Address().String() })
		if _, err := a.Send(ctx, r.Address(), "never posted"); !isRedirect(err, status) {
			t.Fatalf("%d on the read of the recipient: %v", status, err)
		}
		redirect(e, status, x.URL, http.MethodPost, func(p string) bool { return strings.HasSuffix(p, "/messages") })
		if _, err := a.Send(ctx, r.Address(), "never posted"); !isRedirect(err, status) {
			t.Fatalf("%d on the post: %v", status, err)
		}
		if got := x.reached(); len(got) != 0 {
			t.Fatalf("%d was followed: %q", status, got)
		}
		if n := e.srv.Count(r.Address()); n != 0 {
			t.Fatalf("%d: the recipient's server holds %d messages", status, n)
		}
	}
}

// A revocation server that redirects is a revocation server that gave no
// answer: the lookup, which names the address asked about, goes nowhere
// else, and the send goes on.
func TestARevocationServersRedirectIsNoAnswer(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	rs := newRevServer(t)
	x := newElsewhere(t)
	rs.set(func(w http.ResponseWriter, r *http.Request) bool {
		http.Redirect(w, r, x.URL+r.URL.RequestURI(), http.StatusFound)
		return true
	})
	opt := e.opts()
	opt.RevocationServers = []string{rs.URL}
	var silent []error
	opt.NoAnswer = func(_ string, err error) { silent = append(silent, err) }
	a, err := client.Init(ctx, t.TempDir(), opt, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, a)
	r := e.box(protocol.Classic)
	if _, err := a.Send(ctx, r.Address(), "posted"); err != nil {
		t.Fatalf("a send whose revocation server redirects: %v", err)
	}
	if len(silent) == 0 || !isRedirect(silent[0], http.StatusFound) {
		t.Fatalf("what the box was told of the revocation server: %v", silent)
	}
	if got := x.reached(); len(got) != 0 {
		t.Fatalf("the revocation server's redirect was followed: %q", got)
	}
}

// recorder is an HTTP client's transport that counts the requests it is
// asked to make, and makes none.
type recorder struct {
	mu sync.Mutex
	n  int
}

func (rt *recorder) RoundTrip(*http.Request) (*http.Response, error) {
	rt.mu.Lock()
	rt.n++
	rt.mu.Unlock()
	return nil, errors.New("no network here")
}

// A server's URL is https, or http only on this machine. Any other is
// refused before anything is sent or made: no request, and no box
// directory. The box's own server and a revocation server are held to the
// one rule.
func TestAServerIsCalledOverHTTPSOrOnThisMachine(t *testing.T) {
	ctx := context.Background()
	const refusal = "is not a server this client calls"
	// Publish needs no box, so only the check of each call holds it.
	rec, err := newEnv(t).box(protocol.Classic).Revocation()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"http://example.com", "http://irongall:8080", "http://10.0.0.1:8080", "http://172.28.0.2:8080",
		"http://127.0.0.1.example", "http://localhost.example", "http://localhost:8080", "http://LOCALHOST", "http://[::2]:8080", "http://[::ffff:127.0.0.1]:8080",
		"http://0:0:0:0:0:0:0:1", "ftp://irongall.dev", "irongall.dev", "https://", "http://", "",
	} {
		rt := &recorder{}
		dir := filepath.Join(t.TempDir(), "box")
		opt := client.Options{Base: u, HTTPClient: &http.Client{Transport: rt}}
		if u == "" {
			opt.Base = " "
		}
		if _, err := client.Init(ctx, dir, opt, protocol.Classic); err == nil || !strings.Contains(err.Error(), refusal) {
			t.Errorf("%q: Init: %v", u, err)
		}
		if exists(dir) {
			t.Errorf("%q: Init made the box's directory", u)
		}
		if _, err := client.Open(t.TempDir(), opt); err == nil || !strings.Contains(err.Error(), refusal) {
			t.Errorf("%q: Open: %v", u, err)
		}
		if _, err := client.Publish(ctx, opt, rec); err == nil || !strings.Contains(err.Error(), refusal) {
			t.Errorf("%q: Publish: %v", u, err)
		}
		if rt.n != 0 {
			t.Errorf("%q: %d requests made", u, rt.n)
		}
	}
	for _, u := range []string{
		"https://irongall.dev", "HTTPS://irongall.dev", "https://10.0.0.1:8443",
		"http://127.0.0.1:1", "http://127.255.0.9", "http://[::1]:1", "http://someone@127.0.0.1:1",
	} {
		rt := &recorder{}
		_, err := client.Init(ctx, t.TempDir(), client.Options{Base: u, HTTPClient: &http.Client{Transport: rt}}, protocol.Classic)
		if err == nil || strings.Contains(err.Error(), refusal) || rt.n == 0 {
			t.Errorf("%q: Init made %d requests: %v", u, rt.n, err)
		}
	}
	// The revocation servers, whether Options or a list names them.
	for _, s := range []string{"http://example.com", "http://irongall:8080", "http://localhost:8080"} {
		if _, err := client.ParseRevocationServers(s); err == nil {
			t.Errorf("%q was taken as a revocation server", s)
		}
		b, err := client.Open(newEnv(t).box(protocol.Classic).Dir(), client.Options{RevocationServers: []string{s}})
		if err != nil {
			t.Fatal(err)
		}
		if got, err := b.RevocationServers(); err == nil {
			t.Errorf("%q was listed: %q", s, got)
		}
	}
	for _, s := range []string{"https://revocations.example", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		if got, err := client.ParseRevocationServers(s); err != nil || len(got) != 1 {
			t.Errorf("%q: %q, %v", s, got, err)
		}
	}
}
