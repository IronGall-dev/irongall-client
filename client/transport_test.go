package client_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A box calls a server over https, or over http only on this machine, and
// follows no redirect (PROTOCOL.md §11.1): neither its pass nor the address a
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

// redirects are the statuses of a redirect, each of which a client is held
// to, from every call it makes (PROTOCOL.md §11.1).
var redirects = []int{http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther, http.StatusTemporaryRedirect, http.StatusPermanentRedirect}

// A redirect from a box's list, to another port of the same host, which Go's
// own policy would follow with the box's pass. Nothing reaches the other
// server, whether the box made its HTTP client or was handed one, and the
// client it was handed is left as it was.
func TestARedirectIsNeverFollowed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, status := range redirects {
		e := newEnv(t)
		b := e.box(protocol.Classic)
		x := newElsewhere(t)
		redirect(e, status, x.URL, http.MethodGet, func(p string) bool { return strings.HasSuffix(p, "/messages") })
		if _, err := b.Receive(ctx); !isRedirect(err, status) {
			t.Fatalf("a drain answered with a %d: %v", status, err)
		}
		given := &http.Client{}
		opt := e.opts()
		opt.HTTPClient = given
		handed, err := client.Open(b.Dir(), opt)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := handed.Receive(ctx); !isRedirect(err, status) {
			t.Fatalf("a drain answered with a %d by a box handed an HTTP client that follows redirects: %v", status, err)
		}
		if given.CheckRedirect != nil {
			t.Fatal("the HTTP client the box was handed was changed")
		}
		if got := x.reached(); len(got) != 0 {
			t.Fatalf("%d was followed: %q", status, got)
		}
	}
}

// Every call a box makes is held to it: the read of a recipient before a
// send, and the send itself, for each status a redirect has. A send that
// is redirected posts nothing anywhere, and waits in the outbox.
func TestNoCallOfABoxFollowsARedirect(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, status := range redirects {
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

// A record the box's server redirects is not taken there: the owner is told,
// and the record goes nowhere else.
func TestARedirectedPublishIsNotTaken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, status := range redirects {
		e := newEnv(t)
		x := newElsewhere(t)
		b := e.box(protocol.Classic)
		rec, err := b.Revocation(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		redirect(e, status, x.URL, http.MethodPut, func(p string) bool { return strings.HasSuffix(p, "/revocations") })
		if _, err := b.Revoke(ctx, rec); !isRedirect(err, status) {
			t.Fatalf("%d from the box's server: %v", status, err)
		}
		if got := x.reached(); len(got) != 0 {
			t.Fatalf("a publish's %d was followed: %q", status, got)
		}
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
// directory.
func TestAServerIsCalledOverHTTPSOrOnThisMachine(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const refusal = "is not a server this client calls"
	// Publish and Revoke need no box, so only the check of each call holds
	// them.
	rec, err := newEnv(t).box(protocol.Classic).Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{
		"http://example.com", "http://dromas:8080", "http://10.0.0.1:8080", "http://172.28.0.2:8080",
		"http://127.0.0.1.example", "http://localhost.example", "http://localhost:8080", "http://LOCALHOST", "http://[::2]:8080", "http://[::ffff:127.0.0.1]:8080",
		"http://0:0:0:0:0:0:0:1", "ftp://dromas.dev", "dromas.dev", "https://", "http://", "",
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
		if _, err := client.Revoke(ctx, opt, rec); err == nil || !strings.Contains(err.Error(), refusal) {
			t.Errorf("%q: Revoke: %v", u, err)
		}
		if rt.n != 0 {
			t.Errorf("%q: %d requests made", u, rt.n)
		}
	}
	for _, u := range []string{
		"https://dromas.dev", "HTTPS://dromas.dev", "https://10.0.0.1:8443",
		"http://127.0.0.1:1", "http://127.255.0.9", "http://[::1]:1", "http://someone@127.0.0.1:1",
	} {
		rt := &recorder{}
		_, err := client.Init(ctx, t.TempDir(), client.Options{Base: u, HTTPClient: &http.Client{Transport: rt}}, protocol.Classic)
		if err == nil || strings.Contains(err.Error(), refusal) || rt.n == 0 {
			t.Errorf("%q: Init made %d requests: %v", u, rt.n, err)
		}
	}
}

// A call that got no answer it could read says which call and what kind of
// failure, in this client's own words, and keeps net/http's error for
// errors.Is and errors.As (PROTOCOL.md §11.3): a server that is not there, one
// that never answers, a wait the caller ended, and a certificate that does
// not verify, a server's TLS alert, and an answer that is no TLS.
func TestACallWithNoAnswerSaysWhatKind(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	to := e.box(protocol.Classic)
	read := "GET /v1/" + to.Address().String() + ": "
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "http://" + l.Addr().String()
	_ = l.Close()
	silent := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	t.Cleanup(silent.Close)
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(untrusted.Close)
	// A server the box trusts that ends the handshake with an alert: it asks
	// for a client certificate, and the box has none.
	alerting := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	alerting.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS13}
	alerting.StartTLS()
	t.Cleanup(alerting.Close)
	// A server that answers neither TLS nor HTTP. It reads the whole of the
	// client's first record, a ClientHello larger than any small buffer
	// (1,505 bytes from Go 1.27's), before it answers: a socket closed with
	// bytes unread sends a reset, which on Windows can discard the answer
	// before the client reads it.
	garbled, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = garbled.Close() })
	go func() {
		for {
			c, err := garbled.Accept()
			if err != nil {
				return
			}
			hdr := make([]byte, 5)
			if _, err := io.ReadFull(c, hdr); err == nil {
				_, _ = io.CopyN(io.Discard, c, int64(binary.BigEndian.Uint16(hdr[3:])))
			}
			_, _ = c.Write([]byte("\x00\x01\x02\x03\x04 neither TLS nor HTTP\r\n"))
			_ = c.Close()
		}
	}()
	stopped, stop := context.WithCancel(context.Background())
	stop()
	waited, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	for _, c := range []struct {
		name, base, kind string
		ctx              context.Context
		is               error
		http             *http.Client
	}{
		{"a server that is not there", closed, "could not connect", context.Background(), nil, nil},
		{"a server that never answers", silent.URL, "no answer within the wait", waited, context.DeadlineExceeded, nil},
		{"a call its caller stopped", silent.URL, "stopped before an answer came", stopped, context.Canceled, nil},
		{"a certificate that does not verify", untrusted.URL, "the server's TLS certificate does not verify", context.Background(), nil, nil},
		{"a server's TLS alert", alerting.URL, "TLS failed", context.Background(), nil, alerting.Client()},
		{"a server that answers neither TLS nor HTTP", "https://" + garbled.Addr().String(), "TLS failed", context.Background(), nil, nil},
	} {
		opt := e.opts()
		opt.Base = c.base
		if c.http != nil {
			opt.HTTPClient = c.http
		}
		at, err := client.Open(b.Dir(), opt)
		if err != nil {
			t.Fatal(err)
		}
		_, err = at.Send(c.ctx, to.Address(), "x")
		var dial *net.OpError
		if err == nil || !strings.Contains(err.Error(), read+c.kind) || c.is != nil && !errors.Is(err, c.is) || c.base == closed && !errors.As(err, &dial) {
			t.Errorf("%s: %v (from %v)", c.name, err, errors.Unwrap(err))
		}
	}
}
