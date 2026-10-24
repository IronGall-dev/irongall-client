package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A server that paces how much mail a box takes out (a 429 with Retry-After
// on a fetch, PROTOCOL.md §11.5) stops the drain as the drain's own limits do:
// what was delivered stays delivered, the rest waits on the server, the
// Result says how long, and nothing is an error. The next drain takes the
// rest.
func TestAPacedDrainStopsAndResumes(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	for _, body := range []string{"1", "2", "3"} {
		send(t, a, b, body)
	}
	var mu sync.Mutex
	fetches := 0
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/messages/") {
			mu.Lock()
			fetches++
			n := fetches
			mu.Unlock()
			if n == 3 {
				w.Header().Set("Content-Type", protocol.ProblemContentType)
				w.Header().Set("Retry-After", "6")
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(protocol.Problem{Type: protocol.CodeFetchPaced.TypeURI(), Title: "Fetch paced", Status: http.StatusTooManyRequests, Code: protocol.CodeFetchPaced, Detail: "paced"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
	res := receive(t, b)
	if len(res.Delivered) != 2 || !res.More || res.Paced != 6*time.Second {
		t.Fatalf("a paced drain: delivered %d, more %v, paced %s", len(res.Delivered), res.More, res.Paced)
	}
	e.srv.SetMiddle(nil)
	if res := receive(t, b); len(res.Delivered) != 1 || res.More || res.Paced != 0 {
		t.Fatalf("the drain after it: delivered %d, more %v, paced %s", len(res.Delivered), res.More, res.Paced)
	}
}

// Only a paced fetch stops a drain quietly. Any other 429 met in a drain, a
// sender's lookup the box's call budget refused among them, is an error, and
// the mail stays on the server: such a refusal says nothing of the mail, and
// a drain that ended quietly on it would hide that a sender went unchecked
// (#116).
func TestOnlyAPacedFetchEndsADrainQuietly(t *testing.T) {
	t.Parallel()
	fetch := func(r *http.Request) bool {
		return r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/messages/")
	}
	lookup := func(r *http.Request) bool { _, ok := forge.ReadOf(r); return ok }
	for _, c := range []struct {
		name   string
		match  func(*http.Request) bool
		status int
		code   protocol.Code
	}{
		{"a call budget's 429 on the sender's lookup", lookup, http.StatusTooManyRequests, protocol.CodeRateLimited},
		{"a pacing code on the sender's lookup", lookup, http.StatusTooManyRequests, protocol.CodeFetchPaced},
		{"a pacing code under another status on the fetch", fetch, http.StatusServiceUnavailable, protocol.CodeFetchPaced},
		{"a call budget's 429 on the fetch", fetch, http.StatusTooManyRequests, protocol.CodeRateLimited},
	} {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "1")
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if !c.match(r) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Content-Type", protocol.ProblemContentType)
			w.Header().Set("Retry-After", "6")
			w.WriteHeader(c.status)
			_ = json.NewEncoder(w).Encode(protocol.Problem{Type: c.code.TypeURI(), Title: c.code.Title(), Status: int64(c.status), Code: c.code})
		})
		res, err := b.Receive(context.Background())
		if err == nil || (res != nil && (res.Paced != 0 || len(res.Delivered) != 0)) || e.srv.Count(b.Address()) != 1 {
			t.Errorf("%s: %+v, %v, %d held", c.name, res, err, e.srv.Count(b.Address()))
		}
		e.srv.SetMiddle(nil)
		if res := receive(t, b); len(res.Delivered) != 1 {
			t.Errorf("%s, the drain after it: %+v", c.name, res)
		}
	}
}

// A wait a server asks for is at most a day, however large the number it
// writes: a list's Retry-After or a 429's past what a time.Duration holds once
// wrapped to a negative pause, or a short one, and polled without end.
func TestAWaitTheServerAsksForIsAtMostADay(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	const huge = "9223372037" // seconds: one past what a time.Duration holds
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", huge)
			_, _ = w.Write([]byte(`{"count":0,"messages":[],"next_cursor":null}`))
			return
		}
		next.ServeHTTP(w, r)
	})
	if res := receive(t, b); res.PollAfter != 24*60*60 {
		t.Errorf("a list's Retry-After %s is read as %d seconds, want a day", huge, res.PollAfter)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
			w.Header().Set("Content-Type", protocol.ProblemContentType)
			w.Header().Set("Retry-After", huge)
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(protocol.Problem{Type: protocol.CodeRateLimited.TypeURI(), Title: "Rate limited", Status: http.StatusTooManyRequests, Code: protocol.CodeRateLimited})
			return
		}
		next.ServeHTTP(w, r)
	})
	_, err := b.Receive(context.Background())
	if e, ok := errors.AsType[*client.APIError](err); !ok || e.RetryAfter != 24*time.Hour {
		t.Errorf("Retry-After %s: %v, want a wait of a day", huge, err)
	}
}

// A Retry-After is delay-seconds, digits alone, as a server writes it
// (PROTOCOL.md §11.3): an HTTP-date, a sign or a fraction asks for no wait, and
// any number of digits is read, up to a day.
func TestARetryAfterIsDigitsAlone(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	for value, want := range map[string]time.Duration{
		"17":                             17 * time.Second,
		"0017":                           17 * time.Second,
		"0":                              0,
		"+17":                            0,
		"-17":                            0,
		"17.0":                           0,
		"1e2":                            0,
		"Fri, 31 Dec 2027 23:59:59 GMT":  0,
		"123456789012345678901234567890": 24 * time.Hour,
	} {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
				w.Header().Set("Content-Type", protocol.ProblemContentType)
				w.Header().Set("Retry-After", value)
				w.WriteHeader(http.StatusTooManyRequests)
				_ = json.NewEncoder(w).Encode(protocol.Problem{Type: protocol.CodeRateLimited.TypeURI(), Title: "Rate limited", Status: http.StatusTooManyRequests, Code: protocol.CodeRateLimited})
				return
			}
			next.ServeHTTP(w, r)
		})
		_, err := b.Receive(context.Background())
		if e, ok := errors.AsType[*client.APIError](err); !ok || e.RetryAfter != want {
			t.Errorf("Retry-After %q: %v, want a wait of %s", value, err, want)
		}
	}
}
