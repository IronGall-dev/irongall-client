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
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A server that paces how much mail a box takes out (a 429 with Retry-After
// on a fetch, PROTOCOL.md §8) stops the drain as the drain's own limits do:
// what was delivered stays delivered, the rest waits on the server, the
// Result says how long, and nothing is an error. The next drain takes the
// rest.
func TestAPacedDrainStopsAndResumes(t *testing.T) {
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
				_ = json.NewEncoder(w).Encode(protocol.Problem{Type: protocol.CodeRateLimited.TypeURI(), Title: "Rate limited", Status: http.StatusTooManyRequests, Code: protocol.CodeRateLimited, Detail: "paced"})
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

// A wait a server asks for is at most a day, however large the number it
// writes: a poll_after or a Retry-After past what a time.Duration holds once
// wrapped to a negative pause, or a short one, and polled without end.
func TestAWaitTheServerAsksForIsAtMostADay(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	const huge = "9223372037" // seconds: one past what a time.Duration holds
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"count":0,"messages":[],"next_cursor":null,"poll_after":` + huge + `}`))
			return
		}
		next.ServeHTTP(w, r)
	})
	if res := receive(t, b); res.PollAfter != 24*60*60 {
		t.Errorf("poll_after %s is read as %d seconds, want a day", huge, res.PollAfter)
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
