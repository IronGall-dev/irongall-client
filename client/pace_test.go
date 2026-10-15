package client_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

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
