package client_test

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A 401 certificate_revoked with no revocation of the box's certificates to
// show is a server's word (PROTOCOL.md §8, §12.5): the box reads itself,
// shown none it signs one more pass and tries once more, as for the other
// 401s, and then reports the refusal, nothing kept.
func TestACertificateRevokedWithNoneShownIsTriedOnceMore(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	own := "/v1/" + b.Address().String()
	var mu sync.Mutex
	var calls []string
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		mu.Lock()
		calls = append(calls, r.Method+" "+strings.Replace(r.URL.Path, own, "/v1/own", 1))
		mu.Unlock()
		if r.Method == http.MethodGet && r.URL.Path == own+"/messages" {
			forge.Refuse(w, protocol.CodeCertificateRevoked)
			return
		}
		next.ServeHTTP(w, r)
	})
	e.clock.Add(time.Minute)
	_, err := b.Receive(context.Background())
	mu.Lock()
	got := strings.Join(calls, ", ")
	mu.Unlock()
	if client.Code(err) != protocol.CodeCertificateRevoked {
		t.Fatalf("a drain its server answers certificate_revoked with none to show: %v (calls %s)", err, got)
	}
	if want := "GET /v1/own/messages, GET /v1/own, GET /v1/own/messages, GET /v1/own"; got != want {
		t.Errorf("the calls: %s\nwant: %s", got, want)
	}
}
