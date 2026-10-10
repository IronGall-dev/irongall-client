package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/drewstreib/crossbot-client/client"
	"github.com/drewstreib/crossbot-client/internal/fakeserver"
	"github.com/drewstreib/crossbot-client/protocol"
	"golang.org/x/crypto/ssh"
)

// The client's tests run real boxes against internal/fakeserver, an honest
// in-memory server, with no network and nothing to set up: go test ./...
// A test that plays the hostile operator puts a middleware in front of it
// (env.srv.SetMiddle) or uses the operator's powers over storage.

// clock is a settable clock shared by the server and the clients.
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

// env is a fake server and the clock its boxes share.
type env struct {
	t     *testing.T
	clock *clock
	srv   *fakeserver.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}}
	e.srv = fakeserver.New(t, e.clock.Now)
	return e
}

func (e *env) opts() client.Options {
	return client.Options{Base: e.srv.URL, Now: e.clock.Now}
}

// box makes, registers and activates a box.
func (e *env) box(kt protocol.KeyType) *client.Box {
	e.t.Helper()
	b, err := client.Init(context.Background(), e.t.TempDir(), e.opts(), kt)
	if err != nil {
		e.t.Fatalf("init: %v", err)
	}
	return b
}

func send(t *testing.T, from, to *client.Box, body string) *protocol.Receipt {
	t.Helper()
	r, err := from.Send(context.Background(), to.Address(), body)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return r
}

func receive(t *testing.T, b *client.Box) *client.Result {
	t.Helper()
	res, err := b.Receive(context.Background())
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	return res
}

func bodyOf(t *testing.T, d client.Delivery) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(d.Envelope.Body, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

// signer loads a box's identity key from its state directory, as an operator
// who stole it would.
func signer(t *testing.T, b *client.Box) ssh.Signer {
	t.Helper()
	k, err := os.ReadFile(filepath.Join(b.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// capture records the JSON body of the next request matching method and
// path suffix.
func capture(e *env, method, suffix string) *[]byte {
	var got []byte
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == method && strings.HasSuffix(r.URL.Path, suffix) && got == nil {
			got, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(got))
		}
		next.ServeHTTP(w, r)
	})
	return &got
}

// failOnce answers the first request matching method and path suffix with a
// 503, as a server that is down would.
func failOnce(e *env, method, suffix string) {
	failed := false
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == method && strings.HasSuffix(r.URL.Path, suffix) && !failed {
			failed = true
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
