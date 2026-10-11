package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
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

// clock is a settable clock shared by the server, the echo box and its
// correspondents.
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

type env struct {
	t     *testing.T
	clock *clock
	srv   *fakeserver.Server
	key   string // the echo box's identity key file
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}}
	e.srv = fakeserver.New(t, e.clock.Now)
	e.key = newKey(t)
	return e
}

func (e *env) opts() client.Options {
	return client.Options{Base: e.srv.URL, Now: e.clock.Now}
}

// echo starts the echo box in a new, empty state directory, as at every
// start in a tmpfs.
func (e *env) echo() *echo {
	e.t.Helper()
	x, err := start(context.Background(), e.t.TempDir(), e.key, e.opts(), protocol.Classic, log.New(io.Discard, "", 0))
	if err != nil {
		e.t.Fatalf("start: %v", err)
	}
	return x
}

func (e *env) box() *client.Box {
	e.t.Helper()
	b, err := client.Init(context.Background(), e.t.TempDir(), e.opts(), protocol.PostQuantum)
	if err != nil {
		e.t.Fatal(err)
	}
	return b
}

// newKey writes a new Ed25519 identity key as ssh-keygen does.
func newKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "identity")
	if err := os.WriteFile(name, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func receive(t *testing.T, b *client.Box) *client.Result {
	t.Helper()
	res, err := b.Receive(context.Background())
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	return res
}

func body(t *testing.T, d client.Delivery) string {
	t.Helper()
	var s string
	if err := json.Unmarshal(d.Envelope.Body, &s); err != nil {
		t.Fatal(err)
	}
	return s
}

func left(t *testing.T, dir string, sub ...string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(append(append([]string{dir}, sub...), "*")...))
	if err != nil {
		t.Fatal(err)
	}
	return names
}

// A message that passes every check is answered once, signed by the echo
// box, with what it checked and the body it carried, and leaves nothing
// behind in the echo box's memory.
func TestEchoAnswers(t *testing.T) {
	e := newEnv(t)
	x, a := e.echo(), e.box()
	ctx := context.Background()
	sent := "hello \"echo\"\n"
	if _, err := a.Send(ctx, x.b.Address(), sent); err != nil {
		t.Fatal(err)
	}
	x.once(ctx)
	res := receive(t, a)
	if len(res.Delivered) != 1 {
		t.Fatalf("%d replies, %d refused", len(res.Delivered), len(res.Refused))
	}
	d := res.Delivered[0]
	if d.Envelope.From != x.b.Address() {
		t.Fatal("the reply is not from the echo box")
	}
	got := body(t, d)
	j, _ := json.Marshal(sent)
	for _, want := range []string{
		"passed every check",
		"from: " + a.Address().String(),
		"to: " + x.b.Address().String(),
		"body, as JSON: " + string(j) + "\n",
		"readable by whoever runs it",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the reply lacks %q:\n%s", want, got)
		}
	}
	x.once(ctx)
	if res := receive(t, a); len(res.Delivered) != 0 {
		t.Fatal("answered twice")
	}
	for _, sub := range []string{"inbox", "quarantine", "outbox"} {
		if l := left(t, x.b.Dir(), sub); len(l) != 0 {
			t.Errorf("%s keeps %v", sub, l)
		}
	}
}

// The reply names the message it answers: its msg_id, sent_at and the
// SHA-256 of its ciphertext.
func TestEchoNamesTheMessage(t *testing.T) {
	e := newEnv(t)
	x, a := e.echo(), e.box()
	ctx := context.Background()
	r, err := a.Send(ctx, x.b.Address(), "which one")
	if err != nil {
		t.Fatal(err)
	}
	var msgID string
	res, err := x.b.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 {
		t.Fatalf("the echo box got nothing: %v", err)
	}
	msgID = res.Delivered[0].Envelope.MsgID
	x.reply(ctx, res.Delivered[0])
	got := body(t, receive(t, a).Delivered[0])
	for _, want := range []string{
		"msg_id: " + msgID + "\n",
		"ciphertext_sha256: " + r.ID + "\n",
		"sent_at: " + e.clock.Now().Format(protocol.TimeLayout) + "\n",
		"received_at: " + e.clock.Now().Format(protocol.TimeLayout) + "\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the reply lacks %q:\n%s", want, got)
		}
	}
}

// A message that fails a check is never answered: its sender may be anyone's
// address. It is acked and leaves nothing behind.
func TestEchoNeverAnswersARefusal(t *testing.T) {
	e := newEnv(t)
	x, a := e.echo(), e.box()
	ct := []byte("not age, and not signed by a")
	h := sha256.Sum256(ct)
	id := hex.EncodeToString(h[:])
	e.srv.Inject(x.b.Address(), id, a.Address(), ct, []byte("no signature"))
	x.once(context.Background())
	if e.srv.Count(x.b.Address()) != 0 {
		t.Fatal("the refused message was not acked")
	}
	if res := receive(t, a); len(res.Delivered) != 0 {
		t.Fatal("a refused message was answered")
	}
	if l := left(t, x.b.Dir(), "quarantine"); len(l) != 0 {
		t.Fatalf("quarantine keeps %v", l)
	}
}

// A reply the server does not take is retried at the next poll, and dropped
// once it is an hour old.
func TestEchoRetriesThenDropsAReply(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		wait    time.Duration
		answers int
	}{
		{"retried", replyTTL - time.Minute, 1},
		{"dropped", replyTTL, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t)
			x, a := e.echo(), e.box()
			if _, err := a.Send(ctx, x.b.Address(), "hold the reply"); err != nil {
				t.Fatal(err)
			}
			down := func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/"+a.Address().String() {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				next.ServeHTTP(w, r)
			}
			e.srv.SetMiddle(down)
			x.once(ctx)
			if l := left(t, x.b.Dir(), "outbox"); len(l) == 0 {
				t.Fatal("the reply that failed is not kept for retry")
			}
			x.once(ctx) // still failing: kept
			e.clock.Add(tc.wait)
			// Its age is the file's: count it from when it was written.
			p, _ := filepath.Glob(filepath.Join(x.b.Dir(), "outbox", "*.P"))
			if len(p) != 1 {
				t.Fatalf("outbox holds %v", p)
			}
			if err := os.Chtimes(p[0], time.Time{}, e.clock.Now().Add(-tc.wait)); err != nil {
				t.Fatal(err)
			}
			if tc.answers == 1 {
				e.srv.SetMiddle(nil)
			}
			x.once(ctx)
			e.srv.SetMiddle(nil)
			if res := receive(t, a); len(res.Delivered) != tc.answers {
				t.Fatalf("%d answers, want %d", len(res.Delivered), tc.answers)
			}
			if l := left(t, x.b.Dir(), "outbox"); len(l) != 0 {
				t.Fatalf("outbox keeps %v", l)
			}
		})
	}
}

// A reply the server refuses for good is dropped, not kept in outbox/failed/.
func TestEchoDropsAnUndeliverableReply(t *testing.T) {
	e := newEnv(t)
	x, a := e.echo(), e.box()
	ctx := context.Background()
	if _, err := a.Send(ctx, x.b.Address(), "to a box that goes"); err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/"+a.Address().String() {
			fakeserver.WriteJSON(w, http.StatusGone, protocol.Problem{Code: protocol.CodeRevoked})
			return
		}
		next.ServeHTTP(w, r)
	})
	x.once(ctx)
	x.once(ctx)
	if l := left(t, x.b.Dir(), "outbox", "failed"); len(l) != 0 {
		t.Fatalf("outbox/failed keeps %v", l)
	}
}

// Every start publishes a new prekey, and a running box renews it, through
// Receive, once it is a day old.
func TestEchoRenewsItsPrekey(t *testing.T) {
	e := newEnv(t)
	x := e.echo()
	serial := func() uint64 {
		st, _ := e.srv.Prekey(x.b.Address())
		p, err := protocol.ParsePrekey(st)
		if err != nil {
			t.Fatal(err)
		}
		return p.Serial
	}
	first := serial()
	x = e.echo() // a restart
	if s := serial(); s != first+1 {
		t.Fatalf("a restart published serial %d after %d", s, first)
	}
	e.clock.Add(24 * time.Hour)
	x.once(context.Background())
	if s := serial(); s != first+1 {
		t.Fatal("a poll inside a day renewed the prekey")
	}
	e.clock.Add(time.Second)
	x.once(context.Background())
	if s := serial(); s != first+2 {
		t.Fatalf("no new prekey after a day: serial %d", s)
	}
	x.once(context.Background())
	if s := serial(); s != first+2 {
		t.Fatal("renewed again at the next poll, not a day later")
	}
}

// The first start registers the box; a later one, on the same identity,
// keeps its address.
func TestEchoRegistersOnce(t *testing.T) {
	e := newEnv(t)
	x := e.echo()
	if st, _ := e.srv.Prekey(x.b.Address()); st == nil {
		t.Fatal("not registered")
	}
	if y := e.echo(); y.b.Address() != x.b.Address() {
		t.Fatal("a restart changed the address")
	}
}

// A state directory holding another box's identity is refused, never
// overwritten.
func TestEchoRefusesAnotherIdentity(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	other, _ := os.ReadFile(newKey(t))
	if err := os.WriteFile(filepath.Join(dir, "identity"), other, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := start(context.Background(), dir, e.key, e.opts(), protocol.Classic, log.New(io.Discard, "", 0))
	if err == nil || !strings.Contains(err.Error(), "another box's identity") {
		t.Fatalf("got %v", err)
	}
	if held, _ := os.ReadFile(filepath.Join(dir, "identity")); string(held) != string(other) {
		t.Fatal("the identity was overwritten")
	}
}

// The wait before the next poll is the server's: its poll_after, or a rate
// limit's Retry-After.
func TestEchoPacesItself(t *testing.T) {
	e := newEnv(t)
	x := e.echo()
	polls := func(answer func(w http.ResponseWriter)) {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
				answer(w)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	polls(func(w http.ResponseWriter) {
		fakeserver.WriteJSON(w, http.StatusOK, protocol.MessageList{Messages: []protocol.MessageInfo{}, PollAfter: 23})
	})
	if d := x.once(context.Background()); d != 23*time.Second {
		t.Fatalf("waits %s, want the server's poll_after", d)
	}
	polls(func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "17")
		fakeserver.WriteJSON(w, http.StatusTooManyRequests, protocol.Problem{Code: protocol.CodeRateLimited})
	})
	if d := x.once(context.Background()); d != 17*time.Second {
		t.Fatalf("waits %s, want the Retry-After", d)
	}
}
