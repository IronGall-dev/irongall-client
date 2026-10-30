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
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// clock is a settable clock shared by the server, the echo mailbox and its
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
	key   string // the echo mailbox's identity key file
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

// echo starts the echo mailbox in a new, empty state directory, as at every
// start in a tmpfs.
func (e *env) echo() *echo {
	e.t.Helper()
	x, err := start(context.Background(), e.t.TempDir(), e.key, e.opts(), protocol.Classic, log.New(io.Discard, "", 0))
	if err != nil {
		e.t.Fatalf("start: %v", err)
	}
	return x
}

func (e *env) mailbox() *client.Mailbox {
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

func receive(t *testing.T, b *client.Mailbox) *client.Result {
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
// mailbox, with what it checked and the body it carried, and leaves nothing
// behind in the echo mailbox's memory.
func TestEchoAnswers(t *testing.T) {
	e := newEnv(t)
	x, a := e.echo(), e.mailbox()
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
		t.Fatal("the reply is not from the echo mailbox")
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
	for _, sub := range []string{"inbox", "refused", "outbox", "sent"} {
		if l := left(t, x.b.Dir(), sub); len(l) != 0 {
			t.Errorf("%s keeps %v", sub, l)
		}
	}
}

// The reply names the message it answers: its msg_id, as the reply's
// in_reply_to and in its body, its sent_at and the SHA-256 of its ciphertext.
func TestEchoNamesTheMessage(t *testing.T) {
	e := newEnv(t)
	x, a := e.echo(), e.mailbox()
	ctx := context.Background()
	r, err := a.Send(ctx, x.b.Address(), "which one")
	if err != nil {
		t.Fatal(err)
	}
	var msgID string
	res, err := x.b.Receive(ctx)
	if err != nil || len(res.Delivered) != 1 {
		t.Fatalf("the echo mailbox got nothing: %v", err)
	}
	msgID = res.Delivered[0].Envelope.MsgID
	x.reply(ctx, res.Delivered[0])
	reply := receive(t, a).Delivered[0]
	if reply.Envelope.InReplyTo != msgID {
		t.Errorf("the reply's in_reply_to is %q, not %s", reply.Envelope.InReplyTo, msgID)
	}
	got := body(t, reply)
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
	x, a := e.echo(), e.mailbox()
	ct := []byte("not age, and not signed by a")
	h := sha256.Sum256(ct)
	id := hex.EncodeToString(h[:])
	e.srv.Inject(x.b.Address(), id, ct)
	x.once(context.Background())
	if e.srv.Count(x.b.Address()) != 0 {
		t.Fatal("the refused message was not acked")
	}
	if res := receive(t, a); len(res.Delivered) != 0 {
		t.Fatal("a refused message was answered")
	}
	if l := left(t, x.b.Dir(), "refused"); len(l) != 0 {
		t.Fatalf("refused/ keeps %v", l)
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
			x, a := e.echo(), e.mailbox()
			if _, err := a.Send(ctx, x.b.Address(), "hold the reply"); err != nil {
				t.Fatal(err)
			}
			down := func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/"+a.Address().String()+"/messages" {
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
	x, a := e.echo(), e.mailbox()
	ctx := context.Background()
	if _, err := a.Send(ctx, x.b.Address(), "to a mailbox that goes"); err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && r.URL.Path == "/v1/"+a.Address().String()+"/messages" {
			fakeserver.WriteJSON(w, http.StatusGone, protocol.Problem{Type: protocol.CodeRevoked.TypeURI(), Code: protocol.CodeRevoked})
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

// Every start publishes a new prekey, and a running mailbox renews it, through
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
	second := serial()
	if second <= first {
		t.Fatalf("a restart published serial %d after %d", second, first)
	}
	e.clock.Add(24 * time.Hour)
	x.once(context.Background())
	if s := serial(); s != second {
		t.Fatal("a poll inside a day renewed the prekey")
	}
	e.clock.Add(time.Second)
	x.once(context.Background())
	third := serial()
	if third <= second {
		t.Fatalf("no new prekey after a day: serial %d", third)
	}
	x.once(context.Background())
	if s := serial(); s != third {
		t.Fatal("renewed again at the next poll, not a day later")
	}
}

// The first start registers the mailbox; a later one, on the same identity,
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

// A state directory holding another mailbox's identity is refused, never
// overwritten.
func TestEchoRefusesAnotherIdentity(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	other, _ := os.ReadFile(newKey(t))
	if err := os.WriteFile(filepath.Join(dir, "identity"), other, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := start(context.Background(), dir, e.key, e.opts(), protocol.Classic, log.New(io.Discard, "", 0))
	if err == nil || !strings.Contains(err.Error(), "another mailbox's identity") {
		t.Fatalf("got %v", err)
	}
	if held, _ := os.ReadFile(filepath.Join(dir, "identity")); string(held) != string(other) {
		t.Fatal("the identity was overwritten")
	}
}

// The wait before the next poll is the server's: its list's Retry-After, or a
// rate limit's.
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
		w.Header().Set("Retry-After", "23")
		fakeserver.WriteList(w, protocol.MessageList{Messages: []protocol.MessageInfo{}})
	})
	if d, hold := x.once(context.Background()); d != 23*time.Second || !hold {
		t.Fatalf("waits %s, holding %t: want its list's Retry-After, and a hold", d, hold)
	}
	polls(func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "17")
		fakeserver.WriteJSON(w, http.StatusTooManyRequests, protocol.Problem{Type: protocol.CodeRateLimited.TypeURI(), Code: protocol.CodeRateLimited})
	})
	if d, hold := x.once(context.Background()); d != 17*time.Second || hold {
		t.Fatalf("waits %s, holding %t: want the Retry-After, and no hold", d, hold)
	}
}

// lines is a log that hands each line it is written to a channel, and drops
// a line no one is reading.
type lines chan string

func (l lines) Write(p []byte) (int, error) {
	select {
	case l <- string(p):
	default:
	}
	return len(p), nil
}

// A running echo mailbox holds its list, and answers a message as it arrives:
// with no time passed, which a poll, a minute from the last, cannot give.
// How many held requests that takes is not promised: Await holds one after
// another until the list changes, and one that ends unchanged is followed by
// the next at once (#557).
func TestEchoAnswersInSeconds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := fakeserver.NewInMemory(t, time.Now)
		opt := client.Options{Base: srv.URL, HTTPClient: srv.Client()}
		logged := make(lines, 64)
		x, err := start(context.Background(), t.TempDir(), newKey(t), opt, protocol.Classic, log.New(logged, "", 0))
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		a, err := client.Init(context.Background(), t.TempDir(), opt, protocol.PostQuantum)
		if err != nil {
			t.Fatal(err)
		}
		var holds atomic.Int32
		srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Query().Has("wait") {
				holds.Add(1)
			}
			next.ServeHTTP(w, r)
		})
		// The run is ended, and waited for, before the test's cleanup removes
		// the echo mailbox's directory.
		ctx, cancel := context.WithCancel(context.Background())
		ran := make(chan struct{})
		t.Cleanup(func() { cancel(); <-ran })
		go func() {
			defer close(ran)
			_ = x.run(ctx)
		}()
		time.Sleep(time.Minute) // the echo mailbox holds its list
		synctest.Wait()
		sent := time.Now()
		if _, err := a.Send(context.Background(), x.b.Address(), "woke the echo"); err != nil {
			t.Fatal(err)
		}
		for answered := false; !answered; {
			answered = strings.Contains(<-logged, "answered")
		}
		if took := time.Since(sent); holds.Load() < 1 || took != 0 {
			t.Fatalf("answered after %s, in %d holds", took, holds.Load())
		}
		if res := receive(t, a); len(res.Delivered) != 1 || !strings.Contains(body(t, res.Delivered[0]), "woke the echo") {
			t.Fatalf("%d replies", len(res.Delivered))
		}
	})
}

// An echo mailbox with a reply its recipient's server does not take retries it
// once a poll interval, and lists its own mailbox once in that interval, the
// hold that waits for it: within the server's poll budget.
func TestEchoHoldsWithAReplyPending(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		srv := fakeserver.NewInMemory(t, time.Now)
		opt := client.Options{Base: srv.URL, HTTPClient: srv.Client()}
		x, err := start(context.Background(), t.TempDir(), newKey(t), opt, protocol.Classic, log.New(io.Discard, "", 0))
		if err != nil {
			t.Fatal(err)
		}
		a, err := client.Init(context.Background(), t.TempDir(), opt, protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := a.Send(context.Background(), x.b.Address(), "hold the reply"); err != nil {
			t.Fatal(err)
		}
		var lists, posts atomic.Int32
		mine := "/v1/" + x.b.Address().String() + "/messages"
		srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			switch {
			case r.Method == http.MethodPost && r.URL.Path == "/v1/"+a.Address().String()+"/messages":
				posts.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			case r.Method == http.MethodGet && r.URL.Path == mine && !r.URL.Query().Has("cursor"):
				lists.Add(1)
			}
			next.ServeHTTP(w, r)
		})
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); _ = x.run(ctx) }()
		// After its first drain and reply, one hold and one retry each
		// interval, the fake's minute.
		time.Sleep(30 * time.Second)
		l0, p0 := lists.Load(), posts.Load()
		time.Sleep(30 * time.Minute)
		l, p := lists.Load()-l0, posts.Load()-p0
		cancel()
		<-done
		if l != 30 || p != 30 {
			t.Fatalf("in 30 minutes with a reply pending: %d lists and %d posts, want 30 of each", l, p)
		}
	})
}
