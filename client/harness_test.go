package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
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

// box makes and registers a box, whose policy lands every sender's mail in
// inbox/: the tests that use it are of what comes before a message lands.
// Where it lands, held/ by default, is senders_test.go's, which makes its
// boxes with heldBox.
func (e *env) box(kt protocol.KeyType) *client.Box {
	e.t.Helper()
	b := e.heldBox(kt)
	landAll(e.t, b)
	return b
}

// landAll gives a box made outside env.box the policy env.box gives.
func landAll(t *testing.T, b *client.Box) {
	t.Helper()
	if err := b.SetPolicy(client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll}); err != nil {
		t.Fatal(err)
	}
}

// heldBox makes and registers a box with the default policy: mail from a
// sender it has not allowed is held.
func (e *env) heldBox(kt protocol.KeyType) *client.Box {
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

// numberOf is the number of the prekey a box published last, which is its
// working key's and its certificate's too: its serial file. A box takes each
// number from its clock (protocol.SerialAt), so a test reads the number and
// never assumes one.
func numberOf(t *testing.T, b *client.Box) uint64 {
	t.Helper()
	s, err := os.ReadFile(filepath.Join(b.Dir(), "serial"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(s)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// begunAt is the highest number a box holds a prekey's key for, published or
// not: after a renewal the server did not take, the number that attempt took.
func begunAt(t *testing.T, b *client.Box) uint64 {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	if err != nil || len(names) == 0 {
		t.Fatalf("no prekey in %s: %v", b.Dir(), err)
	}
	var top uint64
	for _, name := range names {
		n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(name), ".agekey"), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		top = max(top, n)
	}
	return top
}

// only returns the one file a pattern matches.
func only(t *testing.T, pattern string) string {
	t.Helper()
	names, err := filepath.Glob(pattern)
	if err != nil || len(names) != 1 {
		t.Fatalf("%s matches %d files: %v", pattern, len(names), err)
	}
	return names[0]
}

// prekeyFile names a box's file for prekey n: ext is ".agekey", ".txt" or
// ".txt.sig".
func prekeyFile(b *client.Box, n uint64, ext string) string {
	return filepath.Join(b.Dir(), "prekeys", strconv.FormatUint(n, 10)+ext)
}

// workFile names a box's file for working key n: ext is "", ".pub" or
// "-cert.pub".
func workFile(b *client.Box, n uint64, ext string) string {
	return filepath.Join(b.Dir(), "work", strconv.FormatUint(n, 10)+ext)
}

// worker loads the working key a box has in use, under its certificate, from
// the box's state directory: what the box signs its mail and its passes with.
func worker(t *testing.T, b *client.Box) ssh.Signer {
	t.Helper()
	return workerAt(t, b, numberOf(t, b))
}

// workerAt loads the working key a box made at a serial, under its
// certificate.
func workerAt(t *testing.T, b *client.Box, serial uint64) ssh.Signer {
	t.Helper()
	stem := workFile(b, serial, "")
	k, err := os.ReadFile(stem)
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.ParsePrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(stem + "-cert.pub")
	if err != nil {
		t.Fatal(err)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(key.(*ssh.Certificate), work)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// line is an envelope's line as a sender writes it: from the box whose
// identity document it carries, to a box, sent at the test's clock.
func (e *env) line(doc []byte, from, to protocol.Address, body string) []byte {
	e.t.Helper()
	env, err := protocol.NewEnvelope(from, to, body, e.clock.Now())
	if err != nil {
		e.t.Fatal(err)
	}
	env.Identity = doc
	l, err := env.Line()
	if err != nil {
		e.t.Fatal(err)
	}
	return l
}

// seal encrypts what a sender encrypts, an envelope's line and then whatever
// follows it, to a box's current prekey as the server holds it, and stores it
// in that box as mail from a sender, as only the operator can. It returns the
// id it is stored under: the hash of the ciphertext.
func (e *env) seal(to *client.Box, from protocol.Address, plaintext ...[]byte) string {
	e.t.Helper()
	ct := e.encrypt(to, plaintext...)
	h := sha256.Sum256(ct)
	id := hex.EncodeToString(h[:])
	e.srv.Inject(to.Address(), id, from, ct)
	return id
}

// encrypt encrypts the parts, one after the other, to a box's current prekey.
func (e *env) encrypt(to *client.Box, parts ...[]byte) []byte {
	e.t.Helper()
	st, _ := e.srv.Prekey(to.Address())
	p, err := protocol.ParsePrekey(st)
	if err != nil {
		e.t.Fatal(err)
	}
	r, err := p.Recipient()
	if err != nil {
		e.t.Fatal(err)
	}
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, r)
	if err != nil {
		e.t.Fatal(err)
	}
	for _, part := range parts {
		if _, err := w.Write(part); err != nil {
			e.t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		e.t.Fatal(err)
	}
	return ct.Bytes()
}

// sign signs an envelope's line for a recipient, as the stock tools do.
func sign(t *testing.T, s ssh.Signer, line []byte, to protocol.Address) []byte {
	t.Helper()
	sig, err := protocol.Sign(s, line, protocol.MessageNamespace(to))
	if err != nil {
		t.Fatal(err)
	}
	return sig
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
