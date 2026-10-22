package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// The client's tests run real boxes against internal/fakeserver, an honest
// in-memory server, with no network and nothing to set up: go test ./...
// A test that plays the hostile operator puts a middleware in front of it
// (env.srv.SetMiddle, internal/forge) or uses the operator's powers over
// storage.

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
	if err := b.SetPolicy(t.Context(), client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll}); err != nil {
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

func send(t *testing.T, from, to *client.Box, body string) *client.Sent {
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
// working key's and its certificate's too: its serial record. A box takes each
// number from its clock (protocol.SerialAt), so a test reads the number and
// never assumes one.
func numberOf(t *testing.T, b *client.Box) uint64 {
	t.Helper()
	s, ok := b.Record(t, "serial")
	if !ok {
		t.Fatalf("%s has published no prekey", b.Dir())
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
	return forge.Line(e.t, doc, from, to, body, e.clock.Now())
}

// seal stores in box to, as mail from a sender, what a sender encrypts to its
// prekey as the server holds it, as only the operator can (forge.Seal), and
// returns its id.
func (e *env) seal(to *client.Box, from protocol.Address, plaintext ...[]byte) string {
	return forge.Seal(e.t, e.srv, to.Address(), from, plaintext...)
}

// serve answers r, a read of a box, with the box the server holds, edited
// first (forge.Serve).
func (e *env) serve(w http.ResponseWriter, r *http.Request, next http.Handler, edit func(*protocol.BoxResponse)) {
	forge.Serve(e.t, e.srv, w, r, next, edit)
}

// stateOf is a record the box's state keeps, by the name of the file that held
// it before the state file did (client.Box.Records), and whether it keeps it.
func stateOf(b *client.Box, name string) ([]byte, bool) {
	all, err := client.RecordsAt(b.Dir())
	v, ok := all[name]
	return v, err == nil && ok
}

// statement is a part of the statement a box signed at serial n, as the
// state keeps it: part is ".txt", ".txt.sig" or ".made" (client.Box.Records).
func statement(t *testing.T, b *client.Box, n uint64, part string) []byte {
	t.Helper()
	v, ok := stateOf(b, "prekeys/"+strconv.FormatUint(n, 10)+part)
	if !ok {
		t.Fatalf("%s keeps no statement %d", b.Dir(), n)
	}
	return v
}

// pinnedPeer reports whether box b keeps a record of peer: it pinned the
// peer's identity, as it does once something the peer signed verified.
func pinnedPeer(b *client.Box, peer protocol.Address) bool {
	return has(b, "peers/"+peer.String()+"/identity.doc")
}

// has reports whether the box's state keeps a record (stateOf).
func has(b *client.Box, name string) bool { _, ok := stateOf(b, name); return ok }

func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}
