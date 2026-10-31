package client_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// The client's tests run real mailboxes against internal/fakeserver, an honest
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

// env is a fake server and the clock its mailboxes share.
type env struct {
	t     *testing.T
	clock *clock
	srv   *fakeserver.Server
	http  *http.Client // the in-memory server's, or nil for the default client
	// working is set where the env's mailboxes are made in working-key mode
	// (newWorkEnv): identity mode, the default, otherwise.
	working bool
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}}
	e.srv = fakeserver.New(t, e.clock.Now)
	return e
}

// newWorkEnv is newEnv whose mailboxes are made in working-key mode
// (client.Options.WorkingKey): for a test of what a working key and its
// certificates do.
func newWorkEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.working = true
	return e
}

// newMemEnv is newEnv with the server in memory, for a test that runs in a
// testing/synctest bubble: each mailbox it makes reaches the server through the
// server's client, bounded as the default client is (client.Bounded).
func newMemEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}}
	e.srv = fakeserver.NewInMemory(t, e.clock.Now)
	e.http = e.srv.Client()
	return e
}

func (e *env) opts() client.Options {
	return client.Options{Base: e.srv.URL, Now: e.clock.Now, HTTPClient: e.http, WorkingKey: e.working}
}

// mailbox makes and registers a mailbox, whose policy lands every sender's messages in
// inbox/: the tests that use it are of what comes before a message lands.
// Where it lands, held/ by default, is senders_test.go's, which makes its
// mailboxes with heldMailbox.
func (e *env) mailbox() *client.Mailbox {
	e.t.Helper()
	b := e.heldMailbox()
	landAll(e.t, b)
	return b
}

// landAll gives a mailbox made outside env.mailbox the policy env.mailbox gives.
func landAll(t *testing.T, b *client.Mailbox) {
	t.Helper()
	if err := b.SetPolicy(t.Context(), client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll}); err != nil {
		t.Fatal(err)
	}
}

// heldMailbox makes and registers a mailbox with the default policy: a message from a
// sender it has not allowed is held.
func (e *env) heldMailbox() *client.Mailbox {
	e.t.Helper()
	b, err := client.Init(context.Background(), e.t.TempDir(), e.opts())
	if err != nil {
		e.t.Fatalf("init: %v", err)
	}
	if e.http != nil {
		client.Bounded(b)
	}
	return b
}

func send(t *testing.T, from, to *client.Mailbox, body string) *client.Sent {
	t.Helper()
	r, err := from.Send(context.Background(), to.Address(), body)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return r
}

func receive(t *testing.T, b *client.Mailbox) *client.Result {
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

// testCertLife is how long a certificate a test makes runs: the longest the
// fake server takes.
const testCertLife = time.Duration(fakeserver.MaxCertificateLifetime) * time.Second

// numberOf is the number of the prekey a mailbox published last, which is its
// working key's and its certificate's too in working-key mode: its serial
// record. A mailbox takes each
// number from its clock (protocol.SerialAt), so a test reads the number and
// never assumes one.
func numberOf(t *testing.T, b *client.Mailbox) uint64 {
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

// begunAt is the highest number a mailbox holds a prekey's key for, published or
// not: after a renewal the server did not take, the number that attempt took.
func begunAt(t *testing.T, b *client.Mailbox) uint64 {
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

// prekeyFile names a mailbox's file for prekey n: ext is ".agekey", ".txt" or
// ".txt.sig".
func prekeyFile(b *client.Mailbox, n uint64, ext string) string {
	return filepath.Join(b.Dir(), "prekeys", strconv.FormatUint(n, 10)+ext)
}

// workFile names a mailbox's file for working key n: ext is "", ".pub" or
// "-cert.pub".
func workFile(b *client.Mailbox, n uint64, ext string) string {
	return filepath.Join(b.Dir(), "work", strconv.FormatUint(n, 10)+ext)
}

// worker loads the signer a mailbox has in use from the mailbox's state
// directory: what the mailbox signs its messages and its passes with, its
// identity in identity mode, or its working key under its certificate.
func worker(t *testing.T, b *client.Mailbox) ssh.Signer {
	t.Helper()
	if _, err := os.Stat(workFile(b, numberOf(t, b), "")); errors.Is(err, fs.ErrNotExist) {
		return identityKey(t, b)
	}
	return workerAt(t, b, numberOf(t, b))
}

// workerAt loads the working key a mailbox made at a serial, under its
// certificate.
func workerAt(t *testing.T, b *client.Mailbox, serial uint64) ssh.Signer {
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

// line is an envelope's line as a sender writes it: from the mailbox whose
// identity document it carries, to a mailbox, sent at the test's clock.
func (e *env) line(doc []byte, from, to protocol.Address, body string) []byte {
	return forge.Line(e.t, doc, from, to, body, e.clock.Now())
}

// seal stores in mailbox to what a sender encrypts to its prekey as the server
// holds it, as only the operator can (forge.Seal), and returns its id.
func (e *env) seal(to *client.Mailbox, plaintext ...[]byte) string {
	return forge.Seal(e.t, e.srv, to.Address(), plaintext...)
}

// serve answers r, a read of a mailbox, with the mailbox the server holds, edited
// first (forge.Serve).
func (e *env) serve(w http.ResponseWriter, r *http.Request, next http.Handler, edit func(*protocol.MailboxResponse)) {
	forge.Serve(e.t, e.srv, w, r, next, edit)
}

// stateOf is a record the mailbox's state keeps, by the name of the file that held
// it before the state file did (client.Mailbox.Records), and whether it keeps it.
func stateOf(b *client.Mailbox, name string) ([]byte, bool) {
	all, err := client.RecordsAt(b.Dir())
	v, ok := all[name]
	return v, err == nil && ok
}

// statement is a part of the statement a mailbox signed at serial n, as the
// state keeps it: part is ".txt", ".txt.sig" or ".made" (client.Mailbox.Records).
func statement(t *testing.T, b *client.Mailbox, n uint64, part string) []byte {
	t.Helper()
	v, ok := stateOf(b, "prekeys/"+strconv.FormatUint(n, 10)+part)
	if !ok {
		t.Fatalf("%s keeps no statement %d", b.Dir(), n)
	}
	return v
}

// pinnedPeer reports whether mailbox b keeps a record of peer: it pinned the
// peer's identity, as it does once something the peer signed verified.
func pinnedPeer(b *client.Mailbox, peer protocol.Address) bool {
	return has(b, "peers/"+peer.String()+"/identity.doc")
}

// has reports whether the mailbox's state keeps a record (stateOf).
func has(b *client.Mailbox, name string) bool { _, ok := stateOf(b, name); return ok }

func exists(name string) bool {
	_, err := os.Stat(name)
	return err == nil
}

// keptThrough is the serial the revocation of its own certificates a mailbox
// keeps runs through, or 0 where it keeps none: in working-key mode, its
// trip or a later one.
func keptThrough(t *testing.T, b *client.Mailbox) uint64 {
	t.Helper()
	raw, ok := stateOf(b, "revoked-certs.json")
	if !ok {
		return 0
	}
	var rec protocol.Revocations
	if err := protocol.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	c, err := protocol.ParseRevokedCertificates(rec.RevokedCertificates)
	if err != nil {
		t.Fatal(err)
	}
	return c.Through
}
