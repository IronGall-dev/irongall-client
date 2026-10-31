package sh_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The script's mailbox renewed, pruned, restored and drained against a server
// that forges.

// newest is the highest number the mailbox signed a prekey statement at,
// published or not.
func (b *shMailbox) newest() uint64 {
	b.w.t.Helper()
	var top uint64
	for _, f := range b.files("prekeys") {
		if s, ok := strings.CutSuffix(f, ".txt.sig"); ok {
			n, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				b.w.t.Fatal(err)
			}
			top = max(top, n)
		}
	}
	return top
}

// dated rewrites the not_after of the mailbox's prekey statement n to at.
func (b *shMailbox) dated(n uint64, at time.Time) {
	b.w.t.Helper()
	f := b.file(fmt.Sprintf("prekeys/%d.txt", n))
	if err := os.WriteFile(f, withLine(mustRead(b.w.t, f), 5, at.UTC().Format(protocol.TimeLayout)), 0o600); err != nil {
		b.w.t.Fatal(err)
	}
}

// writeFile writes a file a test needs, failing the test if it cannot.
func writeFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

// once serves mailbox b's read with the statement given once, then as held.
func (w *world) once(b *shMailbox, s stmt) {
	var done atomic.Bool
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == b.addr && done.CompareAndSwap(false, true) {
			forge.Serve(w.t, w.srv, rw, r, next, func(br *protocol.MailboxResponse) { br.Prekey, br.PrekeySignature = s.st, s.sig })
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// A renewal is a new key, signed by the identity, at a later number; senders
// move on, and refuse the statements before it; a sender handed one by a
// stale cache seals the same envelope again to the next.
func TestScriptRenews(t *testing.T) {
	w := newWorld(t)
	a, b, c := w.mailbox(), w.mailbox(), w.mailbox()
	a.mustSend(b, "before the renewal")
	b.recv()
	b1, pass := b.num(), b.read("pass")
	first := w.prekey(b)
	key1 := strings.TrimSpace(b.must(fmt.Sprintf(`age-keygen -y "$DR/prekeys/%d.agekey"`, b1)))
	b.must("dr_rekey")
	b2 := b.num()
	if p, c := w.served(b); b2 <= b1 || p != b2 || c != 0 || b.read("pass") == pass {
		t.Errorf("dr_rekey: number %d after %d, served %d by a signer of rank %d, a new pass %v", b2, b1, p, c, b.read("pass") != pass)
	}
	st2, _ := w.srv.Prekey(b.addr)
	if keyOf(string(st2)) == key1 {
		t.Error("the renewed prekey is the same key")
	}
	a.mustSend(b, "after rotation")
	peer := "peers/" + b.addr.String() + "/"
	if a.read(peer+"serial") != fmt.Sprintln(b2) || a.read(peer+"rank") != "0\n" {
		t.Errorf("A recorded %q by a signer of rank %q, not %d by the identity", a.read(peer+"serial"), a.read(peer+"rank"), b2)
	}
	if d := b.recv(); !slices.Equal(d.bodies(), []string{"after rotation"}) {
		t.Errorf("B's drain after its renewal: %v", d)
	}
	w.serving(b, first)
	if r := a.send(b.addr.String(), "secret"); r.rc == 0 || !strings.Contains(r.err, "rollback") {
		t.Errorf("B's first statement once its second was seen: %v", r)
	}
	w.serving(b, first)
	n := len(w.srv.Requests())
	if r := b.sh("dr_rekey"); r.rc == 0 || !strings.Contains(r.err, "rollback") || slices.Contains(w.calls(n), "PUT /v1/"+b.addr.String()+"/prekey") {
		t.Errorf("a rollback of the mailbox's own prekey: %v, %q", r, w.calls(n))
	}
	w.once(b, first)
	if r := c.send(b.addr.String(), "via a stale cache"); r.rc != 0 || !strings.Contains(r.err, "stale_prekey") || c.read(peer+"serial") != fmt.Sprintln(b2) {
		t.Errorf("a sender handed the first prekey: %v", r)
	}
	if d := b.recv(); !slices.Equal(d.bodies(), []string{"via a stale cache"}) {
		t.Errorf("the message sealed again after stale_prekey: %v", d)
	}
}

// A statement served in the mailbox's name that its identity signed and it
// did not make means its identity is in other hands: the renewal says so,
// recommending that the address be revoked, and goes above it, and the
// mailbox's sends are not held, since no certificate of its own is in doubt
// (PROTOCOL.md §12.4).
func TestScriptSaysAStatementItDidNotMake(t *testing.T) {
	w := newWorld(t)
	a, b := w.mailbox(), w.mailbox()
	n := b.num()
	w.serving(b, w.statement(b, n+1, w.operator().recipient(), notAfter(), b.file("identity")))
	b.mustSend(a, "while it is served")
	out := b.must("dr_rekey")
	var said struct {
		Type   string
		Serial uint64
		Detail string
	}
	l, _, _ := strings.Cut(out, "\n")
	if jsonLine(l, &said) != nil || said.Type != "prekey_not_made" || said.Serial != n+1 || !strings.Contains(said.Detail, "only revoking the address ends that") || !strings.Contains(out, `{"type":"prekey",`) {
		t.Errorf("the renewal that read it: %q", out)
	}
	w.honest()
	if p, c := w.served(b); b.num() <= n+1 || p != b.num() || c != 0 {
		t.Fatalf("the renewal: serial %d after %d, served %d by a signer of rank %d", b.num(), n+1, p, c)
	}
	if out := b.must("dr_rekey"); strings.Contains(out, "prekey_not_made") {
		t.Errorf("a renewal that read the mailbox's own statement: %q", out)
	}
	b.mustSend(a, "after the renewal")
	if d := a.recv(); !slices.Equal(d.bodies(), []string{"while it is served", "after the renewal"}) {
		t.Errorf("A's drain: %v", d)
	}
}

// A retired prekey is deleted by the reading of the clock a server took, at
// its not_after and 33 days; the newest never; then its messages are unrecoverable.
func TestScriptDeletesARetiredPrekey(t *testing.T) {
	w := newWorld(t)
	a, b := w.mailbox(), w.mailbox()
	b1 := b.num()
	posted := forge.Capture(w.srv, http.MethodPost, "/messages")
	a.mustSend(b, "to the first key")
	w.honest()
	ct := filepath.Join(w.work, "first.age")
	writeFile(t, ct, *posted)
	key1 := filepath.Join(w.work, "key1.agekey")
	writeFile(t, key1, []byte(b.read(fmt.Sprintf("prekeys/%d.agekey", b1))))
	b.recv()
	b.must("dr_rekey")
	b2 := b.num()
	decrypts := func(key string) bool { return b.sh(fmt.Sprintf("age -d -i %s < %s > /dev/null", key, ct)).rc == 0 }
	if !decrypts(key1) || !decrypts(b.file(fmt.Sprintf("prekeys/%d.agekey", b1))) {
		t.Fatal("control: a message to the retired key does not decrypt while it is kept")
	}
	b.dated(b1, time.Now().Add(-34*24*time.Hour))
	b.must(fmt.Sprintf("dr_prune %d", time.Now().Add(-48*time.Hour).Unix()))
	if !b.has(fmt.Sprintf("prekeys/%d.agekey", b1)) {
		t.Error("dr_prune by a reading of the clock before the key's deletion time deleted it")
	}
	b.must(fmt.Sprintf("dr_prune %d", time.Now().Unix()))
	if b.has(fmt.Sprintf("prekeys/%d.agekey", b1)) || !b.has(fmt.Sprintf("prekeys/%d.agekey", b2)) {
		t.Errorf("dr_prune past not_after and 33 days: %q", b.files("prekeys"))
	}
	if decrypts(b.file(fmt.Sprintf("prekeys/%d.agekey", b2))) {
		t.Error("a message to the deleted key still decrypts with the mailbox's keys")
	}
	held := b.read(fmt.Sprintf("prekeys/%d.txt", b2))
	b.dated(b2, time.Now().Add(-34*24*time.Hour))
	b.must(fmt.Sprintf("dr_prune %d", time.Now().Unix()))
	if !b.has(fmt.Sprintf("prekeys/%d.agekey", b2)) {
		t.Error("dr_prune deleted the newest key")
	}
	writeFile(t, b.file(fmt.Sprintf("prekeys/%d.txt", b2)), []byte(held))
	// dr_recv prunes, by the reading at which the server answered its list.
	p := w.mailbox()
	p1 := p.newest()
	p.must("dr_rekey")
	p.dated(p1, time.Now().Add(-34*24*time.Hour))
	if d := p.recv(); d.rc != 0 || p.has(fmt.Sprintf("prekeys/%d.agekey", p1)) || !p.has(fmt.Sprintf("prekeys/%d.agekey", p.newest())) {
		t.Errorf("dr_recv did not delete a retired key past its deletion time: %v, %q", d, p.files("prekeys"))
	}
}

// A drain follows every page; a pass the server refuses is replaced on the
// way; a command waits for the lock and leaves none behind when killed; a
// fault in the mailbox itself stops the drain with nothing judged or acked.
func TestScriptDrainsEveryPageAndHoldsTheLock(t *testing.T) {
	w := newWorld(t)
	a, b := w.mailbox(), w.mailbox()
	for i := 1; i <= 3; i++ {
		a.mustSend(b, fmt.Sprintf("page %d", i))
	}
	old := b.read("pass")
	var refusedOnce atomic.Bool // the pass kept is refused once, as a server whose clock ran it out sooner refuses it
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") && refusedOnce.CompareAndSwap(false, true) {
			forge.Refuse(rw, protocol.CodePassExpired)
			return
		}
		next.ServeHTTP(rw, r)
	})
	w.srv.SetPage(2)
	n := len(w.srv.Requests())
	d := b.recv()
	cursors := 0
	for _, r := range w.srv.Requests()[n:] {
		if r.Method == http.MethodGet && strings.HasSuffix(r.Path, "/messages") && strings.HasPrefix(r.Query, "cursor=") {
			cursors++
		}
	}
	w.honest()
	if !slices.Equal(d.bodies(), []string{"page 1", "page 2", "page 3"}) || w.srv.Count(b.addr) != 0 || cursors != 1 || b.read("pass") == old || !refusedOnce.Load() {
		t.Errorf("pages of 2: %v, %d held, %d pages after the first, the refused pass replaced %v", d, w.srv.Count(b.addr), cursors, b.read("pass") != old)
	}
	w.srv.SetPage(50)
	if err := os.Mkdir(b.file("lock"), 0o700); err != nil {
		t.Fatal(err)
	}
	if r := b.sh("DR_LOCK_WAIT=1 dr_recv"); r.rc == 0 || !strings.Contains(r.err, "waiting for this mailbox's lock") || !strings.Contains(r.err, "held its lock") {
		t.Errorf("a command while another holds the lock: %v", r)
	}
	before, _ := w.served(b)
	if r := b.sh(`(sleep 2; rmdir "$DR/lock") & dr_rekey; rc=$?; wait; exit $rc`); r.rc != 0 {
		t.Errorf("dr_rekey while a drain holds the lock: %v", r)
	}
	if after, _ := w.served(b); after <= before {
		t.Error("dr_rekey did not renew once the lock was free")
	}
	if r := b.sh(`rc=0; DR_HOME=$DR bash -c '. "$1"; hold(){ [ -d "$DR/lock" ] || exit 9; kill -TERM $$; sleep 5; }; dr_lock hold' _ ` + abs(t, "dromas.sh") + ` 2> /dev/null || rc=$?; echo $rc`); r.out != "143\n" || exists(b.file("lock")) {
		t.Errorf("a command killed while it holds the lock: %v", r)
	}
	a.mustSend(b, "kept")
	q := b.files("refused")
	held := filepath.Join(w.work, "held")
	b.must(`mkdir ` + held + `; mv "$DR"/prekeys/*.agekey ` + held)
	if d := b.recv(); d.rc == 0 || w.srv.Count(b.addr) != 1 || !slices.Equal(b.files("refused"), q) || !strings.Contains(d.said, "no prekeys") {
		t.Errorf("a drain with the mailbox's prekeys gone: %v", d)
	}
	b.must(`mv ` + held + `/*.agekey "$DR/prekeys/"`)
	if d := b.recv(); !slices.Equal(d.bodies(), []string{"kept"}) || w.srv.Count(b.addr) != 0 {
		t.Errorf("the drain once the mailbox is fixed: %v", d)
	}
}

// sent/ keeps every message the server took: one line, the line its reader
// delivered as its envelope and the server's receipt beside it, and nothing
// else (#356), named <address>.<msg_id>.
func TestScriptKeepsWhatWasSent(t *testing.T) {
	w := newWorld(t)
	a, b := w.mailbox(), w.mailbox()
	receipts := map[string]string{}
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method != http.MethodPost {
			next.ServeHTTP(rw, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		var rc protocol.Receipt
		if protocol.Unmarshal(rec.Body.Bytes(), &rc) == nil {
			receipts[rc.ID] = strings.TrimSpace(rec.Body.String())
		}
		for k, v := range rec.Header() {
			rw.Header()[k] = v
		}
		rw.WriteHeader(rec.Code)
		_, _ = rw.Write(rec.Body.Bytes())
	})
	a.mustSend(b, "one")
	a.mustSend(b, "two")
	w.honest()
	b.recv()
	sent := a.files("sent")
	if len(sent) != 2 {
		t.Fatalf("sent/: %q", sent)
	}
	for _, f := range sent {
		name := "sent/" + f
		fi, _ := os.Stat(a.file(name))
		var s struct {
			Envelope struct {
				To, From string
				MsgID    string `json:"msg_id"`
			}
			Receipt map[string]any
		}
		var m map[string]map[string]any
		if strings.Contains(a.read(name), "\n") || fi.Mode().Perm() != 0o600 || jsonLine(a.read(name), &m) != nil || jsonLine(a.read(name), &s) != nil {
			t.Fatalf("%s is not one line of JSON, 0600: %q", name, a.read(name))
		}
		if f != s.Envelope.To+"."+s.Envelope.MsgID+".json" || s.Envelope.From != a.addr.String() || len(m) != 2 || m["envelope"]["identity"] != nil {
			t.Errorf("%s: %q", name, a.read(name))
		}
		id, _ := s.Receipt["id"].(string)
		if got := strings.TrimSpace(a.must(`jq -c .receipt "$DR/` + name + `"`)); got != receipts[id] {
			t.Errorf("%s's receipt %s is not the server's, %s", name, got, receipts[id])
		}
		if got, want := a.must(`jq -c .envelope "$DR/`+name+`"`), b.must(`jq -c . "$DR/inbox/`+id+`.json"`); got != want {
			t.Errorf("%s is not the line its reader delivered, and the receipt: %q, %q", name, got, want)
		}
	}
}

// A renewal the server does not take is sent again as it was signed, while
// the mailbox still polls; once that statement has expired, a new key is
// signed at a later number; when one is taken, it is the first signed after
// the passed-over one.
func TestScriptRenewsAgainAsSigned(t *testing.T) {
	w := newWorld(t)
	a, b := w.mailbox(), w.mailbox()
	s0 := b.num()
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/prekey") {
			forge.Refuse(rw, protocol.CodeUnavailable)
			return
		}
		next.ServeHTTP(rw, r)
	})
	if r := b.sh("dr_rekey"); r.rc == 0 {
		t.Fatal("a renewal the server refused succeeded")
	}
	first, n := b.read("rekey.json"), b.newest()
	if n <= s0 {
		t.Fatalf("the refused renewal took no new number: %d after %d", n, s0)
	}
	if r := b.sh("dr_rekey"); r.rc == 0 || !b.has(fmt.Sprintf("prekeys/%d.txt.sig", n)) || b.read("rekey.json") != first {
		t.Errorf("the renewal sent again is not the one signed: %v", r)
	}
	if b.num() != s0 {
		t.Errorf("while it waits, the mailbox's serial is %d, not %d", b.num(), s0)
	}
	a.mustSend(b, "while B waits")
	if d := b.recv(); !slices.Equal(d.bodies(), []string{"while B waits"}) {
		t.Errorf("a drain while the renewal waits: %v", d)
	}
	held := b.read(fmt.Sprintf("prekeys/%d.txt", n))
	b.dated(n, time.Now().Add(-time.Minute))
	if r := b.sh("dr_rekey"); r.rc == 0 {
		t.Fatal("a renewal the server refused succeeded")
	}
	m := b.newest()
	key := func(n uint64) string { return b.must(fmt.Sprintf(`age-keygen -y "$DR/prekeys/%d.agekey"`, n)) }
	if m <= n || !b.has(fmt.Sprintf("prekeys/%d.txt.sig", m)) || !b.has(fmt.Sprintf("prekeys/%d.agekey", n)) || key(n) == key(m) {
		t.Errorf("once that statement expired: %q", b.files("prekeys"))
	}
	writeFile(t, b.file(fmt.Sprintf("prekeys/%d.txt", n)), []byte(held))
	signed := b.read(fmt.Sprintf("prekeys/%d.txt", m))
	w.honest()
	b.must("dr_rekey")
	if st, _ := w.srv.Prekey(b.addr); !bytes.Equal(st, []byte(signed)) || b.num() != m {
		t.Errorf("the renewal taken is not the one signed first after the passed-over one: serial %d, %d", b.num(), m)
	}
}

// A mailbox the server forgot, past its record's expiry (PROTOCOL.md §13), with
// its own files kept: no mailbox is served to number above, so dr_rekey numbers
// above what it published, registers anew, and prints no error; messages flow.
func TestScriptRegistersAForgottenMailboxAnew(t *testing.T) {
	w := newWorld(t)
	a, b := w.mailbox(), w.mailbox()
	w.srv.Forget(b.addr)
	n0, calls := b.num(), len(w.srv.Requests())
	if r := b.sh("dr_rekey"); r.rc != 0 || r.err != "" || b.num() <= n0 || !slices.Contains(w.calls(calls), "PUT /v1/"+b.addr.String()) {
		t.Fatalf("a mailbox the server forgot: %v, number %d after %d", r, b.num(), n0)
	}
	if p, _ := w.served(b); p != b.num() {
		t.Errorf("the mailbox registered anew is served at %d, not %d", p, b.num())
	}
	a.mustSend(b, "after it was forgotten")
	if d := b.recv(); !slices.Equal(d.bodies(), []string{"after it was forgotten"}) {
		t.Errorf("a message to the mailbox registered anew: %v", d)
	}
}
