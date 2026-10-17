package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// When things fail, mail is never lost and never delivered twice: a
// transient failure leaves it for next time, a retry is recognised, and a
// fault in the box itself stops the drain instead of judging mail it cannot
// judge.

func TestRoundTrip(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.PostQuantum), e.box(protocol.Classic)
	body := "hello <b>&é☃ — mail is data"
	r := send(t, a, b, body)
	res := receive(t, b)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != body || res.Delivered[0].ID != r.ID {
		t.Fatalf("delivered %+v", res)
	}
	if !bytes.Contains(res.Delivered[0].Line, []byte("<b>&")) {
		t.Fatal("the line is HTML-escaped")
	}
	if res := receive(t, b); len(res.Delivered) != 0 {
		t.Fatal("delivered twice")
	}
	send(t, b, a, "reply")
	if res := receive(t, a); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "reply" {
		t.Fatal("no reply")
	}
}

func TestTransientFailureLeavesMail(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	r := send(t, a, b, "survives a failed fetch")
	failOnce(e, http.MethodGet, "/messages/"+r.ID)
	if _, err := b.Receive(context.Background()); err == nil {
		t.Fatal("the failed fetch was not reported")
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("the mail left by a failed fetch was not delivered next time")
	}
}

// A message delivered but not acked (the ack failed) is acked on the next
// drain, never judged again and reported as a replay.
func TestFailedAckIsRetriedQuietly(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	r := send(t, a, b, "delivered, ack lost")
	failOnce(e, http.MethodDelete, "/messages/"+r.ID)
	res, err := b.Receive(context.Background())
	if err == nil || res == nil || len(res.Delivered) != 1 {
		t.Fatalf("first drain: %v", err)
	}
	e.srv.SetMiddle(nil)
	res = receive(t, b)
	if len(res.Delivered) != 0 || len(res.Refused) != 0 || len(res.Duplicates) != 0 {
		t.Fatalf("second drain: delivered %d, refused %v, duplicates %v", len(res.Delivered), res.Refused, res.Duplicates)
	}
	if e.srv.Count(b.Address()) != 0 {
		t.Fatal("not acked on the second drain")
	}
}

// The same envelope re-encrypted (as after stale_prekey) is a new ciphertext
// with the same msg_id: acked, and not delivered again.
func TestDuplicateRetryIsAckedNotDelivered(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "do this once")
	first := receive(t, b)
	if len(first.Delivered) != 1 {
		t.Fatalf("delivered %d", len(first.Delivered))
	}
	// The line A signed, back in A's outbox: what a send that got no receipt
	// leaves there.
	stem := filepath.Join(a.Dir(), "outbox", b.Address().String()+".00000000-0000-4000-8000-000000000000")
	if err := os.WriteFile(stem+".P", first.Delivered[0].Plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	res := receive(t, b)
	if len(res.Delivered) != 0 || len(res.Duplicates) != 1 {
		t.Fatalf("delivered %d, duplicates %d", len(res.Delivered), len(res.Duplicates))
	}
	if e.srv.Count(b.Address()) != 0 {
		t.Fatal("the duplicate was not acked")
	}
}

// On 409 stale_prekey the client re-encrypts the SAME envelope to the newer
// prekey: same msg_id, so the recipient can never act on it twice.
func TestStalePrekeyReencryptsSameEnvelope(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.PostQuantum), e.box(protocol.PostQuantum)
	failOnce(e, http.MethodPost, "/v1/"+b.Address().String()+"/messages")
	if _, err := a.Send(context.Background(), b.Address(), "kept"); err == nil {
		t.Fatal("the send should have failed")
	}
	e.srv.SetMiddle(nil)
	outbox, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P"))
	if len(outbox) != 1 {
		t.Fatalf("outbox holds %d", len(outbox))
	}
	p, _ := os.ReadFile(outbox[0])
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if rs, err := a.Flush(context.Background()); err != nil || len(rs) != 1 {
		t.Fatalf("flush: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*")); len(left) != 0 {
		t.Fatalf("outbox not emptied: %v", left)
	}
	res := receive(t, b)
	if len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	// The same signed line, byte for byte: only the padding after its
	// signature is made again, for the newer prekey.
	if !bytes.Equal(res.Delivered[0].Plaintext, p) {
		t.Fatal("the re-encrypted message is not the same envelope")
	}
}

// A box restored from its identity alone, its backup, gets a new working key,
// certificate and prekey from Rekey and receives again: the address is the
// identity, and nothing else needs keeping.
func TestRestoreFromIdentity(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	dir := t.TempDir()
	key, err := os.ReadFile(filepath.Join(b.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := client.Open(dir, e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if r.Address() != b.Address() {
		t.Fatal("the restored box has another address")
	}
	landAll(t, r)
	if _, err := r.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	send(t, a, r, "to the restored box")
	if res := receive(t, r); len(res.Delivered) != 1 {
		t.Fatal("the restored box received nothing")
	}
}

// passes records the Authorization value of every call a box makes as itself.
func passes(e *env) *[]string {
	var seen []string
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if a := r.Header.Get("Authorization"); a != "" {
			seen = append(seen, a)
		}
		next.ServeHTTP(w, r)
	})
	return &seen
}

// A box signs one pass and uses it for every call until it is about to run
// out, so a server checks one signature for ten minutes of calls. It is kept
// in the box: a new process uses the same one.
func TestAPassIsUsedUntilItRunsOut(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	seen := passes(e)
	send(t, a, b, "one")
	receive(t, b)
	again, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	receive(t, again)
	first := map[string]bool{}
	for _, p := range *seen {
		first[p] = true
	}
	if len(*seen) < 4 || len(first) != 2 {
		t.Fatalf("%d calls carried %d passes: want one for each of the two boxes", len(*seen), len(first))
	}
	for p := range first {
		if !strings.HasPrefix(p, "irongall-pass address=\"") {
			t.Fatalf("not a pass: %s", p)
		}
	}
	// Past its ten minutes, a new one.
	e.clock.Add(protocol.PassLifetime)
	*seen = nil
	receive(t, b)
	if len(*seen) == 0 || first[(*seen)[0]] {
		t.Fatal("a pass that had run out was sent again")
	}
}

// A new prekey comes with a new certificate, and the server then takes no
// pass under the old one. A client still holding such a pass is refused once,
// signs another under the certificate in use, and carries on.
func TestAPassUnderAnOlderCertificateIsReplaced(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	receive(t, b)
	old, err := os.ReadFile(filepath.Join(b.Dir(), "pass"))
	if err != nil {
		t.Fatal(err)
	}
	first := numberOf(t, b)
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if cur, _ := os.ReadFile(filepath.Join(b.Dir(), "pass")); bytes.Equal(old, cur) {
		t.Fatal("a new certificate did not bring a new pass")
	}
	if exists(workFile(b, first, "")) || !exists(workFile(b, numberOf(t, b), "-cert.pub")) {
		t.Fatal("the older working key was kept, or the new one is missing")
	}
	if err := os.WriteFile(filepath.Join(b.Dir(), "pass"), old, 0o600); err != nil {
		t.Fatal(err)
	}
	send(t, a, b, "after the rekey")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("no delivery after the pass was replaced")
	}
	if now, _ := os.ReadFile(filepath.Join(b.Dir(), "pass")); bytes.Equal(now, old) {
		t.Fatal("the refused pass is still the one kept")
	}
}

// A server whose clock is ahead calls a pass run out before the box does.
// The box signs another and tries once more, and no more than once.
func TestAPassTheServerSaysHasRunOut(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	refusals := 1
	calls := 0
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/messages") {
			calls++
			if calls <= refusals {
				w.Header().Set("Content-Type", protocol.ProblemContentType)
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(protocol.Problem{Type: protocol.CodePassExpired.TypeURI(), Status: http.StatusUnauthorized, Code: protocol.CodePassExpired})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
	if _, err := b.Receive(context.Background()); err != nil || calls != 2 {
		t.Fatalf("receive after one refusal: %v, in %d calls", err, calls)
	}
	refusals, calls = 100, 0
	if _, err := b.Receive(context.Background()); client.Code(err) != protocol.CodePassExpired || calls != 2 {
		t.Fatalf("receive from a server that refuses every pass: %v, in %d calls, want pass_expired after 2", err, calls)
	}
}

// One command of a box at a time. The recipe's lock (an empty lock/) is
// never taken over or written into: a command waits for it, and gives up
// once it has waited as long as it waits. A lock a crashed Go client left
// (lock/pid, held by no one) is taken over.
func TestLock(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	lock := filepath.Join(b.Dir(), "lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	client.SetLockPatience(t, 200*time.Millisecond)
	if _, err := b.Receive(context.Background()); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("receive under the recipe's lock: %v", err)
	}
	if _, err := b.Rekey(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("rekey under the recipe's lock: %v", err)
	}
	if entries, _ := os.ReadDir(lock); len(entries) != 0 {
		t.Fatal("a file was left in the recipe's lock")
	}
	if err := os.WriteFile(filepath.Join(lock, "pid"), []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	receive(t, b)
	if exists(lock) {
		t.Fatal("the lock was not released")
	}
}

// A rekey waits for a drain holding the lock rather than failing at once, as
// every command does: a monthly run that gives up on one collision lets the
// prekey expire.
func TestRekeyWaitsForTheLock(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	lock := filepath.Join(b.Dir(), "lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.Remove(lock)
	}()
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatalf("rekey after the lock was released: %v", err)
	}
}

func TestLiveLockExcludes(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
	client.SetLockPatience(t, 200*time.Millisecond)
	lock := filepath.Join(b.Dir(), "lock")
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(lock, "pid"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString("1\n")
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { //nolint:gosec // a file descriptor fits an int
		t.Fatal(err)
	}
	if _, err := b.Receive(context.Background()); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("receive while another consumer holds the lock: %v", err)
	}
}

// A retired prekey decrypts mail until its deletion time, not_after + 33
// days, and is deleted then: the forward-secrecy bound.
func TestPruneDeletesRetiredKeys(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	send(t, a, b, "to the first key")
	key1 := prekeyFile(b, numberOf(t, b), ".agekey")
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("mail to the retired key was not delivered")
	}
	e.clock.Add(protocol.PrekeyLifetime + protocol.TTL - time.Second)
	if err := b.Prune(); err != nil {
		t.Fatal(err)
	}
	if !exists(key1) {
		t.Fatal("deleted before its deletion time")
	}
	e.clock.Add(time.Second)
	if err := b.Prune(); err != nil {
		t.Fatal(err)
	}
	if exists(key1) {
		t.Fatal("not deleted at not_after + 33 days")
	}
	if !exists(prekeyFile(b, numberOf(t, b), ".agekey")) {
		t.Fatal("the current key was deleted")
	}
}

// A fault in the box itself is an error, never a verdict on the message:
// the drain stops, nothing is quarantined or acked, and the mail is
// delivered once the box is fixed.
func TestLocalFaultLeavesMail(t *testing.T) {
	for _, c := range []struct {
		name     string
		breakBox func(t *testing.T, b *client.Box, a protocol.Address) (fix func())
	}{
		{"the seen-set unreadable", func(t *testing.T, b *client.Box, _ protocol.Address) func() {
			seen := filepath.Join(b.Dir(), "seen")
			_ = os.Remove(seen)
			if err := os.Mkdir(seen, 0o700); err != nil {
				t.Fatal(err)
			}
			return func() { _ = os.Remove(seen) }
		}},
		{"a prekey file unreadable", func(t *testing.T, b *client.Box, _ protocol.Address) func() {
			k := filepath.Join(b.Dir(), "prekeys", "9.agekey")
			if err := os.WriteFile(k, []byte("not an age key\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return func() { _ = os.Remove(k) }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.box(protocol.Classic), e.box(protocol.Classic)
			send(t, a, b, "pins A")
			receive(t, b)
			send(t, a, b, "waits for the box to be fixed")
			fix := c.breakBox(t, b, a.Address())
			res, err := b.Receive(context.Background())
			if err == nil || (res != nil && (len(res.Refused) != 0 || len(res.Delivered) != 0)) {
				t.Fatalf("drain on a broken box: %v, %+v", err, res)
			}
			if q, _ := os.ReadDir(filepath.Join(b.Dir(), "quarantine")); len(q) != 0 || e.srv.Count(b.Address()) != 1 {
				t.Fatal("a broken box quarantined or acked mail it could not judge")
			}
			fix()
			if res := receive(t, b); len(res.Delivered) != 1 {
				t.Fatalf("after the fix: %+v", res)
			}
		})
	}
}

// Flush tries every entry: one that fails never blocks the others. One that
// can never be delivered (refused for good, or older than any recipient
// accepts) moves to outbox/failed/; one that may yet go stays.
func TestFlushNeverStopsAtABadEntry(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	var nobody protocol.Address // sorts first in the outbox
	if _, err := a.Send(ctx, nobody, "to an address no box has"); err == nil || !strings.Contains(err.Error(), "kept in the outbox") {
		t.Fatalf("send to nobody: %v", err)
	}
	failOnce(e, http.MethodPost, "/v1/"+b.Address().String()+"/messages")
	if _, err := a.Send(ctx, b.Address(), "fails once"); err == nil {
		t.Fatal("the send should have failed")
	}
	e.srv.SetMiddle(nil)
	revoke(t, e, c) // revoked for good, with the revocation to show for it
	if _, err := a.Send(ctx, c.Address(), "to a revoked box"); err == nil || !strings.Contains(err.Error(), "outbox/failed") {
		t.Fatalf("send to a revoked box: %v", err)
	}

	rs, err := a.Flush(ctx)
	if len(rs) != 1 || err == nil || !strings.Contains(err.Error(), "no_such_mailbox") {
		t.Fatalf("flush: %d sent, %v", len(rs), err)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("the entry after the bad one was not sent")
	}
	outbox := filepath.Join(a.Dir(), "outbox")
	if left, _ := filepath.Glob(filepath.Join(outbox, "*.P")); len(left) != 1 || !strings.HasPrefix(filepath.Base(left[0]), nobody.String()) {
		t.Fatalf("outbox: %v", left)
	}
	if failed, _ := filepath.Glob(filepath.Join(outbox, "failed", c.Address().String()+".*.P")); len(failed) != 1 {
		t.Fatal("the revoked box's entry did not move to outbox/failed/")
	}
	// Past 33 days no recipient accepts it: it moves to failed/ too.
	e.clock.Add(protocol.TTL + time.Second)
	if _, err := a.Flush(ctx); err == nil {
		t.Fatal("flush of an undeliverable entry reported nothing")
	}
	if left, _ := filepath.Glob(filepath.Join(outbox, "*.P")); len(left) != 0 {
		t.Fatalf("an entry older than 33 days stayed: %v", left)
	}
}

// An entry older than any recipient accepts is never posted, even when the
// server would take it: it moves to outbox/failed/, with no receipt.
func TestStaleOutboxEntryIsNotPosted(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	failOnce(e, http.MethodPost, "/v1/"+b.Address().String()+"/messages")
	if _, err := a.Send(ctx, b.Address(), "stuck"); err == nil {
		t.Fatal("the send should have failed")
	}
	e.clock.Add(protocol.TTL + time.Second)
	rs, err := a.Flush(ctx)
	if len(rs) != 0 || err == nil || !strings.Contains(err.Error(), "outbox/failed") {
		t.Fatalf("flush: %d sent, %v", len(rs), err)
	}
	if e.srv.Count(b.Address()) != 0 {
		t.Fatal("an entry older than 33 days was posted")
	}
	if failed, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "failed", b.Address().String()+".*.P")); len(failed) != 1 {
		t.Fatal("the stale entry did not move to outbox/failed/")
	}
}

// A rekey asked for a key type makes that type. A statement an earlier
// attempt signed for a key of the other type is never signed over: its serial
// is passed over and its key kept.
func TestRekeyMakesTheTypeAskedFor(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	failOnce(e, http.MethodPut, "/prekey")
	if _, err := b.Rekey(ctx, ""); err == nil {
		t.Fatal("the rekey should have failed")
	}
	leftAt := begunAt(t, b)
	left := prekeyFile(b, leftAt, "")
	signed, _ := os.ReadFile(left + ".txt")
	e.srv.SetMiddle(nil)
	p, err := b.Rekey(ctx, protocol.PostQuantum)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := e.srv.Prekey(b.Address())
	served, _ := protocol.ParsePrekey(st)
	if p.Type() != protocol.PostQuantum || served.Type() != protocol.PostQuantum || served.Serial <= leftAt {
		t.Fatalf("published serial %d of type %s", served.Serial, served.Type())
	}
	if now, _ := os.ReadFile(left + ".txt"); len(signed) == 0 || !bytes.Equal(now, signed) || !exists(left+".agekey") {
		t.Fatal("the statement the failed attempt signed was changed, or its key deleted")
	}
}

// A body that is not UTF-8 is refused before anything is sent: JSON would
// replace its bytes.
func TestNonUTF8BodyIsRefused(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	if _, err := a.Send(context.Background(), b.Address(), "\xff\xfe"); err == nil {
		t.Fatal("a non-UTF-8 body was sent")
	}
	if e.srv.Count(b.Address()) != 0 {
		t.Fatal("something was sent")
	}
}
