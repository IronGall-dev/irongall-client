package client_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
	bolt "go.etcd.io/bbolt"
)

// When things fail, a message is never lost and never delivered twice: a
// transient failure leaves it for next time, a retry is recognised, and a
// fault in the mailbox itself stops the drain instead of judging a message it cannot
// judge.

func TestRoundTrip(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.PostQuantum), e.mailbox(protocol.Classic)
	body := "hello <b>&é☃ — a message is data"
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

func TestTransientFailureLeavesTheMessage(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	r := send(t, a, b, "survives a failed fetch")
	forge.FailOnce(e.srv, http.MethodGet, "/messages/"+r.ID)
	if _, err := b.Receive(context.Background()); err == nil {
		t.Fatal("the failed fetch was not reported")
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("the message left by a failed fetch was not delivered next time")
	}
}

// A message delivered but not acked (the ack failed) is acked on the next
// drain, never judged again and reported as a replay.
func TestFailedAckIsRetriedQuietly(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	r := send(t, a, b, "delivered, ack lost")
	forge.FailOnce(e.srv, http.MethodDelete, "/messages/"+r.ID)
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
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
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
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.PostQuantum), e.mailbox(protocol.PostQuantum)
	forge.FailOnce(e.srv, http.MethodPost, "/v1/"+b.Address().String()+"/messages")
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

// A mailbox restored from its identity alone, its backup, gets a new working key,
// certificate and prekey from Rekey and receives again: the address is the
// identity, and nothing else needs keeping. Open makes what every mailbox has,
// its .gitignore among it (#292).
func TestRestoreFromIdentity(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
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
		t.Fatal("the restored mailbox has another address")
	}
	if got, err := os.ReadFile(filepath.Join(dir, ".gitignore")); err != nil || string(got) != "*\n" {
		t.Errorf("the restored mailbox's .gitignore: %q, %v", got, err)
	}
	landAll(t, r)
	if _, err := r.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	send(t, a, r, "to the restored mailbox")
	if res := receive(t, r); len(res.Delivered) != 1 {
		t.Fatal("the restored mailbox received nothing")
	}
}

// passes records the Authorization value of every call a mailbox makes as itself.
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

// A mailbox signs one pass and uses it for every call until it is about to run
// out, so a server checks one signature for ten minutes of calls. It is kept
// in the mailbox: a new process uses the same one.
func TestAPassIsUsedUntilItRunsOut(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
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
		t.Fatalf("%d calls carried %d passes: want one for each of the two mailboxes", len(*seen), len(first))
	}
	for p := range first {
		if !strings.HasPrefix(p, "dromas-pass address=\"") {
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
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	receive(t, b)
	old, ok := stateOf(b, "pass")
	if !ok {
		t.Fatal("no pass kept")
	}
	first := numberOf(t, b)
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if cur, _ := stateOf(b, "pass"); bytes.Equal(old, cur) {
		t.Fatal("a new certificate did not bring a new pass")
	}
	if exists(workFile(b, first, "")) || !exists(workFile(b, numberOf(t, b), "-cert.pub")) {
		t.Fatal("the older working key was kept, or the new one is missing")
	}
	b.SetRecord(t, "pass", old)
	send(t, a, b, "after the rekey")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("no delivery after the pass was replaced")
	}
	if now, _ := stateOf(b, "pass"); bytes.Equal(now, old) {
		t.Fatal("the refused pass is still the one kept")
	}
}

// Every code that refuses the pass a call carried has the mailbox sign another
// and try once more under it, never the pass refused, which the server would
// refuse again (PROTOCOL.md §8): after pass_expired the same pass is the
// clock's sign, and the mailbox's pass after certificate_revoked is signed anew
// too (#408 item 3). The codes are read from the code, every one protocol
// knows that passRefused takes, and those are every 401's (§11.3).
func TestEveryRefusalOfThePassIsTriedUnderANewOne(t *testing.T) {
	t.Parallel()
	var refusing []protocol.Code
	for _, c := range protocol.Codes() {
		if client.PassRefused(c) != (c.Status() == http.StatusUnauthorized) {
			t.Errorf("%s, a %d: taken as a refusal of the pass %v", c, c.Status(), client.PassRefused(c))
		}
		if client.PassRefused(c) {
			refusing = append(refusing, c)
		}
	}
	if len(refusing) == 0 {
		t.Fatal("no code refuses the pass")
	}
	for _, c := range refusing {
		t.Run(string(c), func(t *testing.T) {
			e := newEnv(t)
			b := e.mailbox(protocol.Classic)
			list := mailboxPath(b) + "/messages"
			var mu sync.Mutex
			var passes []string
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == http.MethodGet && r.URL.Path == list {
					mu.Lock()
					passes = append(passes, r.Header.Get("Authorization"))
					first := len(passes) == 1
					mu.Unlock()
					if first {
						forge.Refuse(w, c)
						return
					}
				}
				next.ServeHTTP(w, r)
			})
			e.clock.Add(time.Minute) // within the kept pass's life, and a second past its date
			if _, err := b.Receive(context.Background()); err != nil {
				t.Fatalf("a drain whose list was refused %s once: %v", c, err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(passes) < 2 || passes[0] == "" || passes[1] == passes[0] {
				t.Errorf("after %s the drain's list carried %d passes, the second the one refused: %v", c, len(passes), len(passes) >= 2 && passes[1] == passes[0])
			}
		})
	}
}

// A server whose clock is ahead calls a pass run out before the mailbox does.
// The mailbox signs another and tries once more, and no more than once.
func TestAPassTheServerSaysHasRunOut(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
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

// A lock whose holder was killed is free at once: the kernel lets go of its
// flock, and nothing is left to take over or remove (#235).
func TestAKilledHolderLeavesNoLock(t *testing.T) {
	if dir := os.Getenv("DROMAS_TEST_HOLD_STATE"); dir != "" {
		db, err := bolt.Open(filepath.Join(dir, "state"), 0o600, &bolt.Options{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		_ = db
		fmt.Println("held")
		time.Sleep(time.Minute)
		return
	}
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
	cmd := exec.Command(os.Args[0], "-test.run=^TestAKilledHolderLeavesNoLock$") //nolint:gosec // this test binary, again
	cmd.Env = append(os.Environ(), "DROMAS_TEST_HOLD_STATE="+b.Dir())
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }) // a test that failed first
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "held\n" {
		t.Fatalf("the holder: %q, %v", line, err)
	}
	client.SetLockPatience(t, 200*time.Millisecond)
	if _, err := b.Receive(context.Background()); err == nil || !strings.Contains(err.Error(), "lock") {
		t.Fatalf("receive while the holder lives: %v", err)
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	receive(t, b)
}

// A retired prekey decrypts messages until its deletion time, not_after + 33
// days, and is deleted then: the forward-secrecy bound. A renewal deletes by
// the date of its own pass, which the server took, and it signs a new one.
func TestPruneDeletesRetiredKeys(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	send(t, a, b, "to the first key")
	key1 := prekeyFile(b, numberOf(t, b), ".agekey")
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatal("a message to the retired key was not delivered")
	}
	e.clock.Add(protocol.PrekeyLifetime + protocol.TTL - time.Second)
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if !exists(key1) {
		t.Fatal("deleted before its deletion time")
	}
	e.clock.Add(time.Second)
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	if exists(key1) {
		t.Fatal("not deleted at not_after + 33 days")
	}
	if !exists(prekeyFile(b, numberOf(t, b), ".agekey")) {
		t.Fatal("the current key was deleted")
	}
}

// A fault in the mailbox itself is an error, never a verdict on the message:
// the drain stops, nothing is kept in refused/ or acked, and the message is
// delivered once the mailbox is fixed.
func TestLocalFaultLeavesTheMessage(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name         string
		breakMailbox func(t *testing.T, b *client.Mailbox, a protocol.Address) (fix func())
	}{
		{"the replay set's floor unreadable", func(t *testing.T, b *client.Mailbox, _ protocol.Address) func() {
			b.SetRecord(t, "seen-floor", []byte("soon"))
			return func() { b.SetRecord(t, "seen-floor", nil) }
		}},
		{"a prekey file unreadable", func(t *testing.T, b *client.Mailbox, _ protocol.Address) func() {
			k := filepath.Join(b.Dir(), "prekeys", "9.agekey")
			if err := os.WriteFile(k, []byte("not an age key\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return func() { _ = os.Remove(k) }
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			send(t, a, b, "pins A")
			receive(t, b)
			send(t, a, b, "waits for the mailbox to be fixed")
			fix := c.breakMailbox(t, b, a.Address())
			res, err := b.Receive(context.Background())
			if err == nil || (res != nil && (len(res.Refused) != 0 || len(res.Delivered) != 0)) {
				t.Fatalf("drain on a broken mailbox: %v, %+v", err, res)
			}
			if q, _ := os.ReadDir(filepath.Join(b.Dir(), "refused")); len(q) != 0 || e.srv.Count(b.Address()) != 1 {
				t.Fatal("a broken mailbox kept in refused/ or acked a message it could not judge")
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
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b, c := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	var nobody protocol.Address // sorts first in the outbox
	if _, err := a.Send(ctx, nobody, "to an address no mailbox has"); err == nil || !strings.Contains(err.Error(), "kept in the outbox") {
		t.Fatalf("send to nobody: %v", err)
	}
	forge.FailOnce(e.srv, http.MethodPost, "/v1/"+b.Address().String()+"/messages")
	if _, err := a.Send(ctx, b.Address(), "fails once"); err == nil {
		t.Fatal("the send should have failed")
	}
	e.srv.SetMiddle(nil)
	revoke(t, e, c) // revoked for good, with the revocation to show for it
	if _, err := a.Send(ctx, c.Address(), "to a revoked mailbox"); err == nil || !strings.Contains(err.Error(), "outbox/failed") {
		t.Fatalf("send to a revoked mailbox: %v", err)
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
		t.Fatal("the revoked mailbox's entry did not move to outbox/failed/")
	}
	// Written more than 33 days ago, it is posted no more: it moves to
	// failed/ too.
	e.clock.Add(protocol.TTL + time.Second)
	if _, err := a.Flush(ctx); err == nil {
		t.Fatal("flush of an undeliverable entry reported nothing")
	}
	if left, _ := filepath.Glob(filepath.Join(outbox, "*.P")); len(left) != 0 {
		t.Fatalf("an entry written more than 33 days ago stayed: %v", left)
	}
}

// An entry written more than 33 days ago is never posted, even when the
// server would take it: an outbox posts one for 33 days from when it was
// written, the window a reader's replay set reaches back over past a first
// post. It moves to outbox/failed/, with no receipt.
func TestStaleOutboxEntryIsNotPosted(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	forge.FailOnce(e.srv, http.MethodPost, "/v1/"+b.Address().String()+"/messages")
	if _, err := a.Send(ctx, b.Address(), "stuck"); err == nil {
		t.Fatal("the send should have failed")
	}
	e.clock.Add(protocol.TTL + time.Second)
	rs, err := a.Flush(ctx)
	if len(rs) != 0 || err == nil || !strings.Contains(err.Error(), "outbox/failed") || !strings.Contains(err.Error(), "written more than 33 days ago") {
		t.Fatalf("flush: %d sent, %v", len(rs), err)
	}
	if e.srv.Count(b.Address()) != 0 {
		t.Fatal("an entry written more than 33 days ago was posted")
	}
	if failed, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "failed", b.Address().String()+".*.P")); len(failed) != 1 {
		t.Fatal("the stale entry did not move to outbox/failed/")
	}
}

// A rekey asked for a key type makes that type. A statement an earlier
// attempt signed for a key of the other type is never signed over: its serial
// is passed over and its key kept.
func TestRekeyMakesTheTypeAskedFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
	forge.FailOnce(e.srv, http.MethodPut, "/prekey")
	if _, err := b.Rekey(ctx, ""); err == nil {
		t.Fatal("the rekey should have failed")
	}
	leftAt := begunAt(t, b)
	left := prekeyFile(b, leftAt, "")
	signed := statement(t, b, leftAt, ".txt")
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
	if now := statement(t, b, leftAt, ".txt"); len(signed) == 0 || !bytes.Equal(now, signed) || !exists(left+".agekey") {
		t.Fatal("the statement the failed attempt signed was changed, or its key deleted")
	}
}

// A body that is not UTF-8 is refused before anything is sent: JSON would
// replace its bytes.
func TestNonUTF8BodyIsRefused(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	if _, err := a.Send(context.Background(), b.Address(), "\xff\xfe"); err == nil {
		t.Fatal("a non-UTF-8 body was sent")
	}
	if e.srv.Count(b.Address()) != 0 {
		t.Fatal("something was sent")
	}
}
