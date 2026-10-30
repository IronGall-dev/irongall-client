package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A crash is a mailbox's process killed between two of the steps at which a
// command writes the mailbox (steps.go names each): the next command finds the
// mailbox whole, and goes on from where the last left it. Each case kills a copy
// of this test binary at one step, with SIGKILL, so nothing of the process
// runs after it: no deferred call, no close, no further write. What it cannot
// show is a power cut, where what was not synced is lost: each step syncs
// before the next begins (writeFile, bbolt's commit), and a test cannot pull
// the power (#316).

// crashChild is the environment variable a copy of this binary reads to run
// one command of a mailbox and die at one step.
const crashChild = "DROMAS_TEST_CRASH"

// crashOrder is what the copy runs: the step it dies at, the mailbox's directory,
// its server's URL, its clock in Unix seconds, the command, and for a send,
// the address it goes to.
type crashOrder struct {
	Step, Dir, Base, Command, To string
	Now                          int64
}

// crashCommands are what a copy runs, by name.
var crashCommands = map[string]func(ctx context.Context, b *client.Mailbox, o crashOrder) error{
	"rekey": func(ctx context.Context, b *client.Mailbox, _ crashOrder) error {
		_, err := b.Rekey(ctx, "")
		return err
	},
	"receive": func(ctx context.Context, b *client.Mailbox, _ crashOrder) error { _, err := b.Receive(ctx); return err },
	"remedy": func(ctx context.Context, b *client.Mailbox, _ crashOrder) error {
		_, err := b.RenewAndRevoke(ctx, "")
		return err
	},
	"send": func(ctx context.Context, b *client.Mailbox, o crashOrder) error {
		to, err := protocol.ParseAddress(o.To)
		if err != nil {
			return err
		}
		_, err = b.Send(ctx, to, "sent by a process killed on its way")
		return err
	},
}

// TestCrashChild is the copy of this binary that runs one command and is
// killed at one step: in a test run of its own it does nothing.
func TestCrashChild(t *testing.T) {
	raw := os.Getenv(crashChild)
	if raw == "" {
		t.Skip("run by the crash tests, in a process of its own")
	}
	var o crashOrder
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatal(err)
	}
	client.SetStep(func(name string) {
		if name == o.Step {
			killSelf(o.Step)
			time.Sleep(time.Minute) // the signal is on its way
		}
	})
	now := time.Unix(o.Now, 0).UTC()
	b, err := client.Open(o.Dir, client.Options{Base: o.Base, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	err = crashCommands[o.Command](context.Background(), b, o)
	fmt.Printf("ended before %s: %v\n", o.Step, err)
}

// crash runs command on mailbox b in a copy of this binary, killed at step, and
// fails the test unless it died there.
func crash(t *testing.T, e *env, b *client.Mailbox, command, step string, to protocol.Address) {
	t.Helper()
	order, err := json.Marshal(crashOrder{Step: step, Dir: b.Dir(), Base: e.srv.URL, Command: command, To: to.String(), Now: e.clock.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1") //nolint:gosec // this test binary, again
	cmd.Env = append(os.Environ(), crashChild+"="+string(order))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !killedAt(exit, out, step) {
		t.Fatalf("%s did not die at %s: %v\n%s", command, step, err, out)
	}
}

// inbox is the body of each message in a mailbox's inbox/, as many times as it is
// there.
func inbox(t *testing.T, b *client.Mailbox) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(b.Dir(), "inbox", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	var bodies []string
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		var line struct{ Body string }
		if err := json.Unmarshal(raw, &line); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		bodies = append(bodies, line.Body)
	}
	slices.Sort(bodies)
	return bodies
}

// whole checks a mailbox after a crash by its next commands, opened anew from its
// directory: a drain takes everything waiting on its server, refusing
// nothing; a renewal goes through, and its server serves the prekey it
// published; mail sealed to the new one is read; and the inbox holds every
// message sent to the mailbox, once: waiting, sent before the crash, and those
// sent here.
func whole(t *testing.T, e *env, b, from *client.Mailbox, waiting ...string) {
	t.Helper()
	ctx := context.Background()
	x, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	send(t, from, x, "after the crash")
	res, err := x.Receive(ctx)
	if err != nil || len(res.Refused) != 0 || e.srv.Count(x.Address()) != 0 {
		t.Fatalf("the drain after the crash: %+v, %v; the server still holds %d", res, err, e.srv.Count(x.Address()))
	}
	e.clock.Add(2 * time.Second)
	if _, err := x.Rekey(ctx, ""); err != nil {
		t.Fatalf("the renewal after the crash: %v", err)
	}
	if served := servedSerial(t, e, x); served != numberOf(t, x) {
		t.Fatalf("the server serves %d, the mailbox published %d", served, numberOf(t, x))
	}
	send(t, from, x, "after the renewal")
	if res := receive(t, x); len(res.Delivered) != 1 {
		t.Fatalf("after the renewal: %+v", res)
	}
	want := append(slices.Clone(waiting), "after the crash", "after the renewal")
	slices.Sort(want)
	if got := inbox(t, x); !slices.Equal(got, want) {
		t.Fatalf("inbox/ holds %q, want %q: each message once", got, want)
	}
}

// A renewal killed at each of its steps: the next drain delivers what was
// sealed to the prekey in use before it, and the mailbox renews again.
func TestARenewalKilledAtEachStepLeavesTheMailboxWhole(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	for _, step := range client.Steps("renewal") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			send(t, a, b, "sealed to the prekey in use")
			e.clock.Add(2 * time.Second)
			crash(t, e, b, "rekey", step, protocol.Address{})
			whole(t, e, b, a, "sealed to the prekey in use")
		})
	}
}

// A mailbox its server forgot, killed at each step of the registration that
// brings it back: its server holds no ACL of it, whatever became of the
// answer, and the next commands send the ACL again (#324). A recv brings the
// mailbox back where the registration was not taken.
func TestAForgottenMailboxKilledAtEachStepOfItsRegistrationSendsItsACLAgain(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	for _, step := range client.Steps("renewal") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b, c := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			if _, err := b.Block(context.Background(), c.Address()); err != nil || e.srv.ACL(b.Address()) == nil {
				t.Fatalf("the block before the mailbox was forgotten: %v", err)
			}
			e.srv.Forget(b.Address())
			e.clock.Add(2 * time.Second)
			crash(t, e, b, "rekey", step, protocol.Address{})
			x, err := client.Open(b.Dir(), e.opts())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x.Receive(context.Background()); err != nil {
				t.Fatalf("the recv after the crash: %v", err)
			}
			whole(t, e, b, a)
			if acl := e.srv.ACL(b.Address()); acl == nil || !slices.Contains(acl.Deny.Addrs, c.Address()) {
				t.Fatalf("after a crash at %s the server holds the ACL %+v, which does not deny the sender the mailbox blocked", step, acl)
			}
		})
	}
}

// A recv whose renewal is due, killed at each step of its renewal and of the
// read of its server's ACL that follows it: the read is owed from before the
// renewal (#377), so the next recv makes it, whichever command recorded the
// renewal. After it the server holds the mailbox's own ACL, and recv has said it
// replaced another writer's where one was there, once, and nothing where
// none was: another writer's deny list or pause, the mailbox's own, and a mailbox
// its server forgot, before the renewal's read or between the read and the
// upload, which the renewal registers again (#386). A send between the kill
// and the next recv, whose pass refused has the mailbox read itself and record a
// renewal taken unseen (ownerTaken), leaves the read owed too.
func TestARecvKilledAtEachStepOfItsRenewalReadsItsServersACL(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	const (
		none = iota
		before
		atUpload
	)
	for _, s := range []struct {
		name   string
		other  func(d protocol.Address) *protocol.ACL
		forget int
		send   bool
	}{
		{"another writer's deny list", func(d protocol.Address) *protocol.ACL {
			return &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(false, []protocol.Address{d})}
		}, none, false},
		{"another writer's deny list, a send first", func(d protocol.Address) *protocol.ACL {
			return &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: protocol.NewACLList(false, []protocol.Address{d})}
		}, none, true},
		{"another writer's pause", func(protocol.Address) *protocol.ACL { return &protocol.ACL{Deny: protocol.ACLList{Any: true}} }, none, false},
		{"its own", nil, none, false},
		{"forgotten before the renewal's read", nil, before, false},
		{"forgotten between the renewal's read and its upload", nil, atUpload, false},
	} {
		for _, step := range append(client.Steps("renewal"), client.Steps("heal")...) {
			if step == "held ACL kept" && s.other == nil {
				continue // nothing another writer put is there to keep
			}
			t.Run(s.name+", "+step, func(t *testing.T) {
				ctx := context.Background()
				e := newEnv(t)
				a, b, c, d := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic), e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
				if _, err := b.Block(ctx, c.Address()); err != nil {
					t.Fatal(err)
				}
				own := e.srv.ACL(b.Address())
				if s.other != nil {
					e.srv.PutACL(b.Address(), s.other(d.Address()))
				}
				switch s.forget {
				case before:
					e.srv.Forget(b.Address())
				case atUpload:
					var forgot atomic.Bool
					e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
						if r.Method == http.MethodPut && r.URL.Path == mailboxPath(b)+"/prekey" && forgot.CompareAndSwap(false, true) {
							e.srv.Forget(b.Address())
						}
						next.ServeHTTP(w, r)
					})
				}
				e.clock.Add(25 * time.Hour)
				crash(t, e, b, "receive", step, protocol.Address{})
				x, err := client.Open(b.Dir(), e.opts())
				if err != nil {
					t.Fatal(err)
				}
				if s.send {
					if _, err := x.Send(ctx, a.Address(), "sent before the next recv"); err != nil {
						t.Fatalf("the send after the crash: %v", err)
					}
				}
				res, err := x.Receive(ctx)
				if err != nil || res.ACLErr != nil || res.RenewErr != nil {
					t.Fatalf("the recv after the crash: %+v, %v", res, err)
				}
				if res.ACLReplaced != (s.other != nil) || !e.srv.ACL(x.Address()).SameLists(own) {
					t.Fatalf("the recv after a crash at %s: acl_replaced %v; the server holds %+v, the mailbox's own is %+v", step, res.ACLReplaced, e.srv.ACL(x.Address()), own)
				}
				if again := receive(t, x); again.ACLReplaced {
					t.Fatalf("the replacement is reported again: %+v", again)
				}
			})
		}
	}
}

// A renewal killed after its key and working key were made, before its
// statement was signed, leaves files no statement names; the remedy, which
// takes nothing an earlier attempt left, passes over that number, and its
// files go (begin; #337).
func TestARemedyPassingOverAKilledRenewalDropsWhatItLeft(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
	e.clock.Add(2 * time.Second)
	crash(t, e, b, "rekey", "prekey made", protocol.Address{})
	x, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := x.Record(t, "renewal")
	left, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		t.Fatalf("the renewal under way: %q, %v", raw, err)
	}
	files := []string{prekeyFile(x, left, ".agekey"), workFile(x, left, ""), workFile(x, left, ".pub"), workFile(x, left, "-cert.pub")}
	for _, f := range files {
		if !exists(f) {
			t.Fatalf("the killed renewal left no %s", f)
		}
	}
	e.clock.Add(2 * time.Second)
	if r, err := x.RenewAndRevoke(context.Background(), ""); err != nil || r == nil || r.Prekey == nil || r.Prekey.Serial <= left {
		t.Fatalf("the remedy: %+v, %v", r, err)
	}
	for _, f := range files {
		if exists(f) {
			t.Errorf("the remedy passed over %d and left %s", left, f)
		}
	}
}

// A renewal the server took, whose answer the mailbox never had, is recorded at
// the mailbox's next read of itself, which a pass refused as under a certificate
// not current sends it to; a later renewal the mailbox has begun keeps its
// number.
func TestARenewalTakenUnseenIsRecordedAndALaterOneKeepsItsNumber(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
	e.clock.Add(2 * time.Second)
	crash(t, e, b, "rekey", "renewal taken", protocol.Address{})
	x, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	took := servedSerial(t, e, x)
	later := []byte(strconv.FormatUint(took+1, 10))
	x.SetRecord(t, "renewal", later)
	receive(t, x)
	if got, _ := x.Record(t, "renewal"); numberOf(t, x) != took || !bytes.Equal(got, later) {
		t.Fatalf("published %d, the renewal under way %q; want %d and %q", numberOf(t, x), got, took, later)
	}
}

// The mailbox's own statement served under another of its certificates, here
// signed again by the working key it used before, by whoever took that key,
// is no renewal the server took: the mailbox records it only once it is served
// under the certificate the mailbox made with it.
func TestItsOwnStatementUnderAnotherCertificateIsNoRenewalTaken(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
	stolen, first := worker(t, b), numberOf(t, b)
	e.clock.Add(2 * time.Second)
	crash(t, e, b, "rekey", "renewal taken", protocol.Address{})
	x, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	took := servedSerial(t, e, x)
	st, ok := x.Record(t, "prekeys/"+strconv.FormatUint(took, 10)+".txt")
	if !ok {
		t.Fatalf("the mailbox keeps no statement %d", took)
	}
	sig, err := protocol.Sign(stolen, st, protocol.PrekeyNamespace(x.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == mailboxPath(x) {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.MailboxResponse{Identity: x.Identity().Document(), Prekey: st, PrekeySignature: sig})
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := x.Receive(context.Background()); err == nil || numberOf(t, x) != first {
		t.Fatalf("served under certificate %d: recv %v, published %d", first, err, numberOf(t, x))
	}
	e.srv.SetMiddle(nil)
	if receive(t, x); numberOf(t, x) != took {
		t.Fatalf("served under its own certificate: published %d, want %d", numberOf(t, x), took)
	}
}

// The remedy killed at each of its steps: run again, it revokes and renews,
// the revocation covers the certificate in use before it, and the mailbox comes
// back whole.
func TestTheRemedyKilledAtEachStepLeavesTheMailboxWhole(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	for _, step := range append(client.Steps("revocation"), client.Steps("renewal")...) {
		t.Run(step, func(t *testing.T) {
			ctx := context.Background()
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			first := numberOf(t, b)
			e.clock.Add(2 * time.Second)
			crash(t, e, b, "remedy", step, protocol.Address{})
			x, err := client.Open(b.Dir(), e.opts())
			if err != nil {
				t.Fatal(err)
			}
			r, err := x.RenewAndRevoke(ctx, "")
			if err != nil || r == nil || r.NotRevoked != nil || r.NotRenewed != nil {
				t.Fatalf("the remedy again: %+v, %v", r, err)
			}
			held, err := x.Ask(ctx, x.Address())
			if err != nil || held.Certificates == nil || !held.Certificates.Revokes(first) {
				t.Fatalf("after the remedy again: %+v, %v", held, err)
			}
			whole(t, e, x, a)
		})
	}
}

// A restore from the identity alone killed at each step of its renewal and
// of its adoption of its server's ACL: the next recv adopts it, each entry
// once, and the restored mailbox's first renewal finds the two alike, so the
// server's blocks stay (#366).
func TestARestoreKilledAtEachStepAdoptsItsServersACL(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	for _, step := range append(client.Steps("renewal"), client.Steps("adoption")...) {
		t.Run(step, func(t *testing.T) {
			ctx := context.Background()
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			if _, err := b.Block(ctx, a.Address()); err != nil {
				t.Fatal(err)
			}
			own := e.srv.ACL(b.Address())
			r := restore(t, e, b)
			e.clock.Add(2 * time.Second)
			crash(t, e, r, "rekey", step, protocol.Address{})
			x, err := client.Open(r.Dir(), e.opts())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x.Receive(ctx); err != nil {
				t.Fatalf("the recv after the crash: %v", err)
			}
			e.clock.Add(25 * time.Hour)
			if res := receive(t, x); res.Renewed == nil || res.ACLReplaced || !e.srv.ACL(b.Address()).SameLists(own) {
				t.Fatalf("the first renewal after a crash at %s: %+v; the server holds %+v, the lost mailbox's was %+v", step, res, e.srv.ACL(b.Address()), own)
			}
			if data, err := os.ReadFile(filepath.Join(x.Dir(), "blocked")); err != nil || string(data) != a.Address().String()+"\n" {
				t.Fatalf("blocked after a crash at %s: %q, %v", step, data, err)
			}
		})
	}
}

// A drain killed at each step of a delivery: the message is in the inbox
// once, and leaves the server.
func TestADrainKilledAtEachStepOfADeliveryDeliversOnce(t *testing.T) {
	t.Parallel()
	for _, step := range client.Steps("delivery") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			send(t, a, b, "waits for a drain that dies")
			crash(t, e, b, "receive", step, protocol.Address{})
			whole(t, e, b, a, "waits for a drain that dies")
		})
	}
}

// A drain killed at each step of a refusal: the next drain refuses the
// message again, keeps it once with why, and acks it.
func TestADrainKilledAtEachStepOfARefusalKeepsItOnce(t *testing.T) {
	t.Parallel()
	for _, step := range client.Steps("refusal") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			mailAs(t, e, a, b, worker(t, b), "signed by another mailbox's key")
			crash(t, e, b, "receive", step, protocol.Address{})
			x, err := client.Open(b.Dir(), e.opts())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x.Receive(context.Background()); err != nil {
				t.Fatal(err)
			}
			qs, err := x.RefusedMail(t.Context())
			if err != nil || len(qs) != 1 || qs[0].Code != protocol.RefusedSignature || e.srv.Count(x.Address()) != 0 {
				t.Fatalf("after the crash: %+v, %v; the server holds %d", qs, err, e.srv.Count(x.Address()))
			}
			whole(t, e, x, a)
		})
	}
}

// A drain killed at each step of a fetch's partial: once a cut fetch has
// recorded what it kept, and once a judged message's partial is dropped,
// before its ack. The next drain delivers the message once, asking only for
// the bytes the mailbox did not keep, so the server serves each byte of it once
// in all; and the mailbox keeps no partial after (#381).
func TestADrainKilledAtEachStepOfAPartialDeliversOnce(t *testing.T) {
	t.Parallel()
	for _, step := range client.Steps("partial") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			const body = "fetched by a drain that dies. "
			send(t, a, b, strings.Repeat(body, 2000))
			f := &fetches{b: b}
			var size atomic.Int64
			var cut atomic.Bool
			cut.Store(step == "partial kept")
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if !f.is(r) {
					next.ServeHTTP(w, r)
					return
				}
				if cut.CompareAndSwap(true, false) {
					ct := honest(next, r).Body.Bytes()
					size.Store(int64(len(ct)))
					cutAfter(f, w, ct, len(ct)/2)
				}
				next.ServeHTTP(f.counted(w), r)
			})
			crash(t, e, b, "receive", step, protocol.Address{})
			before := f.served.Load()
			x, err := client.Open(b.Dir(), e.opts())
			if err != nil {
				t.Fatal(err)
			}
			res := receive(t, x)
			if step == "partial kept" {
				if len(res.Delivered) != 1 || f.served.Load() != size.Load() {
					t.Fatalf("after the crash: %+v; the server served %d bytes of %d", res, f.served.Load(), size.Load())
				}
			} else if len(res.Delivered) != 0 || f.served.Load() != before || e.srv.Count(x.Address()) != 0 {
				t.Fatalf("after the crash: %+v, a message the dead drain delivered; the server served %d bytes more, and holds %d", res, f.served.Load()-before, e.srv.Count(x.Address()))
			}
			noPartial(t, x)
			e.srv.SetMiddle(nil)
			whole(t, e, x, a, strings.Repeat(body, 2000))
		})
	}
}

// A send killed at each of its steps: the next flush posts what waits, its
// reader takes it once, and the outbox and sent/ are as a send leaves them.
func TestASendKilledAtEachStepIsReadOnce(t *testing.T) {
	t.Parallel()
	for _, step := range client.Steps("post") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
			crash(t, e, a, "send", step, b.Address())
			x, err := client.Open(a.Dir(), e.opts())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x.Flush(context.Background()); err != nil {
				t.Fatalf("the flush after the crash: %v", err)
			}
			receive(t, b)
			if got, want := inbox(t, b), []string{"sent by a process killed on its way"}; !slices.Equal(got, want) {
				t.Fatalf("the reader's inbox/ holds %q, want %q", got, want)
			}
			if left, _ := filepath.Glob(filepath.Join(x.Dir(), "outbox", "*.P")); len(left) != 0 {
				t.Fatalf("the outbox keeps %v", left)
			}
			if sent, _ := filepath.Glob(filepath.Join(x.Dir(), "sent", "*.json")); len(sent) != 1 {
				t.Fatalf("sent/ keeps %v", sent)
			}
			whole(t, e, b, x, "sent by a process killed on its way")
		})
	}
}
