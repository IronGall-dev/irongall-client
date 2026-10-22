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
	"syscall"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A crash is a box's process killed between two of the steps at which a
// command writes the box (steps.go names each): the next command finds the
// box whole, and goes on from where the last left it. Each case kills a copy
// of this test binary at one step, with SIGKILL, so nothing of the process
// runs after it: no deferred call, no close, no further write. What it cannot
// show is a power cut, where what was not synced is lost: each step syncs
// before the next begins (writeFile, bbolt's commit), and a test cannot pull
// the power (#316).

// crashChild is the environment variable a copy of this binary reads to run
// one command of a box and die at one step.
const crashChild = "IRONGALL_TEST_CRASH"

// crashOrder is what the copy runs: the step it dies at, the box's directory,
// its server's URL, its clock in Unix seconds, the command, and for a send,
// the address it goes to.
type crashOrder struct {
	Step, Dir, Base, Command, To string
	Now                          int64
}

// crashCommands are what a copy runs, by name.
var crashCommands = map[string]func(ctx context.Context, b *client.Box, o crashOrder) error{
	"rekey":   func(ctx context.Context, b *client.Box, _ crashOrder) error { _, err := b.Rekey(ctx, ""); return err },
	"receive": func(ctx context.Context, b *client.Box, _ crashOrder) error { _, err := b.Receive(ctx); return err },
	"remedy": func(ctx context.Context, b *client.Box, _ crashOrder) error {
		_, err := b.RenewAndRevoke(ctx, "")
		return err
	},
	"send": func(ctx context.Context, b *client.Box, o crashOrder) error {
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
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
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

// crash runs command on box b in a copy of this binary, killed at step, and
// fails the test unless it died there.
func crash(t *testing.T, e *env, b *client.Box, command, step string, to protocol.Address) {
	t.Helper()
	order, err := json.Marshal(crashOrder{Step: step, Dir: b.Dir(), Base: e.srv.URL, Command: command, To: to.String(), Now: e.clock.Now().Unix()})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$", "-test.count=1") //nolint:gosec // this test binary, again
	cmd.Env = append(os.Environ(), crashChild+"="+string(order))
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("%s did not die at %s: %v\n%s", command, step, err, out)
	}
}

// inbox is the body of each message in a box's inbox/, as many times as it is
// there.
func inbox(t *testing.T, b *client.Box) []string {
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

// whole checks a box after a crash by its next commands, opened anew from its
// directory: a drain takes everything waiting on its server, refusing
// nothing; a renewal goes through, and its server serves the prekey it
// published; mail sealed to the new one is read; and the inbox holds every
// message sent to the box, once: waiting, sent before the crash, and those
// sent here.
func whole(t *testing.T, e *env, b, from *client.Box, waiting ...string) {
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
		t.Fatalf("the server serves %d, the box published %d", served, numberOf(t, x))
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
// sealed to the prekey in use before it, and the box renews again.
func TestARenewalKilledAtEachStepLeavesTheBoxWhole(t *testing.T) {
	for _, step := range client.Steps("renewal") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.box(protocol.Classic), e.box(protocol.Classic)
			send(t, a, b, "sealed to the prekey in use")
			e.clock.Add(2 * time.Second)
			crash(t, e, b, "rekey", step, protocol.Address{})
			whole(t, e, b, a, "sealed to the prekey in use")
		})
	}
}

// A box its server forgot, killed at each step of the registration that
// brings it back: its server holds no ACL of it, whatever became of the
// answer, and the next commands send the ACL again (#324). A recv brings the
// box back where the registration was not taken.
func TestAForgottenBoxKilledAtEachStepOfItsRegistrationSendsItsACLAgain(t *testing.T) {
	for _, step := range client.Steps("renewal") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
			if _, err := b.Block(context.Background(), c.Address()); err != nil || e.srv.ACL(b.Address()) == nil {
				t.Fatalf("the block before the box was forgotten: %v", err)
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
				t.Fatalf("after a crash at %s the server holds the ACL %+v, which does not deny the sender the box blocked", step, acl)
			}
		})
	}
}

// A renewal killed after its key and working key were made, before its
// statement was signed, leaves files no statement names; the remedy, which
// takes nothing an earlier attempt left, passes over that number, and its
// files go (begin; #337).
func TestARemedyPassingOverAKilledRenewalDropsWhatItLeft(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
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

// A renewal the server took, whose answer the box never had, is recorded at
// the box's next read of itself, which a pass refused as under a certificate
// not current sends it to; a later renewal the box has begun keeps its
// number.
func TestARenewalTakenUnseenIsRecordedAndALaterOneKeepsItsNumber(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
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

// The box's own statement served under another of its certificates, here
// signed again by the working key it used before, by whoever took that key,
// is no renewal the server took: the box records it only once it is served
// under the certificate the box made with it.
func TestItsOwnStatementUnderAnotherCertificateIsNoRenewalTaken(t *testing.T) {
	e := newEnv(t)
	b := e.box(protocol.Classic)
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
		t.Fatalf("the box keeps no statement %d", took)
	}
	sig, err := protocol.Sign(stolen, st, protocol.PrekeyNamespace(x.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == boxPath(x) {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.BoxResponse{Identity: x.Identity().Document(), Prekey: st, PrekeySignature: sig})
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
// the revocation covers the certificate in use before it, and the box comes
// back whole.
func TestTheRemedyKilledAtEachStepLeavesTheBoxWhole(t *testing.T) {
	for _, step := range append(client.Steps("revocation"), client.Steps("renewal")...) {
		t.Run(step, func(t *testing.T) {
			ctx := context.Background()
			e := newEnv(t)
			a, b := e.box(protocol.Classic), e.box(protocol.Classic)
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

// A drain killed at each step of a delivery: the message is in the inbox
// once, and leaves the server.
func TestADrainKilledAtEachStepOfADeliveryDeliversOnce(t *testing.T) {
	for _, step := range client.Steps("delivery") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.box(protocol.Classic), e.box(protocol.Classic)
			send(t, a, b, "waits for a drain that dies")
			crash(t, e, b, "receive", step, protocol.Address{})
			whole(t, e, b, a, "waits for a drain that dies")
		})
	}
}

// A drain killed at each step of a refusal: the next drain refuses the
// message again, keeps it once with why, and acks it.
func TestADrainKilledAtEachStepOfARefusalKeepsItOnce(t *testing.T) {
	for _, step := range client.Steps("refusal") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.box(protocol.Classic), e.box(protocol.Classic)
			mailAs(t, e, a, b, worker(t, b), "signed by another box's key")
			crash(t, e, b, "receive", step, protocol.Address{})
			x, err := client.Open(b.Dir(), e.opts())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := x.Receive(context.Background()); err != nil {
				t.Fatal(err)
			}
			qs, err := x.Quarantined(t.Context())
			if err != nil || len(qs) != 1 || qs[0].Code != protocol.RefusedSignature || e.srv.Count(x.Address()) != 0 {
				t.Fatalf("after the crash: %+v, %v; the server holds %d", qs, err, e.srv.Count(x.Address()))
			}
			whole(t, e, x, a)
		})
	}
}

// A send killed at each of its steps: the next flush posts what waits, its
// reader takes it once, and the outbox and sent/ are as a send leaves them.
func TestASendKilledAtEachStepIsReadOnce(t *testing.T) {
	for _, step := range client.Steps("post") {
		t.Run(step, func(t *testing.T) {
			e := newEnv(t)
			a, b := e.box(protocol.Classic), e.box(protocol.Classic)
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
