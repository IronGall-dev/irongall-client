package client_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A box numbers a certificate by its own clock, and the prekey and working
// key made with it take the same number (protocol.SerialAt, PROTOCOL.md §2b).
// An identity is a key and keeps no record of what it signed, so the clock is
// what a box restored from its identity still has. Where the rule is about
// one machine's clock against another's, these tests give a box a clock of
// its own.

// restore opens the box of b's identity in an empty directory: the identity
// alone, on another machine.
func restore(t *testing.T, e *env, b *client.Box) *client.Box {
	t.Helper()
	return restoreWith(t, e, b, e.clock.Now)
}

// restoreWith is restore on a machine whose clock is now.
func restoreWith(t *testing.T, e *env, b *client.Box, now func() time.Time) *client.Box {
	t.Helper()
	dir := t.TempDir()
	key, err := os.ReadFile(filepath.Join(b.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "identity"), key, 0o600); err != nil {
		t.Fatal(err)
	}
	opt := e.opts()
	opt.Now = now
	r, err := client.Open(dir, opt)
	if err != nil {
		t.Fatal(err)
	}
	if r.Address() != b.Address() {
		t.Fatal("the restored box has another address")
	}
	return r
}

// servedCertificate is the serial of the certificate the statement the server
// serves for b is signed under.
func servedCertificate(t *testing.T, e *env, b *client.Box) uint64 {
	t.Helper()
	st, sig := e.srv.Prekey(b.Address())
	_, cert, err := protocol.VerifyPrekey(b.Identity(), st, sig, e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	return cert.Serial()
}

// A new box's number is its clock, in seconds, and so is a renewal's once the
// clock has moved past the last number. Within one second, and with a clock
// that reads behind the last number, a renewal takes one above it: a serial
// never goes back, whatever the clock does.
func TestABoxNumbersByItsClock(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	var off time.Duration
	b, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() uint64 { return uint64(e.clock.Now().Add(off).Unix()) } //nolint:gosec // a test's clock, after 1970
	first := numberOf(t, b)
	if first != clock() || servedSerial(t, e, b) != first || servedCertificate(t, e, b) != first {
		t.Fatalf("a new box's number is %d, its prekey's %d and its certificate's %d, and its clock reads %d", first, servedSerial(t, e, b), servedCertificate(t, e, b), clock())
	}
	for _, name := range []string{prekeyFile(b, first, ".agekey"), prekeyFile(b, first, ".txt.sig"), workFile(b, first, ""), workFile(b, first, "-cert.pub")} {
		if !exists(name) {
			t.Fatalf("a new box does not hold %s", name)
		}
	}

	// The same second: one above.
	p, err := b.Rekey(ctx, "")
	if err != nil || p.Serial != first+1 || servedCertificate(t, e, b) != first+1 {
		t.Fatalf("a renewal in the second the box was made: %+v, %v", p, err)
	}

	// The clock has moved on: the clock.
	e.clock.Add(time.Hour)
	p, err = b.Rekey(ctx, "")
	if err != nil || p.Serial != clock() || servedSerial(t, e, b) != p.Serial || servedCertificate(t, e, b) != p.Serial {
		t.Fatalf("a renewal an hour on: %+v, %v, and the clock reads %d", p, err, clock())
	}

	// This box's clock set back five minutes, behind its own last number:
	// one above, and the server takes it as the later certificate it is.
	last := p.Serial
	off = -5 * time.Minute
	if clock() >= last {
		t.Fatal("the test does not reach the case: the clock is not behind the last number")
	}
	p, err = b.Rekey(ctx, "")
	if err != nil || p.Serial != last+1 || servedCertificate(t, e, b) != last+1 {
		t.Fatalf("a renewal with the clock behind the last number: %+v, %v", p, err)
	}
	if numberOf(t, b) != last+1 {
		t.Fatalf("the box records %d", numberOf(t, b))
	}
}

// A machine is lost while it holds a renewal the server never took: a working
// key under a certificate nobody else has seen. The identity, restored on
// another machine, knows only what the server shows it, which is the
// statement before that one. Numbered by a count from what the server shows,
// its new certificate would take the lost one's serial, and no revocation could
// name the lost one apart from the box's own. Numbered by its clock it is
// above the lost one, the revocation of everything before it covers the lost one,
// and what the machine's taker signs with that key is refused by whoever
// holds the revocation.
func TestARestoredBoxRevokesWhatTheLostMachineNeverPublished(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	lost, reader := e.box(protocol.Classic), e.box(protocol.Classic)
	first := numberOf(t, lost)
	kept := uploads(e, lost)
	if _, err := lost.Rekey(ctx, ""); err == nil {
		t.Fatal("the lost machine's renewal was meant to fail")
	}
	e.srv.SetMiddle(nil)
	waiting := begunAt(t, lost)
	if waiting <= first || len(*kept) != 1 || servedCertificate(t, e, lost) != first {
		t.Fatalf("the lost machine holds no renewal the server never took: %d after %d, %d uploads", waiting, first, len(*kept))
	}
	taken := workerAt(t, lost, waiting) // what whoever has the machine holds

	e.clock.Add(time.Hour)
	r := restore(t, e, lost)
	p, err := r.Rekey(ctx, "")
	if err != nil {
		t.Fatalf("the restored box's renewal: %v", err)
	}
	if now := uint64(e.clock.Now().Unix()); p.Serial != now || p.Serial <= waiting { //nolint:gosec // a test's clock, after 1970
		t.Fatalf("the restored box numbered its certificate %d: its clock reads %d, and the lost machine's is %d", p.Serial, now, waiting)
	}
	certs, err := r.RevokeEarlier(ctx)
	if err != nil || certs == nil || !certs.Revokes(first) || !certs.Revokes(waiting) || certs.Revokes(p.Serial) {
		t.Fatalf("the restored box's revocation of its certificates: %+v, %v", certs, err)
	}

	// The control: the taken key is good under its certificate, so the
	// revocation is what refuses it. A reader shown none delivers what it signs.
	control := e.box(protocol.Classic)
	says(e, protocol.CodeNotRevoked, http.MethodGet, "/revocations")
	mailAs(t, e, r, control, taken, "signed with the key the lost machine never published")
	if res := receive(t, control); len(res.Delivered) != 1 {
		t.Fatalf("the control: mail under the lost machine's certificate, no revocation shown: %+v", res)
	}
	e.srv.SetMiddle(nil)

	mailAs(t, e, r, reader, taken, "signed with the key the lost machine never published")
	send(t, r, reader, "from the restored box")
	res := receive(t, reader)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "from the restored box" || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a drain of the taker's mail and the restored box's: %+v", res)
	}
}

// The machine that was lost had a clock that read fast, by less than a server
// refuses, so its last certificate is numbered ahead of the time. Its owner,
// on a machine whose clock is right, renews and revokes at once: one above
// that number, with no wait for the clock to pass it, and the list names the
// lost machine's certificate. This is why a serial rises by one where the
// clock gives nothing higher. A client that took its clock and nothing else
// would have to refuse here until the clock caught up, with the taken
// working key the box's own all the while.
func TestALostMachinesFastClockDoesNotDelayTheRemedy(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	fast := 40 * time.Minute
	lost, err := client.Init(ctx, t.TempDir(), e.skewed(&fast), protocol.Classic)
	if err != nil {
		t.Fatalf("a box whose clock reads 40 minutes fast: %v", err)
	}
	reader := e.box(protocol.Classic)
	ahead := numberOf(t, lost)
	if now := uint64(e.clock.Now().Unix()); ahead <= now+60 { //nolint:gosec // a test's clock, after 1970
		t.Fatalf("the test does not reach the case: the lost machine's certificate is %d, and the time is %d", ahead, now)
	}
	taken := worker(t, lost) // what whoever has the machine holds

	r := restore(t, e, lost) // the identity alone, on a machine whose clock is right
	p, err := r.Rekey(ctx, "")
	if err != nil || p.Serial != ahead+1 || servedCertificate(t, e, r) != ahead+1 {
		t.Fatalf("the owner's renewal, its clock behind the lost machine's last number: %+v, %v", p, err)
	}
	certs, err := r.RevokeEarlier(ctx)
	if err != nil || certs == nil || !certs.Revokes(ahead) || certs.Revokes(p.Serial) {
		t.Fatalf("the owner's revocation of certificates: %+v, %v", certs, err)
	}
	mailAs(t, e, r, reader, taken, "signed with the lost machine's key")
	send(t, r, reader, "from the owner, at once")
	res := receive(t, reader)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "from the owner, at once" || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a drain of the taker's mail and the owner's: %+v", res)
	}
}

// A server that answers a restored box from an older record cannot bring its
// numbers back down: the box takes its number from its clock, above every
// certificate its identity made before, and its revocation covers them all. Counted
// from what it was shown, it would have taken a serial used before, and its
// revocation would have stopped below the certificate in use at the time.
func TestARestoredBoxShownAnOlderRecordNumbersAboveItAll(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.box(protocol.Classic)
	first := numberOf(t, b)
	st, sig := e.srv.Prekey(b.Address())
	for range 2 {
		if _, err := b.Rekey(ctx, ""); err != nil {
			t.Fatal(err)
		}
	}
	third := numberOf(t, b)

	e.clock.Add(time.Hour)
	r := restore(t, e, b)
	watch(e, func(w http.ResponseWriter, req *http.Request) bool {
		if req.Method == http.MethodGet && req.URL.Path == "/v1/"+b.Address().String()+"/identity" {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.Identity().Document(), Prekey: st, PrekeySignature: sig})
			return true
		}
		return false
	})
	p, err := r.Rekey(ctx, "")
	if err != nil || p.Serial <= third {
		t.Fatalf("a restored box shown the statement of certificate %d, where %d was in use: %+v, %v", first, third, p, err)
	}
	e.srv.SetMiddle(nil)
	certs, err := r.RevokeEarlier(ctx)
	if err != nil || certs == nil || !certs.Revokes(first) || !certs.Revokes(third) || certs.Revokes(p.Serial) {
		t.Fatalf("its revocation of certificates: %+v, %v", certs, err)
	}
}

// The revocation of every certificate before the one in use runs through
// the serial one below it, whether this box made any of them or not: a box
// cannot know what another machine made for its identity, and by the clock
// all of it is numbered below. The address goes on.
func TestRevokeEarlierNamesEverySerialBelowTheOneInUse(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	n := numberOf(t, a)
	certs, err := a.RevokeEarlier(ctx)
	if err != nil || certs == nil || certs.Through != n-1 || certs.Revokes(n) {
		t.Fatalf("a new box's revocation of its certificates: %+v, %v", certs, err)
	}
	send(t, a, b, "under the certificate in use")
	send(t, b, a, "to the box that revoked everything before it")
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Fatalf("mail under the certificate in use: %+v", res)
	}
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("the box no longer receives: %+v", res)
	}
}

// A box never makes a certificate its own identity has revoked. A revocation
// through a serial far above its clock, a slip of a digit, passes its next
// certificate above it, and the box goes on; one through the highest serial
// there is leaves no certificate to make, and the box says so.
func TestARenewalIsNumberedAboveTheBoxsOwnRevocation(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	key, err := os.ReadFile(filepath.Join(a.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	revokeThrough := func(through uint64) {
		t.Helper()
		certs, err := protocol.NewRevokedCertificates(a.Address(), through)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := protocol.SignRevokedCertificates(id, certs)
		if err != nil {
			t.Fatal(err)
		}
		rec := &protocol.Revocations{Identity: a.Identity().Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
		if _, _, err := a.KeepRevocation(rec); err != nil {
			t.Fatal(err)
		}
		if _, err := a.Publish(ctx, rec); err != nil {
			t.Fatal(err)
		}
	}

	ahead := numberOf(t, a) + 1_000_000
	revokeThrough(ahead)
	p, err := a.Rekey(ctx, "")
	if err != nil || p.Serial != ahead+1 {
		t.Fatalf("a renewal after a revocation through %d: %+v, %v", ahead, p, err)
	}
	send(t, b, a, "to a box whose identity revoked past its clock")
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("the box after its renewal: %+v", res)
	}

	revokeThrough(protocol.MaxSerial)
	if _, err := a.Rekey(ctx, ""); err == nil || !strings.Contains(err.Error(), "revoked its certificates through the highest serial there is") {
		t.Fatalf("a renewal after a revocation through the highest serial: %v", err)
	}
}
