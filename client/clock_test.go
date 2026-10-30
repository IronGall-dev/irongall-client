package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// These tests give a mailbox a clock of its own, set apart from the server's.
// Every other test here shares one clock between the two, and so cannot see
// a check that a second of difference fails (PROTOCOL.md §3.4).

// skewed returns the options of a mailbox whose clock is *off from the server's.
func (e *env) skewed(off *time.Duration) client.Options {
	o := e.opts()
	o.Now = func() time.Time { return e.clock.Now().Add(*off) }
	return o
}

// A mailbox whose clock differs from the server's by less than the pass allows
// (under PassLifetime slow, up to MaxPassLifetime less PassLifetime fast)
// works in full, with mailboxes made that same moment: it registers, mail under
// a certificate just made reaches it and is delivered, its own mail is
// delivered, and it renews.
func TestABoxWhoseClockIsOffByLessThanThePassAllows(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	ctx := context.Background()
	for _, off := range []time.Duration{-9 * time.Minute, -2 * time.Minute, -time.Second, time.Second, 30 * time.Second, 3 * time.Minute, 49 * time.Minute} {
		e := newEnv(t)
		b, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
		if err != nil {
			t.Errorf("a clock %v off: init: %v", off, err)
			continue
		}
		landAll(t, b)
		fresh := e.mailbox(protocol.Classic) // made this moment, on the server's clock: no certificate is newer
		if _, err := fresh.Send(ctx, b.Address(), "under a certificate made this moment"); err != nil {
			t.Errorf("a clock %v off: mail to it: %v", off, err)
		}
		if res, err := b.Receive(ctx); err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
			t.Errorf("a clock %v off: it reads: %+v, %v", off, res, err)
		}
		if _, err := b.Send(ctx, fresh.Address(), "from the mailbox whose clock is off"); err != nil {
			t.Errorf("a clock %v off: it sends: %v", off, err)
		}
		if res, err := fresh.Receive(ctx); err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
			t.Errorf("a clock %v off: its mail is read: %+v, %v", off, res, err)
		}
		if _, err := b.Rekey(ctx, protocol.Classic); err != nil {
			t.Errorf("a clock %v off: it renews: %v", off, err)
		}
	}
}

// The two mailboxes at the far edges of what a server takes, 49 minutes fast and
// 9 slow, are 58 minutes apart, and still exchange mail under certificates
// made that moment: the hour every maker leaves is the width of that window.
func TestTheTwoClocksFurthestApart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	fast, slow := 49*time.Minute, -9*time.Minute
	f, err := client.Init(ctx, t.TempDir(), e.skewed(&fast), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	s, err := client.Init(ctx, t.TempDir(), e.skewed(&slow), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	send(t, f, s, "from the fast mailbox to the slow one")
	send(t, s, f, "from the slow mailbox to the fast one")
	for _, b := range []*client.Mailbox{f, s} {
		if res, err := b.Receive(ctx); err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
			t.Errorf("%+v, %v", res, err)
		}
	}
}

// Further off than that, the server refuses the mailbox: its pass, or, more
// than 50 minutes fast, its certificate, which a server takes once it has
// begun PassLifetime before its own clock and sees before the pass, as
// dromas-server answers both (#426 item 6). A refusal for a time gets the
// client's own sentence: the date on the server's answer, what this
// machine's clock reads, and where to check the clock, which is never the
// server. TestTheDateOnAnAnswerIsNeverAnOrder holds that no other refusal
// gets it.
func TestABoxWhoseClockIsTooFarOffIsToldSo(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct {
		off  time.Duration
		code protocol.Code
		says string
	}{
		{-11 * time.Minute, protocol.CodePassExpired, "11m0s behind that"},
		{-50 * time.Minute, protocol.CodePassExpired, "50m0s behind that"},
		{51 * time.Minute, protocol.CodePrekeyTime, "51m0s ahead of that"},
		{61 * time.Minute, protocol.CodePrekeyTime, "1h1m0s ahead of that"},
	} {
		e := newEnv(t)
		off, dir := c.off, t.TempDir()
		_, err := client.Init(ctx, dir, e.skewed(&off), protocol.Classic)
		if client.Code(err) != c.code {
			t.Errorf("a clock %v off: init: %v, want the code %s", c.off, err, c.code)
			continue
		}
		s := err.Error()
		if told := strings.Contains(s, "against a time source you trust, not against the server"); told != (c.says != "") || !strings.Contains(s, c.says) {
			t.Errorf("a clock %v off: %s", c.off, s)
		}
		// The clock set right, the same mailbox registers. What the refused
		// attempt left is used again, or, where its certificate has not
		// begun by the clock as it now is, made again.
		off = 0
		if _, err := client.Init(ctx, dir, e.skewed(&off), protocol.Classic); err != nil {
			t.Errorf("a clock %v off, then set right: init: %v", c.off, err)
		}
	}
}

// The date on an answer is the server's word. The client sets it beside its
// own clock only when a pass was refused for its time, says whose word it
// is, and sends its reader to a time source of their own: a clock set by a
// server's lie would make an ended certificate valid again.
func TestTheDateOnAnAnswerIsNeverAnOrder(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	lie := now.Add(-40 * 24 * time.Hour)
	problem := func(code protocol.Code) protocol.Problem { return protocol.Problem{Code: code, Detail: "words"} }
	for _, c := range []struct {
		name string
		err  client.APIError
		want bool
	}{
		{"a pass refused for its time", client.APIError{Status: 401, Problem: problem(protocol.CodePassExpired), Dated: lie, Read: now}, true},
		{"a pass refused for its time, the clocks agreeing", client.APIError{Status: 401, Problem: problem(protocol.CodePassExpired), Dated: now, Read: now}, true},
		{"a pass refused for its time, no Date on the answer", client.APIError{Status: 401, Problem: problem(protocol.CodePassExpired)}, false},
		{"a rate limit, dated 40 days back", client.APIError{Status: 429, Problem: problem(protocol.CodeRateLimited), Dated: lie, Read: now}, false},
		{"a bad key, dated 40 days back", client.APIError{Status: 400, Problem: problem(protocol.CodeBadKey), Dated: lie, Read: now}, false},
		{"another 401, dated 40 days back", client.APIError{Status: 401, Problem: problem(protocol.CodeUnauthorized), Dated: lie, Read: now}, false},
	} {
		s := c.err.Error()
		if got := strings.Contains(s, "the server dates its answer"); got != c.want {
			t.Errorf("%s: %q", c.name, s)
		}
		if strings.Contains(strings.ToLower(s), "set this machine's clock") || strings.Contains(strings.ToLower(s), "set the clock") {
			t.Errorf("%s: the error tells its reader to set the clock: %q", c.name, s)
		}
		if c.want && !strings.Contains(s, "Check this machine's clock against a time source you trust, not against the server") {
			t.Errorf("%s: the sentence does not send its reader to their own time source: %q", c.name, s)
		}
	}
}

// A mailbox holds a pass the server still takes, and its clock then goes back.
// Mail waits for it under a certificate that has not begun by the clock as
// it now reads: its sender's clock is 49 minutes fast, which a server takes,
// so that certificate starts 11 minutes back. A mailbox that fetched that mail
// would refuse it and ack it, and it would be gone. It does not fetch: a
// kept pass with more left than it was signed for is not used, and the pass
// signed in its place has run out by the server's clock. The mail is
// delivered when the clock is right.
func TestABoxWhoseClockGoesBackFetchesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	var off time.Duration
	b, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, b)
	if res := receive(t, b); len(res.Delivered) != 0 { // the pass is in the mailbox now, with ten minutes to run
		t.Fatal(res)
	}
	fast := 49 * time.Minute
	sender, err := client.Init(ctx, t.TempDir(), e.skewed(&fast), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	send(t, sender, b, "under a certificate that starts 11 minutes back")

	off = -12 * time.Minute
	res, err := b.Receive(ctx)
	if client.Code(err) != protocol.CodePassExpired || !strings.Contains(err.Error(), "12m0s behind that") || (res != nil && len(res.Delivered)+len(res.Refused) != 0) {
		t.Fatalf("its clock set back 12 minutes: %+v, %v", res, err)
	}
	// Control: at that clock the mail would be refused, so the stop above is
	// what kept it. The certificate it is signed under has not begun.
	began, cerr := protocol.CertificateBegan(statement(t, sender, numberOf(t, sender), ".txt.sig"))
	if cerr != nil || !began.After(e.clock.Now().Add(off)) {
		t.Fatalf("the sender's certificate began %v, which is not after the reader's clock: the test does not reach the case", began)
	}
	off = 0
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Fatalf("on time again: %+v", res)
	}
}

// An envelope dated ahead of this machine's clock is not posted, whether its
// first post was refused or never made. It was written while the clock read
// ahead of where it reads now, a server would take it, and its reader would
// refuse it as future and ack it. It waits in the outbox, as its envelope
// alone, until the clock passes that time, and then goes.
func TestAnEnvelopeDatedAheadWaitsInTheOutbox(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, c := range []struct {
		name     string
		off      time.Duration
		unsealed bool
	}{
		{"posted while the clock was two hours fast, and refused", 2 * time.Hour, false},
		{"written while the clock was 55 minutes fast, and never sealed", 55 * time.Minute, true},
	} {
		e := newEnv(t)
		var off time.Duration
		a, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
		if err != nil {
			t.Fatal(err)
		}
		b := e.mailbox(protocol.Classic)
		off = c.off
		if c.unsealed {
			forge.FailOnce(e.srv, http.MethodGet, mailboxPath(b)) // the entry is written and cannot be sealed
		}
		if _, err := a.Send(ctx, b.Address(), "dated ahead"); err == nil {
			t.Fatalf("%s: sent", c.name)
		} else if c.unsealed && !strings.Contains(err.Error(), "could not be read") {
			t.Fatalf("%s: sealed and posted: %v", c.name, err)
		}
		e.srv.SetMiddle(nil)
		if kept, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.*")); len(kept) != 1 || !strings.HasSuffix(kept[0], ".P") {
			t.Fatalf("%s: the outbox keeps %v, where it keeps the envelope alone", c.name, kept)
		}
		off = 0 // the clock is set right
		if rs, err := a.Flush(ctx); len(rs) != 0 || err == nil || !strings.Contains(err.Error(), "ahead of this machine's clock") {
			t.Fatalf("%s: flushed with the clock right: %v, %v", c.name, rs, err)
		}
		if res := receive(t, b); len(res.Delivered)+len(res.Refused) != 0 {
			t.Fatalf("%s: the reader got %+v", c.name, res)
		}
		if left, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P")); len(left) != 1 {
			t.Fatalf("%s: the entry is not in the outbox: %v", c.name, left)
		}
		e.clock.Add(c.off) // the time it is dated comes
		if rs, err := a.Flush(ctx); len(rs) != 1 || err != nil {
			t.Fatalf("%s: flushed once its time came: %v, %v", c.name, rs, err)
		}
		if res := receive(t, b); len(res.Delivered) != 1 || len(res.Refused) != 0 {
			t.Fatalf("%s: the reader got %+v", c.name, res)
		}
	}
}

// A registration the server took, whose answer was lost: the mailbox does not
// know it is registered. Mail arrives for its first prekey. Its clock then
// reads two hours back, where its first certificate has not begun, and init
// runs again, and is refused at its pass, with the first prekey's key kept.
// Its read of itself there showed the registration the server took, which
// it recorded (noteServed), so with the clock right init has nothing left to
// do, and the key stays: the mail that waited is still read.
func TestInitNeverDropsAKeyMailMayBeWaitingFor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	var off time.Duration
	dir := t.TempDir()
	lost := false
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && !strings.Contains(strings.TrimPrefix(r.URL.Path, "/v1/"), "/") && !lost {
			lost = true
			next.ServeHTTP(httptest.NewRecorder(), r) // the server takes it
			http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := client.Init(ctx, dir, e.skewed(&off), protocol.Classic); err == nil || !lost {
		t.Fatalf("the registration's answer was not lost: %v", err)
	}
	e.srv.SetMiddle(nil)
	address, err := protocol.ParseAddress(strings.TrimSpace(string(mustRead(t, filepath.Join(dir, "address")))))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := only(t, filepath.Join(dir, "prekeys", "*.agekey"))
	key := mustRead(t, keyFile)
	if _, err := e.mailbox(protocol.Classic).Send(ctx, address, "to the first prekey"); err != nil {
		t.Fatalf("mail to the mailbox the server registered: %v", err)
	}

	off = -2 * time.Hour
	_, _ = client.Init(ctx, dir, e.skewed(&off), protocol.Classic) // refused: its pass has run out by the server's clock
	if got := mustRead(t, keyFile); string(got) != string(key) {
		t.Fatal("init replaced the first prekey's key, which mail was waiting for")
	}
	off = 0
	if _, err := client.Init(ctx, dir, e.skewed(&off), protocol.Classic); err != nil {
		t.Fatalf("init with the clock right: %v", err)
	}
	b, err := client.Open(dir, e.skewed(&off))
	if err != nil {
		t.Fatal(err)
	}
	if n := numberOf(t, b); n != first(t, keyFile) || servedSerial(t, e, b) != n {
		t.Fatalf("init recorded %d, where the server took the first prekey, %d", n, first(t, keyFile))
	}
	landAll(t, b)
	if res := receive(t, b); len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Fatalf("the mail that waited for the first prekey: %+v", res)
	}
}

// first is the serial an age key file is for, by its name.
func first(t *testing.T, keyFile string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(keyFile), ".agekey"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name) //nolint:gosec // a test's own file
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A mailbox whose clock read 55 minutes ahead made a certificate at init, and the
// server refused it. Once its clock is right, the next init does not use that
// certificate, which began five minutes before the clock: a reader 9 minutes
// slow, a clock the server takes, would refuse mail under it as not begun.
// It makes another, by the clock as it is (PROTOCOL.md §12.4).
func TestACertificateKeptFromARefusedAttemptLeavesTheHour(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	off, dir := 55*time.Minute, t.TempDir()
	if _, err := client.Init(ctx, dir, e.skewed(&off), protocol.Classic); client.Code(err) != protocol.CodePrekeyTime {
		t.Fatalf("init, 55 minutes ahead: %v", err)
	}
	off = 0 // the clock is set right
	b, err := client.Init(ctx, dir, e.skewed(&off), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	slow := -9 * time.Minute // a clock the server takes
	r, err := client.Init(ctx, t.TempDir(), e.skewed(&slow), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, r)
	send(t, b, r, "under the certificate the refused attempt left")
	if res, err := r.Receive(ctx); err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Errorf("%+v, %v", res, err)
	}
}

// The same of a renewal: one made while the clock read 55 minutes ahead, and
// refused, is not sent again once the clock is right. Its number is spent,
// and the renewal is made again at a later one.
func TestARenewalKeptFromARefusedAttemptLeavesTheHour(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	var off time.Duration
	b, err := client.Init(ctx, t.TempDir(), e.skewed(&off), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	e.clock.Add(2 * time.Second)
	off = 55 * time.Minute
	if _, err := b.Rekey(ctx, ""); client.Code(err) != protocol.CodePrekeyTime {
		t.Fatalf("a renewal 55 minutes ahead: %v", err)
	}
	off = 0
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	slow := -9 * time.Minute
	r, err := client.Init(ctx, t.TempDir(), e.skewed(&slow), protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	landAll(t, r)
	send(t, b, r, "under the renewal made once the clock was right")
	if res, err := r.Receive(ctx); err != nil || len(res.Delivered) != 1 || len(res.Refused) != 0 {
		t.Errorf("%+v, %v", res, err)
	}
}

// jumpAtFetch sets a mailbox's clock off by `by` once the first message it
// fetches has arrived: a clock that moves during a drain.
type jumpAtFetch struct {
	off *time.Duration
	by  time.Duration
}

func (j jumpAtFetch) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := http.DefaultTransport.RoundTrip(r)
	if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/messages/") {
		*j.off = j.by
	}
	return resp, err
}

// A clock that jumps 70 days ahead during a drain, after the server answered
// its list, deletes no prekey: keys are deleted by the clock as it read when
// the server took the drain's pass, and never by a later reading no server
// has seen (PROTOCOL.md §12.4). The mail waiting for the retired key is
// delivered once the clock is right.
func TestAClockThatJumpsDuringADrainDeletesNoKey(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	send(t, a, b, "first, sealed to the prekey about to retire")
	send(t, a, b, "second, sealed to it too")
	e.clock.Add(2 * time.Second)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	keys, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey"))
	var off time.Duration
	o := e.skewed(&off)
	o.HTTPClient = &http.Client{Transport: jumpAtFetch{&off, 70 * 24 * time.Hour}}
	jumpy, err := client.Open(b.Dir(), o)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := jumpy.Receive(ctx); err == nil {
		t.Fatal("a drain whose clock jumped 70 days went through")
	}
	if after, _ := filepath.Glob(filepath.Join(b.Dir(), "prekeys", "*.agekey")); len(after) < len(keys) {
		t.Fatalf("%d prekeys before a drain whose clock jumped, %d after", len(keys), len(after))
	}
	right, err := client.Open(b.Dir(), e.opts())
	if err != nil {
		t.Fatal(err)
	}
	if res, err := right.Receive(ctx); err != nil || len(res.Delivered) != 2 {
		t.Errorf("once the clock is right: %+v, %v", res, err)
	}
}

// And a drain deletes, by the reading at which the server answered its list,
// a retired key whose deletion time has come: the backstop to dropRetired,
// which keeps the newest retired key (PROTOCOL.md §12.4).
func TestADrainDeletesARetiredKeyPastItsDeletionTime(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	b := e.mailbox(protocol.Classic)
	retired := numberOf(t, b)
	e.clock.Add(2 * time.Second)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	// Its not_after 34 days back, so its deletion time, a day back, has come.
	lines := strings.Split(string(statement(t, b, retired, ".txt")), "\n")
	lines[4] = e.clock.Now().Add(-34 * 24 * time.Hour).UTC().Format(protocol.TimeLayout)
	b.SetRecord(t, "prekeys/"+strconv.FormatUint(retired, 10)+".txt", []byte(strings.Join(lines, "\n")))
	receive(t, b)
	if exists(prekeyFile(b, retired, ".agekey")) || !exists(prekeyFile(b, numberOf(t, b), ".agekey")) {
		t.Errorf("after a drain: the retired key is kept %v, the current one %v", exists(prekeyFile(b, retired, ".agekey")), exists(prekeyFile(b, numberOf(t, b), ".agekey")))
	}
}
