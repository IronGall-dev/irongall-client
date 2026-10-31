package client_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The two modes (PROTOCOL.md §5): a mailbox's identity signs in identity
// mode, the default; in working-key mode, reached by a one-way trip, a
// working key under a certificate does. What each party takes of a sender is
// its mode, read from the revocation of its certificates it holds.

// modeOf is a mailbox's mode, as it keeps it.
func modeOf(t *testing.T, b *client.Mailbox) string {
	t.Helper()
	m, err := b.Mode(t.Context())
	if err != nil {
		t.Fatalf("the mode: %v", err)
	}
	return m
}

// A reader that has never met a sender takes its first message in either
// mode: the identity's signature from a sender it holds no trip of, and a
// certificate's from one whose trip its read of the sender shows.
func TestAFirstContactReaderOfEachMode(t *testing.T) {
	t.Parallel()
	for _, working := range []bool{false, true} {
		e := newEnv(t)
		e.working = working
		a := e.mailbox()
		e.working = false
		b := e.mailbox() // the reader, in identity mode either way
		if want := map[bool]string{false: "identity", true: "working_key"}[working]; modeOf(t, a) != want {
			t.Fatalf("the sender's mode: %s, want %s", modeOf(t, a), want)
		}
		send(t, a, b, "the first message")
		if res := receive(t, b); len(res.Delivered) != 1 || len(res.Refused) != 0 {
			t.Fatalf("working-key mode %v: the first message from a sender never met: %+v", working, res)
		}
	}
}

// certificateOf makes a certificate of a new working key, serial n, by the
// identity of mailbox b, and returns its signer: what whoever holds the
// identity can make.
func certificateOf(t *testing.T, e *env, b *client.Mailbox, n uint64) ssh.Signer {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	work, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := protocol.NewCertificate(b.Identity(), identityKey(t, b), work.PublicKey(), n, e.clock.Now(), testCertLife)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert.PublicKey().(*ssh.Certificate), work)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A reader applies the sender's mode at check 7 (PROTOCOL.md §12.3): a
// certificate's signature from a sender in identity mode is bad_signature,
// and the identity's own from a sender in working-key mode is
// certificate_revoked, whatever else verifies. The words name no certificate 0.
func TestTheReaderAppliesTheSendersMode(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.mailbox(), e.mailbox()
	messageAs(t, e, a, b, certificateOf(t, e, a, protocol.SerialAt(e.clock.Now(), 0)), "a certificate from a sender in identity mode")
	res := receive(t, b)
	if len(res.Refused) != 1 || res.Refused[0].Code != protocol.RefusedSignature || !strings.Contains(res.Refused[0].Reason, "identity mode") {
		t.Fatalf("a certificate from a sender in identity mode: %+v", res)
	}
	if q := refusedAs(t, b, res.Refused[0].ID); q.CertificateSerial == 0 || q.SignedBy != a.Address().String() {
		t.Errorf("kept as %+v: who signed it, under its certificate", q)
	}

	w := newWorkEnv(t)
	c, d := w.mailbox(), w.mailbox()
	messageAs(t, w, c, d, identityKey(t, c), "the identity's signature from a sender in working-key mode")
	res = receive(t, d)
	if len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate || strings.Contains(res.Refused[0].Reason, "certificate 0") {
		t.Fatalf("the identity's signature from a sender in working-key mode: %+v", res)
	}
	if q := refusedAs(t, d, res.Refused[0].ID); q.CertificateSerial != 0 || q.SignedBy != "" || q.ClaimsIdentity != c.Address().String() {
		t.Errorf("kept as %+v: the identity it claims alone, since the mailbox holds its trip", q)
	}
}

// Before it refuses a certificate's signature from a sender whose trip it
// holds none of, a reader reads that sender once more, once in a drain: a
// trip that reaches the sender's server's store after its first message
// under a certificate is taken then. One a server never shows refuses the
// message, after one read more, whatever more it sends.
func TestTheReaderReadsTheSenderOnceMoreBeforeRefusingACertificate(t *testing.T) {
	t.Parallel()
	for _, shown := range []bool{true, false} {
		e := newWorkEnv(t)
		a := e.mailbox()
		e.working = false
		b := e.mailbox()
		reads := 0
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if x, ok := forge.ReadOf(r); ok && x == a.Address() {
				reads++
				if reads == 1 || !shown {
					e.serve(w, r, next, func(br *protocol.MailboxResponse) { br.RevokedCertificates, br.RevokedCertificatesSignature = nil, nil })
					return
				}
			}
			next.ServeHTTP(w, r)
		})
		send(t, a, b, "the first under a certificate")
		send(t, a, b, "the second")
		res := receive(t, b)
		switch {
		case shown && (len(res.Delivered) != 2 || reads != 2):
			t.Errorf("a trip shown at the second read: %+v, %d reads of the sender", res, reads)
		case !shown && (len(res.Refused) != 2 || res.Refused[0].Code != protocol.RefusedSignature || reads != 2):
			t.Errorf("a trip never shown: %+v, %d reads of the sender, want 2", res, reads)
		}
	}
}

// A reader whose server holds no mailbox for a sender reads its
// revocations there (GET …/revocations): the trip of a sender its server
// forgot is taken, and its message under a certificate delivered.
func TestTheReaderReadsTheRevocationsOfASenderItsServerForgot(t *testing.T) {
	t.Parallel()
	e := newWorkEnv(t)
	a := e.mailbox()
	e.working = false
	b := e.mailbox()
	send(t, a, b, "from a sender about to be forgotten")
	e.srv.Forget(a.Address())
	from := len(e.srv.Requests())
	res := receive(t, b)
	if len(res.Delivered) != 1 {
		t.Fatalf("a message from a sender its server forgot: %+v", res)
	}
	read := false
	for _, q := range e.srv.Requests()[from:] {
		read = read || q.Method == http.MethodGet && q.Path == mailboxPath(a)+"/revocations"
	}
	if !read {
		t.Error("the sender's revocations were not read")
	}
}

// A sender refuses, at its read before every post, a statement whose signer
// the recipient's mode refuses (PROTOCOL.md §12.2): one under a certificate
// from a recipient in identity mode, and one by the identity from a
// recipient in working-key mode. Nothing is posted.
func TestASenderRefusesAStatementTheRecipientsModeRefuses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, working := range []bool{false, true} {
		e := newEnv(t)
		e.working = working
		a := e.mailbox()
		e.working = false
		b := e.mailbox()
		var by ssh.Signer = identityKey(t, a)
		if !working {
			by = certificateOf(t, e, a, protocol.SerialAt(e.clock.Now(), 0)+5)
		}
		st, _ := e.srv.Prekey(a.Address())
		p, err := protocol.ParsePrekey(st)
		if err != nil {
			t.Fatal(err)
		}
		p.Serial += 10
		sig, err := protocol.Sign(by, p.Statement(), protocol.PrekeyNamespace(a.Address()))
		if err != nil {
			t.Fatal(err)
		}
		op := watchWith(e, func(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
			if x, ok := forge.ReadOf(r); ok && x == a.Address() {
				e.serve(w, r, next, func(br *protocol.MailboxResponse) { br.Prekey, br.PrekeySignature = p.Statement(), sig })
				return true
			}
			return false
		})
		want := map[bool]string{false: "its address is in identity mode", true: "its address is in working-key mode"}[working]
		if _, err := b.Send(ctx, a.Address(), "never posted"); err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("working-key mode %v: a send to a statement the mode refuses: %v", working, err)
		}
		if op.count(http.MethodPost, postTo(a)) != 0 {
			t.Fatalf("working-key mode %v: it was posted", working)
		}
	}
}

// The switch to working-key mode (Mailbox.Switch): the trip, then the first
// statement under a certificate above it, then the messages sent/ keeps from
// the last TTL posted again, under the certificate, each with its msg_id.
// A reader that read the first copy drops the second; one that read none
// takes the second, and refuses the first, signed by the identity, as
// certificate_revoked once it holds the trip. Its server then takes no
// statement the identity signs, and before the trip took none under a
// certificate.
func TestTheSwitchMakesTheTripThenItsFirstCertificate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, read, unread := e.mailbox(), e.mailbox(), e.mailbox()
	send(t, a, read, "read before the switch")
	if res := receive(t, read); len(res.Delivered) != 1 {
		t.Fatal(res)
	}
	send(t, a, unread, "unread at the switch")
	first := numberOf(t, a)
	st, sig := e.srv.Prekey(a.Address())
	idStatement := protocol.PrekeyRequest{Prekey: st, PrekeySignature: sig}

	// Before the trip the server takes no statement under a certificate.
	early := certificateOf(t, e, a, protocol.SerialAt(e.clock.Now(), first))
	if code := upload(t, e, a, early, first+100, early); code != protocol.CodeIdentityMode {
		t.Errorf("a certificate's statement before the trip: %q, want identity_mode", code)
	}

	e.clock.Add(2 * time.Second)
	r, err := a.Switch(ctx)
	if err != nil || r.Prekey == nil || len(r.Retried) != 2 || r.NotRetried != nil {
		t.Fatalf("the switch: %+v, %v", r, err)
	}
	if modeOf(t, a) != "working_key" || servedCertificate(t, e, a) != numberOf(t, a) || keptThrough(t, a) < first || keptThrough(t, a) >= numberOf(t, a) {
		t.Fatalf("after the switch: mode %s, the server serves %d, the mailbox published %d, its trip through %d", modeOf(t, a), servedCertificate(t, e, a), numberOf(t, a), keptThrough(t, a))
	}
	if res := receive(t, read); len(res.Delivered) != 0 || len(res.Duplicates) != 1 {
		t.Errorf("the reader that read the first copy: %+v", res)
	}
	res := receive(t, unread)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "unread at the switch" || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Errorf("the reader that read none: %+v", res)
	}

	// After the trip the server takes no statement its identity signs, the
	// one it served before included.
	body, _ := json.Marshal(idStatement)
	if code := put(t, e, a, "/prekey", body, identityKey(t, a)); code != protocol.CodeCertificateRevoked {
		t.Errorf("an identity's statement after the trip: %q, want certificate_revoked", code)
	}
	// Run again, it is done.
	if _, err := a.Switch(ctx); err == nil || !strings.Contains(err.Error(), "working-key mode already") {
		t.Errorf("a second switch: %v", err)
	}
}

// upload sends a prekey statement at serial n signed by by to mailbox a's
// server, with a pass by pass, as anyone holding them can, and returns the
// code the server answers, or "" for none.
func upload(t *testing.T, e *env, a *client.Mailbox, by ssh.Signer, n uint64, pass ssh.Signer) protocol.Code {
	t.Helper()
	k, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p := &protocol.Prekey{Address: a.Address(), Serial: n, Key: k.Recipient().String(), NotAfter: e.clock.Now().Add(24 * time.Hour).Truncate(time.Second)}
	sig, err := protocol.Sign(by, p.Statement(), protocol.PrekeyNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(protocol.PrekeyRequest{Prekey: p.Statement(), PrekeySignature: sig})
	return put(t, e, a, "/prekey", body, pass)
}

// put PUTs body to mailbox a's path rest with a pass by pass, and returns
// the code the server answers, or "" for none.
func put(t *testing.T, e *env, a *client.Mailbox, rest string, body []byte, pass ssh.Signer) protocol.Code {
	t.Helper()
	h, _, err := protocol.NewPass(pass, a.Address(), strings.TrimPrefix(e.srv.URL, "http://"), e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPut, e.srv.URL+mailboxPath(a)+rest, bytes.NewReader(body))
	req.Header.Set("Authorization", h)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // read only
	var p protocol.Problem
	if resp.StatusCode < 300 {
		return ""
	}
	if err := json.NewDecoder(resp.Body).Decode(&p); err != nil {
		t.Fatal(err)
	}
	return p.Code
}

// A server takes a pass only by the current statement's signer (PROTOCOL.md
// §8): the identity's pass at an address in working-key mode is
// certificate_revoked; a certificate's at an address in identity mode is
// certificate_not_current, naming no certificate.
func TestThePassIsByTheCurrentStatementsSigner(t *testing.T) {
	t.Parallel()
	e := newWorkEnv(t)
	a := e.mailbox()
	if code := put(t, e, a, "/acl", []byte(`{"allow":["*"],"deny":[]}`), identityKey(t, a)); code != protocol.CodeCertificateRevoked {
		t.Errorf("the identity's pass in working-key mode: %q", code)
	}
	e.working = false
	b := e.mailbox()
	cert := certificateOf(t, e, b, protocol.SerialAt(e.clock.Now(), 0)+5)
	h, _, err := protocol.NewPass(cert, b.Address(), strings.TrimPrefix(e.srv.URL, "http://"), e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, e.srv.URL+mailboxPath(b)+"/acl", nil)
	req.Header.Set("Authorization", h)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var p protocol.Problem
	_ = json.NewDecoder(resp.Body).Decode(&p)
	_ = resp.Body.Close()
	if p.Code != protocol.CodeCertificateNotCurrent || p.CertificateSerial != nil {
		t.Errorf("a certificate's pass in identity mode: %+v", p)
	}
	if words := (&client.APIError{Status: 401, Problem: p}).Error(); strings.Contains(words, "certificate 0") || strings.Contains(words, ", certificate ") {
		t.Errorf("certificate_not_current with no certificate says %q", words)
	}
}

// On 409 identity_mode, a server that does not hold the trip (here, one that
// lost it), a mailbox in working-key mode publishes the revocation it keeps
// and renews again, once.
func TestOnIdentityModeTheMailboxPublishesItsTripAndRenewsAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a := e.mailbox()
	e.clock.Add(2 * time.Second)
	once := false
	op := watchWith(e, func(w http.ResponseWriter, r *http.Request, next http.Handler) bool {
		if r.Method == http.MethodPut && r.URL.Path == mailboxPath(a)+"/prekey" && !once {
			once = true
			forge.Refuse(w, protocol.CodeIdentityMode)
			return true
		}
		return false
	})
	p, err := a.Rekey(ctx)
	if err != nil || p == nil || servedSerial(t, e, a) != p.Serial {
		t.Fatalf("a renewal answered identity_mode once: %+v, %v", p, err)
	}
	if op.count(http.MethodPut, mailboxPath(a)+"/revocations") != 1 || op.count(http.MethodPut, mailboxPath(a)+"/prekey") != 2 {
		t.Errorf("calls: %q", op.seen)
	}
}

// A server whose maximum leaves a certificate no time to sign messages, the
// TTL and the hour, is refused working-key mode before anything is published
// (PROTOCOL.md §11.18); identity mode goes on there.
func TestWorkingKeyModeIsRefusedWhereTheServersMaximumLeavesNoRoom(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	e.srv.SetPolicy(protocol.ServerDocument{MaxCertificateLifetime: uint64((protocol.TTL + protocol.MaxSkew) / time.Second)})
	opt := e.opts()
	opt.WorkingKey = true
	from := len(e.srv.Requests())
	if _, err := client.Init(ctx, t.TempDir(), opt); err == nil || !strings.Contains(err.Error(), "working-key mode is refused here") {
		t.Fatalf("init --offline: %v", err)
	}
	for _, q := range e.srv.Requests()[from:] {
		if q.Method != http.MethodGet {
			t.Errorf("%s %s before working-key mode was refused", q.Method, q.Path)
		}
	}
	// An hour more is room.
	e.srv.SetPolicy(protocol.ServerDocument{MaxCertificateLifetime: uint64((protocol.TTL+protocol.MaxSkew)/time.Second) + 3600})
	if b, err := client.Init(ctx, t.TempDir(), opt); err != nil || modeOf(t, b) != "working_key" {
		t.Fatalf("init --offline with room: %v", err)
	}
	if _, err := client.Init(ctx, t.TempDir(), e.opts()); err != nil {
		t.Fatalf("init in identity mode: %v", err)
	}
}

// A certificate runs for the longest its server's document names. A server
// whose maximum is shorter than that, its document read before it changed,
// answers certificate_too_long with its maximum, and the mailbox makes the
// statement again under a certificate of that one, once.
func TestACertificateTooLongIsMadeAgainAtTheServersMaximum(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a := e.mailbox()
	e.clock.Add(2 * time.Second)
	short := fakeserver.MaxCertificateLifetime - 86400
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.URL.Path == protocol.DocumentPath {
			next.ServeHTTP(w, r) // the document names the longer one
			e.srv.SetPolicy(protocol.ServerDocument{MaxCertificateLifetime: short})
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := a.Rekey(ctx); err != nil {
		t.Fatalf("a renewal answered certificate_too_long: %v", err)
	}
	st, sig := e.srv.Prekey(a.Address())
	_, by, err := protocol.VerifyPrekey(a.Identity(), st, sig, e.clock.Now())
	if err != nil || by.Certificate() == nil || by.Certificate().Lifetime() != time.Duration(short)*time.Second {
		t.Fatalf("the statement taken: %v, %+v", err, by)
	}
	words := (&client.APIError{Status: 400, Problem: protocol.Problem{Code: protocol.CodeCertificateTooLong, MaxCertificateLifetime: &short}}).Error()
	if !strings.Contains(words, strconv.FormatUint(short, 10)+" seconds") {
		t.Errorf("certificate_too_long says %q", words)
	}
}

// The server keeps a mailbox until the later of its prekey's not_after plus
// the TTL and the end of the latest certificate it took, and never lowers it.
func TestTheServerKeepsAMailboxByItsLatestCertificate(t *testing.T) {
	t.Parallel()
	e := newWorkEnv(t)
	// A certificate longer than a prekey and the TTL: its end is the later.
	long := 200 * 24 * time.Hour
	e.srv.SetPolicy(protocol.ServerDocument{MaxCertificateLifetime: uint64(long / time.Second)})
	a := e.mailbox()
	kept := e.srv.KeptUntil(a.Address())
	if want := e.clock.Now().Add(-protocol.MaxSkew).Add(long); kept.Before(want) {
		t.Errorf("kept until %s, before its certificate ends, %s", kept, want)
	}
	e.clock.Add(time.Hour)
	if err := a.SetPrekeyLifetime(t.Context(), client.MinPrekeyLifetime); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Rekey(t.Context()); err != nil {
		t.Fatal(err)
	}
	if again := e.srv.KeptUntil(a.Address()); again.Before(kept) {
		t.Errorf("kept until %s, lowered from %s", again, kept)
	}
}

// A restore is told its mode (init, or init --offline) and never guesses: it
// reads its mailbox and its revocations at its server, and stops where they
// show the other mode, publishing nothing.
func TestARestoreIsToldItsMode(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	for _, working := range []bool{false, true} {
		for _, told := range []bool{false, true} {
			e := newEnv(t)
			e.working = working
			a := e.mailbox()
			e.clock.Add(time.Minute)
			r := restore(t, e, a)
			opt := e.opts()
			opt.WorkingKey = told
			from := len(e.srv.Requests())
			_, err := client.Init(ctx, r.Dir(), opt)
			published := false
			for _, q := range e.srv.Requests()[from:] {
				published = published || q.Method == http.MethodPut
			}
			if told == working {
				if err != nil || modeOf(t, r) != modeOf(t, a) || servedSerial(t, e, a) != numberOf(t, r) {
					t.Errorf("working-key mode %v, told %v: %v", working, told, err)
				}
				continue
			}
			if err == nil || !strings.Contains(err.Error(), "REFUSED") || published {
				t.Errorf("working-key mode %v, told %v: %v, published %v", working, told, err, published)
			}
		}
	}
}

// A trip an identity-mode mailbox that has published a statement did not
// make, shown by a record handed over or by its server, is said, and the
// mailbox signs nothing more but its address's revocation (PROTOCOL.md
// §12.5). Its own trip, made by the switch, is never that.
func TestATripTheMailboxDidNotMakeLeavesOnlyTheRevocation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(), e.mailbox()
	rec := certsRecord(t, a.Dir(), numberOf(t, a)) // signed elsewhere, with the identity
	if _, _, err := a.KeepRevocation(ctx, rec); err != nil {
		t.Fatal(err)
	}
	var foreign *client.ForeignTripError
	if _, err := a.Mode(ctx); !errors.As(err, &foreign) {
		t.Fatalf("the mode after a trip handed over: %v", err)
	}
	if st, err := a.Status(ctx); err != nil || st.Mode != "working_key" || !strings.Contains(strings.Join(st.Attention, " "), "revoking the address") && !strings.Contains(strings.Join(st.Attention, " "), "dromas revocation publish") {
		t.Errorf("status: %+v, %v", st, err)
	}
	from := len(e.srv.Requests())
	if _, err := a.Rekey(ctx); !errors.As(err, &foreign) {
		t.Errorf("a renewal: %v", err)
	}
	if _, err := a.Send(ctx, b.Address(), "never signed"); !errors.As(err, &foreign) {
		t.Errorf("a send: %v", err)
	}
	if _, err := a.Switch(ctx); !errors.As(err, &foreign) {
		t.Errorf("a switch: %v", err)
	}
	for _, q := range e.srv.Requests()[from:] {
		if q.Pass {
			t.Errorf("%s %s carried a pass", q.Method, q.Path)
		}
	}
	rev, err := a.Revocation(ctx)
	if err != nil {
		t.Fatalf("the address's revocation: %v", err)
	}
	if _, err := a.Revoke(ctx, rev); err != nil {
		t.Errorf("published: %v", err)
	}
}

// An identity-mode mailbox served a statement its identity signed that it
// did not make says so and recommends revoking the address; recv renews
// nothing above it, its owner's renewal does, and its outbox does not wait:
// no certificate of its own is in doubt (PROTOCOL.md §12.4).
func TestAnIdentityModeStatementItDidNotMake(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(), e.mailbox()
	st, _ := e.srv.Prekey(a.Address())
	p, err := protocol.ParsePrekey(st)
	if err != nil {
		t.Fatal(err)
	}
	k, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p.Serial, p.Key = p.Serial+5, k.Recipient().String()
	sig, err := protocol.Sign(identityKey(t, a), p.Statement(), protocol.PrekeyNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == a.Address() {
			e.serve(w, r, next, func(br *protocol.MailboxResponse) { br.Prekey, br.PrekeySignature = p.Statement(), sig })
			return
		}
		next.ServeHTTP(w, r)
	})
	e.clock.Add(25 * time.Hour)
	res, err := a.Receive(ctx)
	if err != nil || res.NotMade == nil || res.Renewed != nil || res.NotMade.CertificateSerial != 0 {
		t.Fatalf("recv: %+v, %v", res, err)
	}
	if words := res.NotMade.Words(); !strings.Contains(words, "identity is in other hands") || strings.Contains(words, "certificate 0") {
		t.Errorf("its words: %s", words)
	}
	e.srv.SetMiddle(nil)
	if _, err := a.Send(ctx, b.Address(), "the outbox does not wait"); err != nil {
		t.Errorf("a send: %v", err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == a.Address() {
			e.serve(w, r, next, func(br *protocol.MailboxResponse) { br.Prekey, br.PrekeySignature = p.Statement(), sig })
			return
		}
		next.ServeHTTP(w, r)
	})
	if q, err := a.Rekey(ctx); err != nil || q.Serial <= p.Serial {
		t.Errorf("the owner's renewal: %+v, %v", q, err)
	}
}

// After the trip both kinds of revocation still verify and are kept: they are
// the identity's, never ranked and never subject to the mode (PROTOCOL.md §5).
func TestRevocationsVerifyAfterTheTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a, b := e.mailbox(), e.mailbox()
	e.clock.Add(2 * time.Second)
	if _, err := a.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	certs, err := a.RevokeEarlier(ctx)
	if err != nil || certs == nil {
		t.Fatalf("a revocation of certificates after the trip: %+v, %v", certs, err)
	}
	if held, err := b.Ask(ctx, a.Address()); err != nil || held.Certificates == nil || held.Certificates.Through != certs.Through {
		t.Fatalf("its peer asks: %+v, %v", held, err)
	}
	rec, err := a.Revocation(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Revoke(ctx, rec); err != nil {
		t.Fatal(err)
	}
	if held, err := b.Ask(ctx, a.Address()); err != nil || !held.Revoked {
		t.Fatalf("its peer asks after the address's revocation: %+v, %v", held, err)
	}
}
