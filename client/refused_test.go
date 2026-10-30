package client_test

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A refused message is kept with what the checks established when it was
// judged (PROTOCOL.md §12.3, "The verdict"), so that its owner can judge it once
// its key is gone: a message under a certificate that has not begun says who
// signed it, under which certificate, beginning when, and what this
// machine's clock read; a forged one says only whose identity it claims.
func TestARefusedMessageKeepsWhatItsChecksFound(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{protocol.IdentityEd25519, protocol.IdentityP256} {
		t.Run(kind, func(t *testing.T) { refusedFindings(t, kind) })
	}
}

func refusedFindings(t *testing.T, kind string) {
	ctx := context.Background()
	e := newEnv(t)
	o := e.opts()
	o.IdentityType = kind
	a, err := client.Init(ctx, t.TempDir(), o, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	b, c := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	stamp := func(t time.Time) string { return t.UTC().Format(protocol.TimeLayout) }

	// A certificate a's identity made two hours ahead of every clock here.
	key, err := os.ReadFile(filepath.Join(a.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	idSigner, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	work := workKey(t, a)
	serial := numberOf(t, a) + 1
	ahead := e.clock.Now().Add(2 * time.Hour)
	cert, err := protocol.NewCertificate(a.Identity(), idSigner, work.PublicKey(), serial, ahead)
	if err != nil {
		t.Fatal(err)
	}
	early, err := ssh.NewCertSigner(cert.PublicKey().(*ssh.Certificate), work)
	if err != nil {
		t.Fatal(err)
	}
	line := e.line(a.Identity().Document(), a.Address(), b.Address(), "under a certificate that has not begun")
	notBegun := e.seal(b, line, forge.Sign(t, early, line, b.Address()))
	forged := e.line(a.Identity().Document(), a.Address(), b.Address(), "from A, says the forger")
	forgery := e.seal(b, forged, forge.Sign(t, worker(t, c), forged, b.Address()))

	res, err := b.Receive(ctx)
	if err != nil || len(res.Refused) != 2 || len(res.Delivered) != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	qs, err := b.RefusedMail(t.Context())
	if err != nil || len(qs) != 2 {
		t.Fatalf("%+v, %v", qs, err)
	}
	byID := map[string]client.RefusedMail{}
	for _, q := range qs {
		byID[q.ID] = q
	}
	q := byID[notBegun]
	want := client.RefusedMail{
		ID:                notBegun,
		Code:              protocol.RefusedSignature,
		Reason:            "the certificate of the key that signed it has not begun, by this machine's clock",
		ReceivedAt:        q.ReceivedAt,
		JudgedAt:          stamp(e.clock.Now()),
		SignedBy:          a.Address().String(),
		CertificateSerial: serial,
		CertificateBegan:  stamp(ahead.Add(-protocol.MaxSkew)),
		CertificateEnds:   stamp(cert.NotAfter()),
		SentAt:            stamp(e.clock.Now()),
		MsgID:             q.MsgID,
	}
	if q != want || q.ReceivedAt == "" || !protocol.IsMsgID(q.MsgID) {
		t.Errorf("under a certificate that has not begun:\n got %+v\nwant %+v", q, want)
	}
	q = byID[forgery]
	want = client.RefusedMail{
		ID:             forgery,
		Code:           protocol.RefusedSignature,
		Reason:         "it is not signed under a certificate of the sender's identity",
		ReceivedAt:     q.ReceivedAt,
		JudgedAt:       stamp(e.clock.Now()),
		ClaimsIdentity: a.Address().String(),
	}
	if q != want {
		t.Errorf("a forgery:\n got %+v\nwant %+v", q, want)
	}
}

// workKey is the private half of a mailbox's current working key.
func workKey(t *testing.T, b *client.Mailbox) ssh.Signer {
	t.Helper()
	raw, err := os.ReadFile(workFile(b, numberOf(t, b), ""))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// A message refused whose ack was lost is listed again, and judged again: one
// that passes then is delivered, and nothing of its refusal is kept, neither
// the message in refused/ nor why it was refused (#211).
func TestADeliveryLeavesNothingOfAnEarlierRefusal(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
	line := forge.Line(t, a.Identity().Document(), a.Address(), b.Address(), "dated ahead of the reader", e.clock.Now().Add(2*time.Hour))
	id := e.seal(b, line, forge.Sign(t, worker(t, a), line, b.Address()))
	says(e, protocol.CodeUnavailable, "DELETE", "/messages/"+id)
	res, err := b.Receive(ctx)
	if err == nil || len(res.Refused) != 1 || res.Refused[0].Code != protocol.RefusedFuture || !exists(filepath.Join(b.Dir(), "refused", id+".json")) || !has(b, "refused/"+id+".reason") {
		t.Fatalf("a message dated ahead, whose ack fails: %+v, %v", res, err)
	}
	e.srv.SetMiddle(nil)
	e.clock.Add(2 * time.Hour)
	if res := receive(t, b); len(res.Delivered) != 1 || res.Delivered[0].ID != id {
		t.Fatalf("the same message once the clock reached it: %+v", res)
	}
	if qs, err := b.RefusedMail(t.Context()); err != nil || len(qs) != 0 || exists(filepath.Join(b.Dir(), "refused", id+".json")) || has(b, "refused/"+id+".reason") {
		t.Errorf("after its delivery the mailbox keeps %+v, %v of its refusal", qs, err)
	}
}

// A refused message names its signer only where the mailbox holds no revocation
// of that address or that certificate (#265), whichever check refuses it:
// each refusal a signature that verifies can meet, against each thing the
// reading mailbox can hold of its signer. Where it holds a revocation that covers
// the mail, the record and Refusal.Findings give the identity the mail claims
// and nothing more, as for a signature that does not verify (#336); where it
// holds none that does, both name the signer and its certificate.
func TestARefusalNamesNoSignerTheMailboxHoldsRevoked(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("long: -short skips it; scripts/check.sh full and CI run it")
	}
	type sent struct {
		id     string
		serial uint64 // the certificate it is signed under
	}
	// under is a's working key certified anew by a's identity at serial n,
	// its certificate starting at start.
	under := func(t *testing.T, a *client.Mailbox, n uint64, start time.Time) ssh.Signer {
		cert, err := protocol.NewCertificate(a.Identity(), identityKey(t, a), workKey(t, a).PublicKey(), n, start)
		if err != nil {
			t.Fatal(err)
		}
		s, err := ssh.NewCertSigner(cert.PublicKey().(*ssh.Certificate), workKey(t, a))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	signed := func(e *env, b *client.Mailbox, s ssh.Signer, line []byte) string {
		return e.seal(b, line, forge.Sign(t, s, line, b.Address()))
	}
	// Each refusal, by the check that makes it where the mailbox holds nothing
	// of a; "" is mail that passes every check before the revocations'.
	refusals := []struct {
		name, code string
		send       func(t *testing.T, e *env, a, b, thief *client.Mailbox) sent
	}{
		{"its certificate not begun", protocol.RefusedSignature, func(t *testing.T, e *env, a, b, _ *client.Mailbox) sent {
			n := numberOf(t, a) + 1
			line := e.line(a.Identity().Document(), a.Address(), b.Address(), "not begun")
			return sent{signed(e, b, under(t, a, n, e.clock.Now().Add(2*time.Hour)), line), n}
		}},
		{"its certificate ended", protocol.RefusedSignature, func(t *testing.T, e *env, a, b, _ *client.Mailbox) sent {
			n := numberOf(t, a) - 1000
			line := e.line(a.Identity().Document(), a.Address(), b.Address(), "ended")
			return sent{signed(e, b, under(t, a, n, e.clock.Now().Add(-70*24*time.Hour)), line), n}
		}},
		{"sent_at older than the TTL", protocol.RefusedStale, func(t *testing.T, e *env, a, b, _ *client.Mailbox) sent {
			line := forge.Line(t, a.Identity().Document(), a.Address(), b.Address(), "old", e.clock.Now().Add(-protocol.TTL-time.Second))
			return sent{signed(e, b, worker(t, a), line), numberOf(t, a)}
		}},
		{"sent_at ahead", protocol.RefusedFuture, func(t *testing.T, e *env, a, b, _ *client.Mailbox) sent {
			line := forge.Line(t, a.Identity().Document(), a.Address(), b.Address(), "ahead", e.clock.Now().Add(protocol.MaxSkew+time.Minute))
			return sent{signed(e, b, worker(t, a), line), numberOf(t, a)}
		}},
		{"to another mailbox", protocol.RefusedAttribution, func(t *testing.T, e *env, a, b, thief *client.Mailbox) sent {
			line := e.line(a.Identity().Document(), a.Address(), thief.Address(), "to another")
			return sent{signed(e, b, worker(t, a), line), numberOf(t, a)}
		}},
		{"an envelope of another version", protocol.RefusedEnvelope, func(t *testing.T, e *env, a, b, _ *client.Mailbox) sent {
			env := `{"v":2,"from":"` + a.Address().String() + `","to":"` + b.Address().String() + `","identity":"` + base64.StdEncoding.EncodeToString(a.Identity().Document()) + `","sent_at":"` + e.clock.Now().Format(protocol.TimeLayout) + `","msg_id":"77777777-2222-4333-8444-555555555555","body":"x"}`
			return sent{mail(t, e, a, b, env), numberOf(t, a)}
		}},
		{"sent_at below the replay set's floor", protocol.RefusedStale, func(t *testing.T, e *env, a, b, _ *client.Mailbox) sent {
			b.SetRecord(t, "seen-floor", []byte(strconv.FormatInt(e.clock.Now().Unix(), 10)))
			line := e.line(a.Identity().Document(), a.Address(), b.Address(), "below the floor")
			return sent{signed(e, b, worker(t, a), line), numberOf(t, a)}
		}},
		{"good in every other way", "", func(t *testing.T, e *env, a, b, _ *client.Mailbox) sent {
			line := e.line(a.Identity().Document(), a.Address(), b.Address(), "good mail")
			return sent{signed(e, b, worker(t, a), line), numberOf(t, a)}
		}},
	}
	// What b holds of a when it judges: covers is whether it covers the mail,
	// and late the refusal of mail that passes every check before the
	// revocations'.
	holdings := []struct {
		name   string
		covers bool
		late   string
		hold   func(t *testing.T, a, b *client.Mailbox, serial uint64)
	}{
		{"nothing", false, "", func(*testing.T, *client.Mailbox, *client.Mailbox, uint64) {}},
		{"the address revoked", true, client.RefusedRevoked, func(t *testing.T, a, b *client.Mailbox, _ uint64) {
			rec, err := a.Revocation(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := b.KeepRevocation(t.Context(), rec); err != nil {
				t.Fatal(err)
			}
		}},
		{"its certificates revoked through the mail's", true, client.RefusedCertificate, func(t *testing.T, a, b *client.Mailbox, n uint64) {
			if _, _, err := b.KeepRevocation(t.Context(), certsRecord(t, a.Dir(), n)); err != nil {
				t.Fatal(err)
			}
		}},
		{"its certificates revoked through the one below the mail's", false, "", func(t *testing.T, a, b *client.Mailbox, n uint64) {
			if _, _, err := b.KeepRevocation(t.Context(), certsRecord(t, a.Dir(), n-1)); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, r := range refusals {
		for _, h := range holdings {
			t.Run(r.name+", "+h.name, func(t *testing.T) {
				e := newEnv(t)
				a, b, thief := e.mailbox(protocol.Classic), e.mailbox(protocol.Classic), e.mailbox(protocol.Classic)
				m := r.send(t, e, a, b, thief)
				h.hold(t, a, b, m.serial)
				res := receive(t, b)
				code := r.code
				if code == "" {
					code = h.late
				}
				if code == "" {
					if len(res.Delivered) != 1 || len(res.Refused) != 0 {
						t.Fatalf("want it delivered: %+v", res)
					}
					return
				}
				if len(res.Refused) != 1 || res.Refused[0].Code != code || res.Refused[0].ID != m.id {
					t.Fatalf("want it refused %s: %+v", code, res)
				}
				q, f := refusedAs(t, b, m.id), res.Refused[0].Findings
				if h.covers {
					if q.SignedBy != "" || q.ClaimsIdentity != a.Address().String() || q.CertificateSerial != 0 || q.SentAt != "" || q.MsgID != "" {
						t.Errorf("kept as %+v, where the mailbox holds a revocation that covers it", q)
					}
					if f.Signed || f.Identity == nil || *f.Identity != a.Address() || f.Serial != 0 || !f.Began.IsZero() || !f.Ends.IsZero() || !f.SentAt.IsZero() || f.MsgID != "" {
						t.Errorf("Refusal.Findings %+v, where the mailbox holds a revocation that covers it", f)
					}
					return
				}
				if q.SignedBy != a.Address().String() || q.CertificateSerial != m.serial {
					t.Errorf("kept as %+v, where the mailbox holds no revocation that covers it", q)
				}
				if !f.Signed || f.Serial != m.serial {
					t.Errorf("Refusal.Findings %+v, where the mailbox holds no revocation that covers it", f)
				}
			})
		}
	}
}

// identityKey is a mailbox's identity key.
func identityKey(t *testing.T, b *client.Mailbox) ssh.Signer {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(b.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// refusedAs is what refused list gives of message id.
func refusedAs(t *testing.T, b *client.Mailbox, id string) client.RefusedMail {
	t.Helper()
	qs, err := b.RefusedMail(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range qs {
		if q.ID == id {
			return q
		}
	}
	t.Fatalf("refused/ holds no %s: %+v", id, qs)
	return client.RefusedMail{}
}
