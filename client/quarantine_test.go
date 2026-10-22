package client_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A refused message is kept with what the checks established when it was
// judged (PROTOCOL.md §5, "The verdict"), so that its owner can judge it once
// its key is gone: a message under a certificate that has not begun says who
// signed it, under which certificate, beginning when, and what this
// machine's clock read; a forged one says only whose identity it claims.
func TestAQuarantinedMessageKeepsWhatItsChecksFound(t *testing.T) {
	for _, kind := range []string{protocol.IdentityEd25519, protocol.IdentityP256} {
		t.Run(kind, func(t *testing.T) { quarantinedFindings(t, kind) })
	}
}

func quarantinedFindings(t *testing.T, kind string) {
	ctx := context.Background()
	e := newEnv(t)
	o := e.opts()
	o.IdentityType = kind
	a, err := client.Init(ctx, t.TempDir(), o, protocol.Classic)
	if err != nil {
		t.Fatal(err)
	}
	b, c := e.box(protocol.Classic), e.box(protocol.Classic)
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
	notBegun := e.seal(b, a.Address(), line, forge.Sign(t, early, line, b.Address()))
	forged := e.line(a.Identity().Document(), a.Address(), b.Address(), "from A, says the forger")
	forgery := e.seal(b, a.Address(), forged, forge.Sign(t, worker(t, c), forged, b.Address()))

	res, err := b.Receive(ctx)
	if err != nil || len(res.Refused) != 2 || len(res.Delivered) != 0 {
		t.Fatalf("%+v, %v", res, err)
	}
	qs, err := b.Quarantined()
	if err != nil || len(qs) != 2 {
		t.Fatalf("%+v, %v", qs, err)
	}
	byID := map[string]client.Quarantined{}
	for _, q := range qs {
		byID[q.ID] = q
	}
	q := byID[notBegun]
	want := client.Quarantined{
		ID:                notBegun,
		Code:              protocol.RefusedSignature,
		Reason:            "the certificate of the key that signed it has not begun, by this machine's clock",
		From:              a.Address().String(),
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
	want = client.Quarantined{
		ID:             forgery,
		Code:           protocol.RefusedSignature,
		Reason:         "it is not signed under a certificate of the sender's identity",
		From:           a.Address().String(),
		ReceivedAt:     q.ReceivedAt,
		JudgedAt:       stamp(e.clock.Now()),
		ClaimsIdentity: a.Address().String(),
	}
	if q != want {
		t.Errorf("a forgery:\n got %+v\nwant %+v", q, want)
	}
}

// workKey is the private half of a box's current working key.
func workKey(t *testing.T, b *client.Box) ssh.Signer {
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
// the message in quarantine/ nor why it was refused (#211).
func TestADeliveryLeavesNothingOfAnEarlierRefusal(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	line := forge.Line(t, a.Identity().Document(), a.Address(), b.Address(), "dated ahead of the reader", e.clock.Now().Add(2*time.Hour))
	id := e.seal(b, a.Address(), line, forge.Sign(t, worker(t, a), line, b.Address()))
	says(e, protocol.CodeUnavailable, "DELETE", "/messages/"+id)
	res, err := b.Receive(ctx)
	if err == nil || len(res.Refused) != 1 || res.Refused[0].Code != protocol.RefusedFuture || !exists(filepath.Join(b.Dir(), "quarantine", id+".json")) || !has(b, "quarantine/"+id+".reason") {
		t.Fatalf("a message dated ahead, whose ack fails: %+v, %v", res, err)
	}
	e.srv.SetMiddle(nil)
	e.clock.Add(2 * time.Hour)
	if res := receive(t, b); len(res.Delivered) != 1 || res.Delivered[0].ID != id {
		t.Fatalf("the same message once the clock reached it: %+v", res)
	}
	if qs, err := b.Quarantined(); err != nil || len(qs) != 0 || exists(filepath.Join(b.Dir(), "quarantine", id+".json")) || has(b, "quarantine/"+id+".reason") {
		t.Errorf("after its delivery the box keeps %+v, %v of its refusal", qs, err)
	}
}

// A refused message names its signer only where the box holds no revocation
// of that address or that certificate (#265): mail a thief signs with a taken
// working key whose certificate the identity revoked, posted from the thief's
// own box, is kept as claiming the identity, never as signed by it; and so is
// mail of an address the box holds revoked.
func TestARefusalNamesNoSignerTheBoxHoldsRevoked(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b, thief := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	stolen := worker(t, a)
	if _, err := a.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeEarlier(ctx); err != nil {
		t.Fatal(err)
	}
	if held, err := b.Ask(ctx, a.Address()); err != nil || held.Certificates == nil {
		t.Fatalf("b asks about a: %+v, %v", held, err)
	}
	line := e.line(a.Identity().Document(), a.Address(), b.Address(), "signed with a key a revoked, posted from another box")
	id := e.seal(b, thief.Address(), line, forge.Sign(t, stolen, line, b.Address()))
	res := receive(t, b)
	if len(res.Refused) != 1 || res.Refused[0].Code != protocol.RefusedAttribution {
		t.Fatalf("the thief's mail: %+v", res)
	}
	q := quarantinedAs(t, b, id)
	if q.SignedBy != "" || q.ClaimsIdentity != a.Address().String() || q.CertificateSerial != 0 {
		t.Errorf("mail under a certificate the box holds revoked is kept as %+v", q)
	}

	// The address itself revoked: mail signed by its working key in use.
	rec, err := a.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.KeepRevocation(rec); err != nil {
		t.Fatal(err)
	}
	line = e.line(a.Identity().Document(), a.Address(), b.Address(), "from an address the box holds revoked")
	id = e.seal(b, thief.Address(), line, forge.Sign(t, worker(t, a), line, b.Address()))
	receive(t, b)
	if q := quarantinedAs(t, b, id); q.SignedBy != "" || q.ClaimsIdentity != a.Address().String() {
		t.Errorf("mail of an address the box holds revoked is kept as %+v", q)
	}
}

// quarantinedAs is what quarantine list gives of message id.
func quarantinedAs(t *testing.T, b *client.Box, id string) client.Quarantined {
	t.Helper()
	qs, err := b.Quarantined()
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range qs {
		if q.ID == id {
			return q
		}
	}
	t.Fatalf("quarantine/ holds no %s: %+v", id, qs)
	return client.Quarantined{}
}
