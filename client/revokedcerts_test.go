package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A working key can be taken without the identity, so an identity can revoke
// the certificates it made and keep its address. These tests play a mailbox
// whose working key was taken, and an operator that helps the thief.

func keptList(b *client.Mailbox, of protocol.Address) bool {
	_, ok := stateOf(b, "peers/"+of.String()+"/revoked-certs.json")
	return ok
}

// messageAs injects a message that signer signed as mailbox from, to mailbox to, as an
// operator delivering what a thief made.
func messageAs(t *testing.T, e *env, from, to *client.Mailbox, signer ssh.Signer, body string) {
	t.Helper()
	line := e.line(from.Identity().Document(), from.Address(), to.Address(), body)
	e.seal(to, line, forge.Sign(t, signer, line, to.Address()))
}

// A mailbox renews under a new certificate and revokes every one before it. A message
// under the old certificate is refused when it is read, the mailbox's own
// included, and whatever a thief signs with the old key afterwards. The
// address goes on: the mailbox writes and is written to.
func TestRevokeEarlierEndsWhatAnOldWorkingKeySigns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a, b := e.mailbox(), e.mailbox()
	stolen := worker(t, a) // read before the renewal deletes it
	first := numberOf(t, a)
	send(t, a, b, "sent under the first certificate, and unread")
	if _, err := a.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	second := numberOf(t, a)
	certs, err := a.RevokeEarlier(ctx)
	if err != nil || certs == nil || certs.Through != second-1 || !certs.Revokes(first) || certs.Revokes(second) {
		t.Fatalf("revoke earlier: %+v, %v", certs, err)
	}
	send(t, a, b, "sent under the second certificate")

	res := receive(t, b)
	if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "sent under the second certificate" || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a drain of messages under a revoked certificate and under the current one: %+v", res)
	}
	if !keptList(b, a.Address()) || keptRevocation(b, a.Address()) {
		t.Fatal("the revocation of certificates was not kept, or the address was taken as revoked")
	}

	// The operator now hides the revocation and delivers what the thief
	// signs.
	forge.Hides(e.t, e.srv)
	messageAs(t, e, a, b, stolen, "signed by the key that was taken")
	if res := receive(t, b); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a thief's message under the revoked certificate, the revocation hidden: %+v", res)
	}
	e.srv.SetMiddle(nil)

	// The address goes on, both ways.
	send(t, b, a, "to the mailbox that revoked its old certificates")
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("the mailbox no longer receives: %+v", res)
	}

	// A second time, after another renewal: through a higher serial,
	// everything before the certificate in use.
	if _, err := a.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	if certs, err := a.RevokeEarlier(ctx); err != nil || certs.Through != numberOf(t, a)-1 || !certs.Revokes(second) {
		t.Fatalf("the second revocation: %+v, %v", certs, err)
	}
}

// RevokeEarlier after a renewal the server took whose answer the mailbox never
// had, its process killed at "renewal taken": its read of itself records that
// renewal (noteServed), so it revokes below the certificate in use once the
// read is done, the one before the renewal among them, and a reader refuses
// what that one's working key signs after it. Read before, the serial left
// that certificate unrevoked (#391).
func TestRevokeEarlierAfterARenewalTakenUnseenRevokesTheCertificateBeforeIt(t *testing.T) {
	t.Parallel()
	for _, killed := range []bool{false, true} {
		name := "the renewal recorded"
		if killed {
			name = "the renewal taken unseen"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			e := newWorkEnv(t)
			b, c := e.mailbox(), e.mailbox()
			before := numberOf(t, b)
			stolen := worker(t, b) // in use before the renewal: whoever copied the mailbox holds it
			e.clock.Add(2 * time.Second)
			if killed {
				crash(t, e, b, "rekey", "renewal taken", protocol.Address{})
			} else if _, err := b.Rekey(ctx); err != nil {
				t.Fatal(err)
			}
			x, err := client.Open(b.Dir(), e.opts())
			if err != nil {
				t.Fatal(err)
			}
			certs, err := x.RevokeEarlier(ctx)
			inUse := numberOf(t, x)
			if err != nil || certs == nil || certs.Through != inUse-1 || !certs.Revokes(before) || inUse != servedSerial(t, e, x) {
				t.Errorf("RevokeEarlier, with %d in use before the renewal and %d after (the server's %d): %+v, %v", before, inUse, servedSerial(t, e, x), certs, err)
			}
			// What that working key signs after, as b, put in c's mailbox by
			// whoever holds it and the server: c reads b's mailbox, with its
			// revocation of certificates, before it judges.
			messageAs(t, e, x, c, stolen, "signed with the working key b used before its renewal")
			if res := receive(t, c); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
				t.Errorf("a message under certificate %d after RevokeEarlier: delivered %d, refused %+v", before, len(res.Delivered), res.Refused)
			}
		})
	}
}

// A revocation of certificates is the identity's to sign, and the highest one
// a reader has verified stands: what a server shows that a working key
// signed, or that is a lower one of the identity's own, changes nothing.
func TestOnlyTheIdentitysHighestRevocationCounts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a, b := e.mailbox(), e.mailbox()
	doc := a.Identity().Document()
	// show serves A's mailbox with rec's revocation of certificates in place of
	// what the server holds, and counts the reads it served so.
	var shown atomic.Int32
	show := func(rec protocol.Revocations) {
		shown.Store(0)
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if x, ok := forge.ReadOf(r); ok && x == a.Address() {
				shown.Add(1)
				e.serve(w, r, next, func(br *protocol.MailboxResponse) {
					br.RevokedCertificates, br.RevokedCertificatesSignature = rec.RevokedCertificates, rec.RevokedCertificatesSignature
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	// B meets A first through an honest read, and keeps its trip, without
	// which it takes no certificate of A's: a server that withholds it costs
	// A its messages, and forges nothing (PROTOCOL.md §15.6).
	send(t, a, b, "before anything is forged")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("the first message: %+v", res)
	}

	// What a working key can sign: a revocation of the mailbox's own
	// certificate.
	forged, err := protocol.NewRevokedCertificates(a.Address(), numberOf(t, a))
	if err != nil {
		t.Fatal(err)
	}
	byWorker, err := protocol.Sign(worker(t, a), forged.Statement(), protocol.RevokedCertsNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	show(protocol.Revocations{Identity: doc, RevokedCertificates: forged.Statement(), RevokedCertificatesSignature: byWorker})
	send(t, a, b, "under certificate 1, which a working key cannot revoke")
	if res := receive(t, b); len(res.Delivered) != 1 || keptList(b, a.Address()) || shown.Load() == 0 {
		t.Fatalf("a revocation a working key signed was applied or kept, or never shown: %+v", res)
	}
	e.srv.SetMiddle(nil)

	// The identity's first revocation covers certificate 1; its second, 1
	// and 2.
	if _, err := a.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeEarlier(ctx); err != nil {
		t.Fatal(err)
	}
	var served protocol.MailboxResponse
	resp, err := http.Get(e.srv.URL + "/v1/" + a.Address().String())
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&served); err != nil || served.Record() == nil {
		t.Fatalf("the read of a mailbox with its certificates revoked: %+v, %v", served, err)
	}
	_ = resp.Body.Close()
	firstList := *served.Record()
	second := workerAt(t, a, numberOf(t, a)) // read before the next renewal deletes it
	if _, err := a.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeEarlier(ctx); err != nil {
		t.Fatal(err)
	}
	messageAs(t, e, a, b, second, "under certificate 2, which the second revocation covers")
	if res := receive(t, b); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a message under a revoked certificate: %+v", res)
	}

	// A server serves the first revocation again, which did not cover
	// certificate 2. B holds the second, and a lower one never replaces a
	// higher one: what was revoked stays revoked.
	show(firstList)
	messageAs(t, e, a, b, second, "under certificate 2, with the lower revocation shown again")
	if res := receive(t, b); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate || shown.Load() == 0 {
		t.Fatalf("a lower revocation replaced the higher one, or was never shown: %+v", res)
	}
	// And with nothing shown at all, the kept revocation still stands.
	show(protocol.Revocations{Identity: doc})
	messageAs(t, e, a, b, second, "under certificate 2, with no revocation shown")
	if res := receive(t, b); len(res.Delivered) != 0 || len(res.Refused) != 1 || shown.Load() == 0 {
		t.Fatalf("the kept revocation did not hold once the server stopped showing it: %+v", res)
	}
}

// A mailbox's statements are ordered by certificate first. So whoever took a
// working key can publish a prekey at the highest serial there is and hold
// nothing: the mailbox's next certificate passes it, at the server and at every
// sender that had pinned the thief's.
func TestALaterCertificateOutranksAnyPrekeySerial(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a, b := e.mailbox(), e.mailbox()
	stolen := worker(t, a)
	first := numberOf(t, a)
	st, _ := e.srv.Prekey(a.Address())
	p, err := protocol.ParsePrekey(st)
	if err != nil {
		t.Fatal(err)
	}
	p.Serial = protocol.MaxSerial
	sig, err := protocol.Sign(stolen, p.Statement(), protocol.PrekeyNamespace(a.Address()))
	if err != nil {
		t.Fatal(err)
	}
	pass, _, err := protocol.NewPass(stolen, a.Address(), strings.TrimPrefix(e.srv.URL, "http://"), e.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(protocol.PrekeyRequest{Prekey: p.Statement(), PrekeySignature: sig})
	req, _ := http.NewRequest(http.MethodPut, e.srv.URL+"/v1/"+a.Address().String()+"/prekey", bytes.NewReader(body))
	req.Header.Set("Authorization", pass)
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("the thief's prekey at the last serial: %v, %v", resp, err)
	}
	_ = resp.Body.Close()

	// B fetches it, and is pinned at the last serial under the first certificate.
	if _, err := b.Resolve(ctx, a.Address()); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	// A renews: a new certificate, at a later number, far below that serial.
	got, err := a.Rekey(ctx)
	if err != nil || got.Serial <= first || got.Serial >= protocol.MaxSerial {
		t.Fatalf("a renewal after a prekey at the last serial: %+v, %v", got, err)
	}
	// B follows the mailbox to the later certificate, and messages reach A again.
	send(t, b, a, "to the mailbox that took its address back")
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("a message after the renewal: %+v", res)
	}
	// And never back: the thief's statement, served again, is a rollback.
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/"+a.Address().String() {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.MailboxResponse{Identity: a.Identity().Document(), Prekey: p.Statement(), PrekeySignature: sig})
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := b.Send(ctx, a.Address(), "to the thief's prekey"); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("under certificate %d, below %d", first, got.Serial)) {
		t.Fatalf("the earlier certificate served again: %v", err)
	}
}

// A revocation of certificates the mailbox keeps that no longer verifies, or is
// no record, is an error at each use, never nothing revoked: the mailbox's own
// stops a renewal, and a peer's a send to it and a drain of its messages, which
// stay on the server (#69).
func TestAKeptRevocationOfCertificatesThatDoesNotVerifyIsAnError(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a, b := e.mailbox(), e.mailbox()
	if _, err := a.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeEarlier(ctx); err != nil {
		t.Fatal(err)
	}
	send(t, b, a, "keeps what a's mailbox carries")
	raw, ok := a.Record(t, "revoked-certs.json")
	if !ok {
		t.Fatal("a keeps no revocation of its certificates")
	}
	var rec protocol.Revocations
	if err := protocol.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	other, err := protocol.NewRevokedCertificates(a.Address(), 1)
	if err != nil {
		t.Fatal(err)
	}
	rec.RevokedCertificates = other.Statement() // under the signature of another
	tampered, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	n := numberOf(t, a)
	for _, c := range []struct{ name, why string }{{string(tampered), "no longer verifies"}, {"not a record", "is not a record"}} {
		a.SetRecord(t, "revoked-certs.json", []byte(c.name))
		e.clock.Add(2 * time.Second)
		if _, err := a.Rekey(ctx); err == nil || !strings.Contains(err.Error(), c.why) || numberOf(t, a) != n {
			t.Errorf("its own %s: rekey %v, published %d of %d", c.why, err, numberOf(t, a), n)
		}
	}
	b.SetRecord(t, "peers/"+a.Address().String()+"/revoked-certs.json", tampered)
	if _, err := b.Send(ctx, a.Address(), "to a mailbox whose revocation b keeps broken"); err == nil || !strings.Contains(err.Error(), "no longer verifies") {
		t.Errorf("a peer's that no longer verifies: send %v", err)
	}
	a.SetRecord(t, "revoked-certs.json", raw)
	send(t, a, b, "from a mailbox whose revocation b keeps broken")
	if _, err := b.Receive(ctx); err == nil || !strings.Contains(err.Error(), "no longer verifies") || e.srv.Count(b.Address()) != 1 {
		t.Errorf("a peer's that no longer verifies: recv %v, the server holds %d", err, e.srv.Count(b.Address()))
	}
}

// So it is where the server shows none of the mailbox's revocations, and what a
// mailbox keeps is all there is (PROTOCOL.md §10.2): above, each command meets
// the fault first in its keep of what the read of a's mailbox shows, so each use
// of the kept record is held here, the renewal's (nextNumber), the send's
// (resolve) and the drain's (judge) (#392).
func TestAKeptRevocationOfCertificatesThatDoesNotVerifyIsAnErrorWhereTheServerShowsNone(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newWorkEnv(t)
	a, b := e.mailbox(), e.mailbox()
	if _, err := a.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeEarlier(ctx); err != nil {
		t.Fatal(err)
	}
	send(t, b, a, "keeps what a's mailbox carries")
	raw, ok := b.Record(t, "peers/"+a.Address().String()+"/revoked-certs.json")
	if !ok {
		t.Fatal("b keeps no revocation of a's certificates")
	}
	var rec protocol.Revocations
	if err := protocol.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	other, err := protocol.NewRevokedCertificates(a.Address(), 1)
	if err != nil {
		t.Fatal(err)
	}
	rec.RevokedCertificates = other.Statement() // under the signature of another
	tampered, err := json.Marshal(rec)
	if err != nil {
		t.Fatal(err)
	}
	b.SetRecord(t, "peers/"+a.Address().String()+"/revoked-certs.json", tampered)
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == mailboxPath(a) {
			e.serve(w, r, next, func(br *protocol.MailboxResponse) { br.RevokedCertificates, br.RevokedCertificatesSignature = nil, nil })
			return
		}
		next.ServeHTTP(w, r)
	})
	own, _ := a.Record(t, "revoked-certs.json")
	a.SetRecord(t, "revoked-certs.json", tampered)
	published := numberOf(t, a)
	e.clock.Add(2 * time.Second)
	if _, err := a.Rekey(ctx); err == nil || !strings.Contains(err.Error(), "no longer verifies") || numberOf(t, a) != published {
		t.Errorf("a renewal past a kept revocation of the mailbox's own certificates that does not verify: %v, published %d of %d", err, numberOf(t, a), published)
	}
	a.SetRecord(t, "revoked-certs.json", own)
	n := e.srv.Count(a.Address())
	if _, err := b.Send(ctx, a.Address(), "to a mailbox whose revocation b keeps broken"); err == nil || !strings.Contains(err.Error(), "no longer verifies") || e.srv.Count(a.Address()) != n {
		t.Errorf("a send past a kept revocation of the peer's certificates that does not verify: %v; the server holds %d for a, %d before", err, e.srv.Count(a.Address()), n)
	}
	send(t, a, b, "from a mailbox whose revocation b keeps broken")
	res, err := b.Receive(ctx)
	if err == nil || !strings.Contains(err.Error(), "no longer verifies") || e.srv.Count(b.Address()) != 1 {
		t.Errorf("a drain past a kept revocation of the sender's certificates that does not verify: %v, delivered %d; the server holds %d", err, len(res.Delivered), e.srv.Count(b.Address()))
	}
}

// A send names its prekey's statement by the SHA-256 of its bytes as served
// (protocol.StatementHash), in its query, in either mode, and its body is the
// age file itself, as an octet stream. Another statement by the same signer
// is named apart.
func TestASendNamesItsStatement(t *testing.T) {
	t.Parallel()
	for _, working := range []bool{false, true} {
		e := newEnv(t)
		e.working = working
		a, b := e.mailbox(), e.mailbox()
		if _, err := b.Rekey(context.Background()); err != nil {
			t.Fatal(err)
		}
		var query, contentType string
		var body []byte
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodPost && r.URL.Path == "/v1/"+b.Address().String()+"/messages" {
				query, contentType = r.URL.RawQuery, r.Header.Get("Content-Type")
				body, _ = io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
			}
			next.ServeHTTP(w, r)
		})
		id := send(t, a, b, "names the prekey it was sealed to").ID
		st, _ := e.srv.Prekey(b.Address())
		if want := "statement=" + protocol.StatementHash(st); query != want {
			t.Errorf("working-key mode %v: a send's query: %q, want %q", working, query, want)
		}
		h := sha256.Sum256(body)
		if contentType != protocol.CiphertextContentType || !bytes.HasPrefix(body, []byte("age-encryption.org/v1\n")) || hex.EncodeToString(h[:]) != id {
			t.Errorf("a send's body, %s: %q…, not the ciphertext the receipt names", contentType, body[:min(len(body), 40)])
		}
		// Another statement, five above, by the same signer: the send names it
		// as served, and the server, which holds the other, answers
		// stale_prekey.
		p, err := protocol.ParsePrekey(st)
		if err != nil {
			t.Fatal(err)
		}
		p.Serial += 5
		sig, err := protocol.Sign(worker(t, b), p.Statement(), protocol.PrekeyNamespace(b.Address()))
		if err != nil {
			t.Fatal(err)
		}
		query = ""
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == mailboxPath(b):
				fakeserver.WriteJSON(w, http.StatusOK, protocol.MailboxResponse{Identity: b.Identity().Document(), Prekey: p.Statement(), PrekeySignature: sig})
				return
			case r.Method == http.MethodPost && r.URL.Path == mailboxPath(b)+"/messages" && query == "":
				query = r.URL.RawQuery
			}
			next.ServeHTTP(w, r)
		})
		_, err = a.Send(context.Background(), b.Address(), "sealed to a statement five above")
		if want := "statement=" + protocol.StatementHash(p.Statement()); query != want || client.Code(err) != protocol.CodeStalePrekey {
			t.Errorf("working-key mode %v: a send to a statement five above: %q, %v; want %q and stale_prekey", working, query, err, want)
		}
	}
}
