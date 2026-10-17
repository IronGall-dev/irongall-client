package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// A working key can be taken without the identity, so an identity can revoke
// the certificates it made and keep its address. These tests play a box
// whose working key was taken, and an operator that helps the thief.

func keptList(b *client.Box, of protocol.Address) bool {
	return exists(filepath.Join(b.Dir(), "peers", of.String(), "revoked-certs.json"))
}

// mailAs injects mail that signer signed as box from, to box to, as an
// operator delivering what a thief made.
func mailAs(t *testing.T, e *env, from, to *client.Box, signer ssh.Signer, body string) {
	t.Helper()
	line := e.line(from.Identity().Document(), from.Address(), to.Address(), body)
	e.seal(to, from.Address(), line, sign(t, signer, line, to.Address()))
}

// A box renews under a new certificate and revokes every one before it. Mail
// under the old certificate is refused when it is read, the box's own
// included, and whatever a thief signs with the old key afterwards. The
// address goes on: the box writes and is written to.
func TestRevokeEarlierEndsWhatAnOldWorkingKeySigns(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	stolen := worker(t, a) // read before the renewal deletes it
	first := numberOf(t, a)
	send(t, a, b, "sent under the first certificate, and unread")
	if _, err := a.Rekey(ctx, ""); err != nil {
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
		t.Fatalf("a drain of mail under a revoked certificate and under the current one: %+v", res)
	}
	if !keptList(b, a.Address()) || keptRevocation(b, a.Address()) {
		t.Fatal("the revocation of certificates was not kept, or the address was taken as revoked")
	}

	// The operator now hides the revocation and delivers what the thief
	// signs.
	says(e, protocol.CodeNotRevoked, http.MethodGet, "/revocations")
	mailAs(t, e, a, b, stolen, "signed by the key that was taken")
	if res := receive(t, b); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a thief's mail under the revoked certificate, the revocation hidden: %+v", res)
	}
	e.srv.SetMiddle(nil)

	// The address goes on, both ways.
	send(t, b, a, "to the box that revoked its old certificates")
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("the box no longer receives: %+v", res)
	}

	// A second time, after another renewal: through a higher serial,
	// everything before the certificate in use.
	if _, err := a.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if certs, err := a.RevokeEarlier(ctx); err != nil || certs.Through != numberOf(t, a)-1 || !certs.Revokes(second) {
		t.Fatalf("the second revocation: %+v, %v", certs, err)
	}
}

// A revocation of certificates is the identity's to sign, and the highest one
// a reader has verified stands: what a server shows that a working key
// signed, or that is a lower one of the identity's own, changes nothing.
func TestOnlyTheIdentitysHighestRevocationCounts(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	doc := a.Identity().Document()
	show := func(rec protocol.Revocations) {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/v1/"+a.Address().String()+"/revocations") {
				fakeserver.WriteJSON(w, http.StatusOK, rec)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	// What a working key can sign: a revocation of the box's own
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
	if res := receive(t, b); len(res.Delivered) != 1 || keptList(b, a.Address()) {
		t.Fatalf("a revocation a working key signed was applied or kept: %+v", res)
	}
	e.srv.SetMiddle(nil)

	// The identity's first revocation covers certificate 1; its second, 1
	// and 2.
	if _, err := a.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeEarlier(ctx); err != nil {
		t.Fatal(err)
	}
	var firstList protocol.Revocations
	resp, err := http.Get(e.srv.URL + "/v1/" + a.Address().String() + "/revocations")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.NewDecoder(resp.Body).Decode(&firstList); err != nil || len(firstList.RevokedCertificates) == 0 || len(firstList.Revocation) != 0 {
		t.Fatalf("the record of a box with its certificates revoked and its address not: %+v, %v", firstList, err)
	}
	_ = resp.Body.Close()
	second := workerAt(t, a, numberOf(t, a)) // read before the next renewal deletes it
	if _, err := a.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeEarlier(ctx); err != nil {
		t.Fatal(err)
	}
	mailAs(t, e, a, b, second, "under certificate 2, which the second revocation covers")
	if res := receive(t, b); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("mail under a revoked certificate: %+v", res)
	}

	// A server serves the first revocation again, which did not cover
	// certificate 2. B holds the second, and a lower one never replaces a
	// higher one: what was revoked stays revoked.
	show(firstList)
	mailAs(t, e, a, b, second, "under certificate 2, with the lower revocation shown again")
	if res := receive(t, b); len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != client.RefusedCertificate {
		t.Fatalf("a lower revocation replaced the higher one: %+v", res)
	}
	// And with nothing shown at all, the kept revocation still stands.
	show(protocol.Revocations{Identity: doc})
	mailAs(t, e, a, b, second, "under certificate 2, with no revocation shown")
	if res := receive(t, b); len(res.Delivered) != 0 || len(res.Refused) != 1 {
		t.Fatalf("the kept revocation did not hold once the server stopped showing it: %+v", res)
	}
}

// A box's statements are ordered by certificate first. So whoever took a
// working key can publish a prekey at the highest serial there is and hold
// nothing: the box's next certificate passes it, at the server and at every
// sender that had pinned the thief's.
func TestALaterCertificateOutranksAnyPrekeySerial(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
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
	got, err := a.Rekey(ctx, "")
	if err != nil || got.Serial <= first || got.Serial >= protocol.MaxSerial {
		t.Fatalf("a renewal after a prekey at the last serial: %+v, %v", got, err)
	}
	// B follows the box to the later certificate, and mail reaches A again.
	send(t, b, a, "to the box that took its address back")
	if res := receive(t, a); len(res.Delivered) != 1 {
		t.Fatalf("mail after the renewal: %+v", res)
	}
	// And never back: the thief's statement, served again, is a rollback.
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.URL.Path == "/v1/"+a.Address().String()+"/identity" {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: a.Identity().Document(), Prekey: p.Statement(), PrekeySignature: sig})
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := b.Send(ctx, a.Address(), "to the thief's prekey"); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("under certificate %d, below %d", first, got.Serial)) {
		t.Fatalf("the earlier certificate served again: %v", err)
	}
}

// A send names its prekey by both serials, its own and its certificate's.
func TestASendNamesBothSerials(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	if _, err := b.Rekey(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	sent := capture(e, http.MethodPost, "/v1/"+b.Address().String()+"/messages")
	send(t, a, b, "names the prekey it was sealed to")
	var req map[string]json.RawMessage
	if err := json.Unmarshal(*sent, &req); err != nil {
		t.Fatal(err)
	}
	if n := strconv.FormatUint(numberOf(t, b), 10); string(req["prekey_serial"]) != n || string(req["certificate_serial"]) != n || len(req) != 3 {
		t.Fatalf("a send's members: %s", *sent)
	}
}
