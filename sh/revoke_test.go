package sh_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// Revocation in the script: of an address and of its certificates, what a
// sender asks before it posts, and a mailbox's own revocations.

// top is the highest serial there is, 2^53 - 1.
const top = 9007199254740991

// revocation is mailbox b's revocation record, made with ssh-keygen as the Go
// client's revocation make makes one: the script makes none. Its signature is
// left in $W/<name>.rev.sig.
func (b *shMailbox) revocation(name string) []byte {
	b.w.t.Helper()
	return []byte(b.must(`a=$(cat "$DR/address"); printf 'dromas-revoke-v1\n%s\n' "$a" | ssh-keygen -q -Y sign -n "dromas-revoke-v1:$a" -f "$DR/identity" > "$W/` + name + `.rev.sig" &&
jq -cn --arg i "$(dr_b64 "$DR/identity.doc")" --arg s "$(dr_b64 "$W/` + name + `.rev.sig")" '{type:"revocation_record", identity:$i, revocation_signature:$s}'`))
}

// revoke publishes b's revocation at its server, as the Go client's
// revocation publish does, and keeps it in the mailbox as that command keeps it.
func (b *shMailbox) revoke() {
	b.w.t.Helper()
	rec := filepath.Join(b.w.work, "own.rev.json")
	writeFile(b.w.t, rec, b.revocation("own"))
	b.must(`dr_api PUT "/v1/$(cat "$DR/address")/revocations" ` + rec + ` > /dev/null && cp "$W/own.rev.sig" "$DR/revoked.sig"`)
}

// certs is a revocation of b's certificates through serial, signed with the
// key file signer, and its record, made with ssh-keygen: the script applies
// one and makes none. The statement and signature are $W/<name>.certs and
// .sig, the record $W/<name>.json.
func (b *shMailbox) certs(name string, serial uint64, signer string) string {
	b.w.t.Helper()
	b.must(fmt.Sprintf(`a=$(cat "$DR/address"); printf 'dromas-revoke-certs-v1\n%%s\n%%s\n' "$a" %d > "$W/%[2]s.certs"; ssh-keygen -q -Y sign -n "dromas-revoke-certs-v1:$a" -f %[3]s < "$W/%[2]s.certs" > "$W/%[2]s.sig"
jq -cn --arg i "$(dr_b64 "$DR/identity.doc")" --arg l "$(dr_b64 "$W/%[2]s.certs")" --arg g "$(dr_b64 "$W/%[2]s.sig")" '{identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$W/%[2]s.json"`, serial, name, signer))
	return filepath.Join(b.w.work, name+".json")
}

// saysRevoked answers every read of mailbox b 410 revoked, carrying record, or
// none if it is nil: an operator's word, whatever it shows.
func (w *world) saysRevoked(b *shMailbox, record *protocol.Revocations) {
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == b.addr {
			forge.Refuse(rw, protocol.CodeRevoked, func(p *protocol.Problem) { p.Record = record })
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// showing answers every read of mailbox b as the server does, with the members
// of a JSON object put over it: whatever an operator shows.
func (w *world) showing(b *shMailbox, members []byte) {
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); !ok || x != b.addr {
			next.ServeHTTP(rw, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		var mailbox, over map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &mailbox) != nil || json.Unmarshal(members, &over) != nil {
			w.t.Fatalf("an operator shows members over a mailbox, and the server answered %d", rec.Code)
		}
		maps.Copy(mailbox, over)
		fakeserver.WriteJSON(rw, http.StatusOK, mailbox)
	})
}

// failing answers every read of mailbox b with code: no answer about it.
func (w *world) failing(b *shMailbox, code protocol.Code) {
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == b.addr {
			forge.Refuse(rw, code)
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// record reads a JSON record a test made.
func record(t *testing.T, name string) *protocol.Revocations {
	t.Helper()
	var r protocol.Revocations
	if err := protocol.Unmarshal(mustRead(t, name), &r); err != nil {
		t.Fatal(err)
	}
	return &r
}

// A revocation is the identity's own signature over its fixed statement: a
// server's word, or what it shows that is not one, revokes nothing; a real
// one ends the mailbox, is kept, and holds against a server that hides it; no
// answer about a sender is not "not revoked".
func TestScriptTakesARevocationOnItsProofAlone(t *testing.T) {
	w := newWorld(t)
	ra, rb, rc, rd := w.mailbox(), w.mailbox(), w.mailbox(), w.mailbox()
	va := strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "a", "address")))
	vdoc := abs(t, filepath.Join(vectors, "a", "identity.doc"))
	sigs := []string{"a/revoke.sig", "a/revoke.sha256.sig"}
	if p256() {
		if r := ra.sh(fmt.Sprintf("dr_revcheck %s %s %s", strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "c", "address"))), abs(t, filepath.Join(vectors, "c", "identity.doc")), abs(t, filepath.Join(vectors, "c", "revoke.sig")))); r.rc != 0 {
			t.Errorf("c/revoke.sig, by a P-256 identity, is not taken: %v", r)
		}
	} else {
		t.Log("this ssh-keygen reads no P-256 key (OpenSSH built without OpenSSL), so c/revoke.sig is not tried: a known variance (PROTOCOL.md Appendix A)")
	}
	for _, v := range sigs {
		if r := ra.sh(fmt.Sprintf("dr_revcheck %s %s %s", va, vdoc, abs(t, filepath.Join(vectors, v)))); r.rc != 0 {
			t.Errorf("vector %s is not taken as A's revocation: %v", v, r)
		}
	}
	bad, _ := filepath.Glob(filepath.Join(vectors, "revoke", "bad-*.sig"))
	if len(bad) == 0 {
		t.Fatal("no revoke/bad-*.sig vectors")
	}
	vb := strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "b", "address")))
	for _, v := range append(bad, "b") {
		cmd := fmt.Sprintf("dr_revcheck %s %s %s", va, vdoc, abs(t, v))
		if v == "b" { // A's revocation for another mailbox, and under another identity
			cmd = fmt.Sprintf("dr_revcheck %s %s %[3]s || dr_revcheck %[4]s %[5]s %[3]s", vb, vdoc, abs(t, filepath.Join(vectors, sigs[0])), va, abs(t, filepath.Join(vectors, "b", "identity.doc")))
		}
		if r := ra.sh(cmd); r.rc == 0 {
			t.Errorf("%s is taken as a revocation: %v", v, r)
		}
	}
	rbRec := filepath.Join(w.work, "rb.json")
	writeFile(t, rbRec, rb.revocation("rb"))
	untyped := filepath.Join(w.work, "rb-untyped.json")
	rb.must(`jq -c 'del(.type)' ` + rbRec + ` > ` + untyped)
	if out := rb.must("dr_record " + rbRec + "; dr_record " + untyped); out != strings.Repeat(rb.addr.String()+"\n", 2) {
		t.Errorf("a record, and one that names no type: %q", out)
	}
	// A working key's signature over the same statement, under a certificate
	// RB's identity made: good under its certificate, and no revocation. (That
	// the server refuses it is dromas-server's to test.)
	wk := filepath.Join(w.work, "wk.json")
	rb.must(fmt.Sprintf(`printf 'dromas-revoke-v1\n%%s\n' %[1]s | ssh-keygen -q -Y sign -n dromas-revoke-v1:%[1]s -f %[2]s > "$W/wk.sig"
dr_signed %[1]s "$DR/identity.doc" dromas-revoke-v1:%[1]s "$W/wk.sig" <(printf 'dromas-revoke-v1\n%%s\n' %[1]s) > /dev/null
jq -cn --arg i "$(dr_b64 "$DR/identity.doc")" --arg s "$(dr_b64 "$W/wk.sig")" '{identity:$i, revocation_signature:$s}' > %[3]s`, rb.addr, w.certify(rb, rb.num()+1), wk))
	if r := rb.sh("dr_record " + wk); r.rc == 0 {
		t.Errorf("a working key's signature is read as a record: %v", r)
	}
	// The operator says RB is revoked, and shows nothing, or what is not its
	// revocation: a working key's signature, another mailbox's revocation, and
	// another mailbox's signature with this mailbox's document.
	rcRec := filepath.Join(w.work, "rc.json")
	writeFile(t, rcRec, rc.revocation("rc"))
	mixed := filepath.Join(w.work, "mixed.json")
	rb.must(`jq -c --slurpfile b ` + rbRec + ` '.identity = $b[0].identity' ` + rcRec + ` > ` + mixed)
	wordOnly := func(what string) {
		t.Helper()
		if r := ra.send(rb.addr.String(), "to a mailbox the server calls revoked"); r.rc == 0 || !strings.Contains(r.err, "showed no revocation that verifies") || ra.has("peers/"+rb.addr.String()+"/revoke.sig") || !ra.bare() {
			t.Errorf("%s: %v", what, r)
		}
	}
	w.saysRevoked(rb, nil)
	wordOnly("a server's word, with nothing to show")
	for _, shown := range []string{wk, rcRec, mixed} {
		w.saysRevoked(rb, record(t, shown))
		wordOnly("a server's word, showing " + filepath.Base(shown))
	}
	w.honest()
	ra.mustSend(rb, "to a mailbox the server calls revoked")
	if d := rb.recv(); len(d.messages) != 1 {
		t.Errorf("the same send once the server lets it: %v", d)
	}
	// A real revocation: the mailbox learns it from the proof, and the messages
	// waiting for it go; a second changes nothing.
	rd.mustSend(ra, "one")
	rd.mustSend(ra, "two")
	ra.mustSend(rd, "waiting in the mailbox that is revoked")
	rd.revoke()
	if d := rd.recv(); d.rc == 0 || !strings.Contains(d.said, "REVOKED: this mailbox's own address is revoked") {
		t.Errorf("a revoked mailbox's recv: %v", d)
	}
	if r := rd.send(ra.addr.String(), "from a revoked mailbox"); r.rc == 0 || !strings.Contains(r.err, "REVOKED") || !rd.bare() {
		t.Errorf("a revoked mailbox's send: %v", r)
	}
	n := len(w.srv.Requests())
	reads := func(a protocol.Address, since int) int {
		return len(slices.DeleteFunc(w.calls(since), func(c string) bool { return c != "GET /v1/"+a.String() }))
	}
	if d := ra.recv(); len(d.messages) != 0 || d.refused("revoked") != 2 || reads(rd.addr, n) != 1 || !ra.has("peers/"+rd.addr.String()+"/revoke.sig") || w.srv.Count(ra.addr) != 0 {
		t.Errorf("messages from a mailbox revoked since: %v, %d reads of it", d, reads(rd.addr, n))
	}
	// The operator then hides the revocation, and delivers a message that
	// sender's identity signed, which still verifies.
	late := rd.line(ra.addr, "00000000-0000-4000-8000-00000000d001", "signed with a key that still verifies", 0)
	w.inject(ra, "", late, rd.sign(ra.addr, late))
	forge.Hides(t, w.srv)
	if d := ra.recv(); len(d.messages) != 0 || d.refused("revoked") != 1 {
		t.Errorf("a kept revocation against a server that hides it: %v", d)
	}
	n = len(w.srv.Requests())
	if r := ra.send(rd.addr.String(), "to a revoked mailbox"); r.rc == 0 || !strings.Contains(r.err, "REVOKED: "+rd.addr.String()+" is revoked") || len(w.srv.Requests()) != n || !ra.bare() {
		t.Errorf("a send to a mailbox this mailbox holds a revocation of: %v, %q", r, w.calls(n))
	}
	// No answer about a sender, or a 2xx that is no mailbox this script reads,
	// stops the drain with the message on the server; the next drain asks
	// again.
	rb.mustSend(rc, "waits for an answer")
	stopped := func(what string) {
		t.Helper()
		if d := rc.recv(); d.rc == 0 || len(d.messages) != 0 || w.srv.Count(rc.addr) != 1 || len(rc.files("refused")) != 0 {
			t.Errorf("%s: %v", what, d)
		}
	}
	w.failing(rb, protocol.CodeUnavailable)
	stopped("no answer about the sender")
	for _, v := range []string{"mailbox-bad-prekey-a-number.json", "mailbox-bad-revoked-certificates-a-number.json"} {
		w.showing(rb, mustRead(t, filepath.Join(vectors, "answer", v)))
		stopped(v + " over the mailbox served")
	}
	w.honest()
	if d := rc.recv(); d.rc != 0 || len(d.messages) != 1 {
		t.Errorf("the drain once the server answers: %v", d)
	}
}

// keptCerts is the revocation of certificates a mailbox keeps of address a, as
// its statement.
func (b *shMailbox) keptCerts(a protocol.Address) string {
	return b.must(`jq -r .revoked_certificates "$DR/peers/` + a.String() + `/revoked-certs.json" | base64 -d`)
}

// A revocation of certificates is the identity's own signature over exact
// text; a kept one revokes every rank through its own, the identity's 0
// among them, and one that no longer verifies is a fault.
func TestScriptReadsARevocationOfCertificates(t *testing.T) {
	w := newWorld(t)
	p := w.mailbox()
	va := strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "a", "address")))
	vec := func(n string) string { return abs(t, filepath.Join(vectors, n)) }
	ok4, okTop := vec("revoked/ok-through-4"), vec("revoked/ok-through-the-highest")
	if out := p.must(fmt.Sprintf("dr_certscheck %[1]s %[2]s %[3]s.txt %[3]s.sig; dr_certscheck %[1]s %[2]s %[3]s.txt %[3]s.sha256.sig; dr_certscheck %[1]s %[2]s %[4]s.txt %[4]s.sig", va, vec("a/identity.doc"), ok4, okTop)); out != "4\n4\n9007199254740991\n" {
		t.Errorf("the vectors that are a revocation of certificates: %q", out)
	}
	bad, _ := filepath.Glob(filepath.Join(vectors, "revoked", "bad-*.txt"))
	for _, v := range bad {
		if r := p.sh(fmt.Sprintf("dr_certscheck %s %s %s %s", va, vec("a/identity.doc"), abs(t, v), abs(t, strings.TrimSuffix(v, ".txt")+".sig"))); r.rc == 0 {
			t.Errorf("%s is taken as a revocation of A's certificates", filepath.Base(v))
		}
	}
	vb := strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "b", "address")))
	if r := p.sh(fmt.Sprintf("dr_certscheck %[1]s %[2]s %[3]s.txt %[3]s.sig || dr_certscheck %[4]s %[2]s %[3]s.txt %[3]s.sig", vb, vec("b/identity.doc"), ok4, va)); r.rc == 0 {
		t.Error("A's revocation of certificates is taken for another mailbox, or under another identity")
	}
	out := p.must(fmt.Sprintf(`d="$DR/peers/%[1]s"; mkdir -p "$d"; cp %[2]s "$d/identity.doc"
rec(){ jq -cn --arg i "$(dr_b64 %[2]s)" --arg l "$(dr_b64 "$1")" --arg g "$(dr_b64 "$2")" '{identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$d/revoked-certs.json"; }
rec %[3]s.txt %[3]s.sig; for n in 0 1 3 4 5 9007199254740991; do dr_mode %[1]s $n; echo -n "$? "; done
rec %[4]s.txt %[4]s.sig; dr_mode %[1]s 9007199254740991; echo -n "$? "
rec %[3]s.txt %[4]s.sig; dr_mode %[1]s 2; echo -n "$? "
echo '{}' > "$d/revoked-certs.json"; dr_mode %[1]s 2; echo "$?"`, va, vec("a/identity.doc"), ok4, okTop))
	if out != "1 1 1 1 0 0 1 3 3\n" {
		t.Errorf("a kept revocation through 4, through the highest, under another's signature, and one that holds none: %q", out)
	}
}

// hashQuery is the query a send names statement s by: its SHA-256, in
// lowercase hex (PROTOCOL.md §11.10).
func hashQuery(s stmt) string {
	h := sha256.Sum256(s.st)
	return "statement=" + hex.EncodeToString(h[:])
}

// lastQuery is the query of the last post to mailbox to the server was sent.
func (w *world) lastQuery(to *shMailbox) string {
	rs := w.srv.Requests()
	for i := len(rs) - 1; i >= 0; i-- {
		if rs[i].Method == http.MethodPost && rs[i].Path == "/v1/"+to.addr.String()+"/messages" {
			return rs[i].Query
		}
	}
	return ""
}

// Certificates revoked, as the script's mailboxes meet them at a peer in
// working-key mode, a Go mailbox made by init --offline: its working key
// taken, a prekey published with it at the highest serial there is under its
// certificate, the peer's next certificate passing it, and its identity's
// revocation ending what the taken key can still sign. The script's own
// mailbox is in identity mode, so it is the sender and the reader here.
func TestScriptAfterAWorkingKeyIsTaken(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	ca, cc := w.mailbox(), w.mailbox()
	g, cb := w.goMailbox(true)
	op := w.operator()
	if _, err := g.Send(ctx, cc.addr, "signed under the first certificate, and read after it was revoked"); err != nil {
		t.Fatal(err)
	}
	n1, first := numberOf(t, g), w.prekey(cb)
	ca.mustSend(cb, "before the theft")
	if q := w.lastQuery(cb); q != hashQuery(first) {
		t.Errorf("a send does not name its statement by its hash: %q", q)
	}
	// CB's working key is taken. With it the thief signs a pass, and
	// publishes a prekey of the operator's under CB's certificate, at the
	// highest serial there is.
	taken := filepath.Join(w.work, "taken")
	writeFile(t, taken, []byte(cb.read(fmt.Sprintf("work/%d", n1))))
	writeFile(t, taken+"-cert.pub", []byte(cb.read(fmt.Sprintf("work/%d-cert.pub", n1))))
	thiefs := w.statement(cb, top, op.recipient(), notAfter(), taken+"-cert.pub")
	body, _ := json.Marshal(protocol.PrekeyRequest{Prekey: thiefs.st, PrekeySignature: thiefs.sig})
	writeFile(t, filepath.Join(w.work, "top.json"), body)
	ca.must(fmt.Sprintf(`A=%s; na=$(jq -nr --argjson t "$(dr_now)" '$t + 600 | todate')
printf 'dromas-pass-v1\n%%s\n%%s\n%%s\n' "$A" "$(dr_server "$SRV")" "$na" | ssh-keygen -q -Y sign -n "dromas-pass-v1:$A" -f %s > "$W/thief.sig" &&
dr_api PUT "/v1/$A/prekey" "$W/top.json" -H "Authorization: dromas-pass address=\"$A\", not_after=\"$na\", signature=\"$(dr_b64 "$W/thief.sig")\"" > /dev/null`, cb.addr, taken+"-cert.pub"))
	if p, c := w.served(cb); p != top || c != n1 {
		t.Fatalf("the thief's prekey was not taken: %d under %d", p, c)
	}
	ca.mustSend(cb, "encrypted to the thief")
	peer := "peers/" + cb.addr.String() + "/"
	if ca.read(peer+"serial") != fmt.Sprintln(top) || ca.read(peer+"rank") != fmt.Sprintln(n1) || w.lastQuery(cb) != hashQuery(thiefs) {
		t.Fatalf("CA's send to the thief's prekey: %q", w.lastQuery(cb))
	}
	w.serving(cb, first)
	if r := ca.send(cb.addr.String(), "x"); r.rc == 0 || !strings.Contains(r.err, fmt.Sprintf("prekey serial %d is below one already seen", n1)) {
		t.Errorf("an earlier statement by one signer: %v", r)
	}
	w.honest()
	// The owner renews: the next certificate passes the thief's statement, and
	// senders follow.
	if _, err := g.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	n2 := numberOf(t, g)
	if p, c := w.served(cb); n2 <= n1 || n2 >= top || p != n2 || c != n2 {
		t.Errorf("a renewal past the top serial: %d, served %d under %d", n2, p, c)
	}
	ca.mustSend(cb, "after the renewal")
	if ca.read(peer+"serial") != fmt.Sprintln(n2) || ca.read(peer+"rank") != fmt.Sprintln(n2) || w.lastQuery(cb) != hashQuery(w.prekey(cb)) {
		t.Errorf("CA's send after the renewal: %q", w.lastQuery(cb))
	}
	res, err := g.Receive(ctx)
	var bodies []string
	for _, d := range res.Delivered {
		bodies = append(bodies, string(d.Envelope.Body))
	}
	if slices.Sort(bodies); err != nil || !slices.Equal(bodies, []string{`"after the renewal"`, `"before the theft"`}) || len(res.Refused) != 1 || res.Refused[0].Code != "undecryptable" {
		t.Errorf("what CB reads after its renewal: %q, %+v, %v", bodies, res.Refused, err)
	}
	thief := func(to *shMailbox, msgID, body string) {
		l := envelope(t, cb.addr, to.addr, []byte(cb.read("identity.doc")), msgID, body, 0)
		w.inject(to, "", l, w.signWith(taken+"-cert.pub", to.addr, l))
	}
	thief(ca, "00000000-0000-4000-8000-00000000c001", "signed by the thief, before the revocation")
	if d := ca.recv(); !slices.Equal(d.bodies(), []string{"signed by the thief, before the revocation"}) {
		t.Errorf("control: a message the taken key signs, while nothing revokes it but the trip below it: %v", d)
	}
	// A revocation the working key signs is none; the identity's, through
	// every certificate before the new one, is published with no pass. (What
	// the server takes of either is dromas-server's to test.)
	cb.certs("CBw", n1, cb.file(fmt.Sprintf("work/%d-cert.pub", n2)))
	ca.must(fmt.Sprintf(`dr_signed %s %s dromas-revoke-certs-v1:%[1]s "$W/CBw.sig" "$W/CBw.certs" > /dev/null`, cb.addr, cb.file("identity.doc")))
	if r := ca.sh(fmt.Sprintf(`dr_certscheck %s %s "$W/CBw.certs" "$W/CBw.sig"`, cb.addr, cb.file("identity.doc"))); r.rc == 0 {
		t.Errorf("a revocation of certificates the working key signed is taken: %v", r)
	}
	certs, err := g.RevokeEarlier(ctx)
	if err != nil || !certs.Revokes(n1) || certs.Revokes(n2) {
		t.Fatalf("RevokeEarlier: %+v %v", certs, err)
	}
	// A message the thief signs now, and one under the mailbox's new certificate.
	thief(ca, "00000000-0000-4000-8000-00000000c002", "signed by the thief, after the revocation")
	if _, err := g.Send(ctx, ca.addr, "under the new certificate"); err != nil {
		t.Fatal(err)
	}
	n := len(w.srv.Requests())
	reads := func() int {
		return len(slices.DeleteFunc(w.calls(n), func(c string) bool { return c != "GET /v1/"+cb.addr.String() }))
	}
	if d := ca.recv(); !slices.Equal(d.bodies(), []string{"under the new certificate"}) || d.refused("certificate_revoked") != 1 || reads() != 1 ||
		ca.keptCerts(cb.addr) != string(certs.Statement()) || strings.Count(ca.read(peer+"revoked-certs.json"), "\n") != 1 || ca.has(peer+"revoke.sig") {
		t.Errorf("after the revocation: %v, %d reads", d, reads())
	}
	thief(ca, "00000000-0000-4000-8000-00000000c003", "signed by the thief, the revocation hidden")
	forge.Hides(t, w.srv)
	if d := ca.recv(); len(d.messages) != 0 || d.refused("certificate_revoked") != 1 {
		t.Errorf("a kept revocation of certificates against a server that hides it: %v", d)
	}
	w.honest()
	if d := cc.recv(); len(d.messages) != 0 || d.refused("certificate_revoked") != 1 {
		t.Errorf("the mailbox's unread message under that certificate: %v", d)
	}
	// CC never saw a later statement of CB's, and holds the revocation: a
	// server that serves the thief's prekey gets nothing encrypted to it.
	w.serving(cb, thiefs)
	if r := cc.send(cb.addr.String(), "not to a prekey under a revoked certificate"); r.rc == 0 || !strings.Contains(r.err, "signed under a certificate its identity has revoked") || cc.has(peer+"serial") || !cc.bare() {
		t.Errorf("a prekey statement under a revoked certificate: %v", r)
	}
	w.honest()
	cc.mustSend(cb, "not to a prekey under a revoked certificate")
	if cc.read(peer+"rank") != fmt.Sprintln(n2) {
		t.Errorf("the send, the server honest, went under %q", cc.read(peer+"rank"))
	}
	// A lower revocation never replaces a higher one, whatever a server
	// shows; a kept one that no longer verifies is a fault of the mailbox.
	if _, err := g.Send(ctx, ca.addr, "another, for a second lookup"); err != nil {
		t.Fatal(err)
	}
	w.showing(cb, mustRead(t, cb.certs("CB1", n1-1, cb.file("identity"))))
	if d := ca.recv(); len(d.messages) != 1 || ca.keptCerts(cb.addr) != string(certs.Statement()) {
		t.Errorf("a lower revocation replaced a higher one: %v", d)
	}
	w.honest()
	if _, err := g.Send(ctx, ca.addr, "held while the kept revocation is broken"); err != nil {
		t.Fatal(err)
	}
	kept := ca.read(peer + "revoked-certs.json")
	ca.must(fmt.Sprintf(`jq -cn --arg i "$(dr_b64 "$DR/%sidentity.doc")" --arg l "$(dr_b64 "$W/CB1.certs")" --arg g "$(dr_b64 "$W/CBw.sig")" '{identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$DR/%[1]srevoked-certs.json"`, peer))
	q := len(ca.files("refused"))
	if d := ca.recv(); d.rc == 0 || len(d.messages) != 0 || w.srv.Count(ca.addr) != 1 || len(ca.files("refused")) != q || !strings.Contains(d.said, "does not verify") {
		t.Errorf("a kept revocation swapped for one that does not verify: %v", d)
	}
	writeFile(t, ca.file(peer+"revoked-certs.json"), []byte(kept))
	if d := ca.recv(); d.rc != 0 || len(d.messages) != 1 {
		t.Errorf("after the kept revocation was put back: %v", d)
	}
}

// A script mailbox shown a trip it did not make, a revocation of its
// certificates its identity signed, holds its identity to be in another's
// hands: it says so, recommends revoking the address, and signs nothing more
// (PROTOCOL.md §12.5). A reader and a sender that hold the trip refuse what
// its identity signed, whenever it was signed; and the identity alone,
// restored, has published nothing and takes the trip as its mode, which the
// script does not sign in.
func TestScriptStopsAtATripItDidNotMake(t *testing.T) {
	w := newWorld(t)
	ca, cd := w.mailbox(), w.mailbox()
	cd.mustSend(ca, "signed by CD's identity before the trip")
	w.publish(cd.addr, cd.certs("CD-trip", uint64(time.Now().Unix())-1, cd.file("identity")))
	if cd.has("revoked-certs.json") {
		t.Fatal("the mailbox holds the trip published by hand")
	}
	const foreign = "this mailbox holds a revocation of its own certificates that its identity signed and this mailbox did not make, so its identity is in other hands"
	// Its drain is refused its pass, by the identity, as certificate_revoked:
	// it reads itself, keeps the trip, and stops.
	if d := cd.recv(); d.rc == 0 || !strings.Contains(d.said, foreign) || !strings.Contains(d.said, "Revoke the address") || !cd.has("revoked-certs.json") {
		t.Fatalf("a drain refused its pass for a trip: %v", d)
	}
	n := len(w.srv.Requests())
	for _, c := range []string{"dr_recv", "dr_rekey", "dr_pass", "printf x | dr_send " + ca.addr.String()} {
		if r := cd.sh(c); r.rc == 0 || !strings.Contains(r.err, foreign) {
			t.Errorf("%s once the trip is held: %v", c, r)
		}
	}
	if len(w.srv.Requests()) != n || !cd.bare() {
		t.Errorf("the mailbox called the server, or kept a send, once it held the trip: %q", w.calls(n))
	}
	// A reader shown the trip refuses what CD's identity signed, whenever it
	// was signed; a sender refuses CD's statement, which its identity signed.
	if d := ca.recv(); len(d.messages) != 0 || d.refused("certificate_revoked") != 1 || !strings.Contains(d.said, "signed by its sender's identity, and its sender's address is in working-key mode") {
		t.Errorf("a message CD's identity signed, read once the trip is held: %v", d)
	}
	if r := ca.send(cd.addr.String(), "x"); r.rc == 0 || !strings.Contains(r.err, "signed by its identity, and "+cd.addr.String()+" is in working-key mode") || !ca.bare() {
		t.Errorf("a send to CD once the trip is held: %v", r)
	}
	// The identity alone, restored: it takes the served trip as its mode.
	re := w.empty()
	if err := os.MkdirAll(re.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, re.file("identity"), []byte(cd.read("identity")))
	if r := re.sh("dr_rekey"); r.rc == 0 || !strings.Contains(r.err, "this script signs in identity mode only") || strings.Contains(r.err, foreign) || len(re.files("prekeys")) != 0 {
		t.Errorf("the identity alone, restored where the trip is served: %v", r)
	}
}

// A mailbox makes no statement above the highest serial there is (#69): not
// past an earlier attempt that took the highest and left nothing it can send,
// and not when what it published is the highest, its server holding no mailbox
// for it to read.
func TestScriptMakesNoStatementAboveTheHighest(t *testing.T) {
	w := newWorld(t)
	cf := w.mailbox()
	n := cf.num()
	above := func() bool { return cf.has(fmt.Sprintf("prekeys/%d.agekey", uint64(top)+1)) }
	writeFile(t, cf.file(fmt.Sprintf("prekeys/%d.txt.sig", uint64(top))), []byte("not a signature\n"))
	if r := cf.sh("dr_rekey"); r.rc == 0 || !strings.Contains(r.err, "prekey serial is the highest there is") || cf.num() != n || above() {
		t.Errorf("a renewal past an attempt at the highest serial: %v", r)
	}
	if err := os.Remove(cf.file(fmt.Sprintf("prekeys/%d.txt.sig", uint64(top)))); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cf.file("serial"), fmt.Appendln(nil, uint64(top)))
	w.failing(cf, protocol.CodeNoSuchMailbox)
	if r := cf.sh("dr_rekey"); r.rc == 0 || !strings.Contains(r.err, "prekey serial is the highest there is") || above() {
		t.Errorf("a renewal from the highest serial, published: %v", r)
	}
}

// A kept revocation of a peer's certificates that does not verify is a fault
// of the mailbox, where the server shows none to keep instead (#69): a send to
// the peer posts nothing, and a drain of its messages stops with the messages on the
// server.
func TestScriptStopsAtAKeptRevocationThatDoesNotVerify(t *testing.T) {
	w := newWorld(t)
	ca, cb := w.mailbox(), w.mailbox()
	ca.mustSend(cb, "pins CB")
	writeFile(t, ca.file("peers/"+cb.addr.String()+"/revoked-certs.json"), mustRead(t, cb.certs("CB-not-its-own", 1, ca.file("identity"))))
	n := w.posts(cb.addr)
	if r := ca.send(cb.addr.String(), "not past a revocation that does not verify"); r.rc == 0 || !strings.Contains(r.err, "does not verify") || w.posts(cb.addr) != n || !ca.bare() {
		t.Errorf("a send: %v", r)
	}
	cb.mustSend(ca, "waits past a revocation that does not verify")
	if d := ca.recv(); d.rc == 0 || len(d.messages) != 0 || w.srv.Count(ca.addr) != 1 || !strings.Contains(d.said, "does not verify") {
		t.Errorf("a drain: %v", d)
	}
}

// A sender reads its recipient's mailbox before every post, keeps what
// verifies, and seals to what it then holds; no answer is not "none held".
// The recipient is a Go mailbox in working-key mode, made by init --offline,
// whose identity revokes the certificate a thief holds a key under.
func TestScriptAsksBeforeItPosts(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	sa, sc, sd, se := w.mailbox(), w.mailbox(), w.mailbox(), w.mailbox()
	g, sb := w.goMailbox(true)
	read := func() []string {
		t.Helper()
		res, err := g.Receive(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var bodies []string
		for _, d := range res.Delivered {
			bodies = append(bodies, string(d.Envelope.Body))
		}
		slices.Sort(bodies)
		return bodies
	}
	n := len(w.srv.Requests())
	sa.mustSend(sb, "asked first")
	if c := w.calls(n); !slices.Equal(c, []string{"GET /v1/" + sb.addr.String(), "POST /v1/" + sb.addr.String() + "/messages"}) {
		t.Errorf("the calls of a send: %q", c)
	}
	for _, code := range []protocol.Code{protocol.CodeUnavailable, protocol.CodeTooLarge} {
		w.failing(sb, code)
		n = len(w.srv.Requests())
		if r := sa.send(sb.addr.String(), "waits for an answer"); r.rc == 0 || !strings.Contains(r.err, "could not be read") || !sa.bare() || !slices.Equal(w.calls(n), []string{"GET /v1/" + sb.addr.String()}) {
			t.Errorf("a read of the recipient answered %s: %v, %q", code, r, w.calls(n))
		}
	}
	w.honest()
	sa.mustSend(sb, "waits for an answer")
	if got := read(); !slices.Equal(got, []string{`"asked first"`, `"waits for an answer"`}) {
		t.Errorf("SB's messages: %q", got)
	}
	// SB's working key is taken. SB renews, and its identity revokes every
	// certificate before the new one. An operator that helps the thief goes
	// on serving the old statement, beside the trip alone.
	n1, old := numberOf(t, g), w.prekey(sb)
	var trip protocol.MailboxResponse
	if err := protocol.Unmarshal([]byte(sa.must(`dr_look `+sb.addr.String())), &trip); err != nil || trip.RevokedCertificates == nil {
		t.Fatalf("the trip SB's server holds: %v", err)
	}
	if _, err := g.Rekey(ctx); err != nil {
		t.Fatal(err)
	}
	certs, err := g.RevokeEarlier(ctx)
	if err != nil || !certs.Revokes(n1) {
		t.Fatalf("RevokeEarlier: %+v %v", certs, err)
	}
	peer := "peers/" + sb.addr.String() + "/"
	w.reading(sb.addr, func(br *protocol.MailboxResponse) {
		br.Prekey, br.PrekeySignature, br.RevokedCertificates, br.RevokedCertificatesSignature = old.st, old.sig, trip.RevokedCertificates, trip.RevokedCertificatesSignature
	})
	sc.send(sb.addr.String(), "sealed to the old prekey")
	if q := w.lastQuery(sb); q != hashQuery(old) || sc.read(peer+"rank") != fmt.Sprintln(n1) || sc.keptCerts(sb.addr) != string(trip.RevokedCertificates) {
		t.Errorf("control: a sender shown no revocation above the trip does not seal to the old prekey: %q", q)
	}
	// The same operator, the revocation not hidden: SE has never met SB.
	w.serving(sb, old)
	n = w.posts(sb.addr)
	if r := se.send(sb.addr.String(), "never sealed to the old prekey"); r.rc == 0 || !strings.Contains(r.err, "signed under a certificate its identity has revoked") || w.posts(sb.addr) != n ||
		se.keptCerts(sb.addr) != string(certs.Statement()) || se.has(peer+"serial") || !se.bare() {
		t.Errorf("a sender that asks before it sends: %v", r)
	}
	w.honest()
	se.mustSend(sb, "never sealed to the old prekey")
	if se.read(peer+"rank") != fmt.Sprintln(numberOf(t, g)) {
		t.Errorf("SE's send, the server honest, went under %q", se.read(peer+"rank"))
	}
	// What a mailbox was shown once holds after the server hides it.
	if out := sd.must(`dr_lookup ` + sb.addr.String() + `; echo $?`); out != "1\n" || sd.keptCerts(sb.addr) != string(certs.Statement()) {
		t.Errorf("SD's lookup: %q", out)
	}
	w.reading(sb.addr, func(br *protocol.MailboxResponse) {
		br.Prekey, br.PrekeySignature, br.RevokedCertificates, br.RevokedCertificatesSignature = old.st, old.sig, trip.RevokedCertificates, trip.RevokedCertificatesSignature
	})
	n = w.posts(sb.addr)
	if r := sd.send(sb.addr.String(), "never sealed either"); r.rc == 0 || !strings.Contains(r.err, "signed under a certificate its identity has revoked") || w.posts(sb.addr) != n {
		t.Errorf("after the server turned: %v", r)
	}
	w.honest()
	if got := read(); !slices.Equal(got, []string{`"never sealed to the old prekey"`}) {
		t.Errorf("SB's messages: %q", got)
	}
}

// A mailbox's own revocations: a clock far ahead deletes no key that a
// message waits for; a mailbox that holds its own revocation of its address
// signs nothing more.
func TestScriptUnderItsOwnRevocations(t *testing.T) {
	w := newWorld(t)
	s1, s2, s3, s4 := w.mailbox(), w.mailbox(), w.mailbox(), w.mailbox()
	s1.mustSend(s4, "sealed to a prekey about to retire")
	time.Sleep(time.Second)
	s4.must("dr_rekey")
	keys := func() int { k, _ := filepath.Glob(s4.file("prekeys/*.agekey")); return len(k) }
	k0 := keys()
	if d := (at{s4, 70 * 24 * time.Hour}).recv(); d.rc == 0 || keys() != k0 {
		t.Errorf("a drain at a clock 70 days ahead: %v, %d keys then %d", d, k0, keys())
	}
	if d := s4.recv(); !slices.Equal(d.bodies(), []string{"sealed to a prekey about to retire"}) {
		t.Errorf("the message sealed to the retired prekey, once the clock is right: %v", d)
	}
	s2.revoke()
	n := len(w.srv.Requests())
	if r := s2.send(s3.addr.String(), "from a revoked address"); r.rc == 0 || !strings.Contains(r.err, "REVOKED: this mailbox's own address is revoked") || !s2.bare() {
		t.Errorf("a send from a mailbox that holds its own revocation: %v", r)
	}
	if out := s2.must(`dr_recv > /dev/null 2>&1 && echo drained; dr_rekey > /dev/null 2>&1 && echo renewed; dr_pass > /dev/null 2>&1 && echo signed; true`); out != "" || len(w.srv.Requests()) != n {
		t.Errorf("a mailbox that holds its own revocation: %q, calls %q", out, w.calls(n))
	}
}
