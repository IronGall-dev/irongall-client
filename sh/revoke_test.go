package sh_test

import (
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

	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Revocation in the script: of an address and of its certificates, what a
// sender asks before it posts, and a box's own revocations (test.sh's §17 to
// §19 and §21 until 2026-10-21).

// top is the highest serial there is, 2^53 - 1.
const top = 9007199254740991

// revocation is box b's revocation record, made with ssh-keygen as the Go
// client's revocation make makes one: the script makes none. Its signature is
// left in $W/<name>.rev.sig.
func (b *sbox) revocation(name string) []byte {
	b.w.t.Helper()
	return []byte(b.must(`a=$(cat "$IG/address"); printf 'irongall-revoke-v1\n%s\n' "$a" | ssh-keygen -q -Y sign -n "irongall-revoke-v1:$a" -f "$IG/identity" > "$W/` + name + `.rev.sig" &&
jq -cn --arg i "$(ig_b64 "$IG/identity.doc")" --arg s "$(ig_b64 "$W/` + name + `.rev.sig")" '{type:"revocation_record", identity:$i, revocation_signature:$s}'`))
}

// revoke publishes b's revocation at its server, as the Go client's
// revocation publish does, and keeps it in the box as that command keeps it.
func (b *sbox) revoke() {
	b.w.t.Helper()
	rec := filepath.Join(b.w.work, "own.rev.json")
	writeFile(b.w.t, rec, b.revocation("own"))
	b.must(`ig_api PUT "/v1/$(cat "$IG/address")/revocations" ` + rec + ` > /dev/null && cp "$W/own.rev.sig" "$IG/revoked.sig"`)
}

// certs is a revocation of b's certificates through serial, signed with the
// key file signer, and its record, made with ssh-keygen: the script applies
// one and makes none. The statement and signature are $W/<name>.certs and
// .sig, the record $W/<name>.json.
func (b *sbox) certs(name string, serial uint64, signer string) string {
	b.w.t.Helper()
	b.must(fmt.Sprintf(`a=$(cat "$IG/address"); printf 'irongall-revoke-certs-v1\n%%s\n%%s\n' "$a" %d > "$W/%[2]s.certs"; ssh-keygen -q -Y sign -n "irongall-revoke-certs-v1:$a" -f %[3]s < "$W/%[2]s.certs" > "$W/%[2]s.sig"
jq -cn --arg i "$(ig_b64 "$IG/identity.doc")" --arg l "$(ig_b64 "$W/%[2]s.certs")" --arg g "$(ig_b64 "$W/%[2]s.sig")" '{identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$W/%[2]s.json"`, serial, name, signer))
	return filepath.Join(b.w.work, name+".json")
}

// publish puts a record at b's server, with no pass: the identity's own
// signature is the authority.
func (b *sbox) publish(record string) {
	b.w.t.Helper()
	b.must(`ig_api PUT "/v1/$(cat "$IG/address")/revocations" ` + record + ` > /dev/null`)
}

// saysRevoked answers every read of box b 410 revoked, carrying record, or
// none if it is nil: an operator's word, whatever it shows.
func (w *world) saysRevoked(b *sbox, record *protocol.Revocations) {
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == b.addr {
			forge.Refuse(rw, protocol.CodeRevoked, func(p *protocol.Problem) { p.Record = record })
			return
		}
		next.ServeHTTP(rw, r)
	})
}

// showing answers every read of box b as the server does, with the members
// of a JSON object put over it: whatever an operator shows.
func (w *world) showing(b *sbox, members []byte) {
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); !ok || x != b.addr {
			next.ServeHTTP(rw, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		var box, over map[string]any
		if json.Unmarshal(rec.Body.Bytes(), &box) != nil || json.Unmarshal(members, &over) != nil {
			w.t.Fatalf("an operator shows members over a box, and the server answered %d", rec.Code)
		}
		maps.Copy(box, over)
		fakeserver.WriteJSON(rw, http.StatusOK, box)
	})
}

// failing answers every read of box b with code: no answer about it.
func (w *world) failing(b *sbox, code protocol.Code) {
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
// one ends the box, is kept, and holds against a server that hides it; no
// answer about a sender is not "not revoked".
func TestScriptTakesARevocationOnItsProofAlone(t *testing.T) {
	w := newWorld(t)
	ra, rb, rc, rd := w.box(), w.box(), w.box(), w.box()
	va := strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "a", "address")))
	vdoc := abs(t, filepath.Join(vectors, "a", "identity.doc"))
	sigs := []string{"a/revoke.sig", "a/revoke.sha256.sig"}
	if p256() {
		if r := ra.sh(fmt.Sprintf("ig_revcheck %s %s %s", strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "c", "address"))), abs(t, filepath.Join(vectors, "c", "identity.doc")), abs(t, filepath.Join(vectors, "c", "revoke.sig")))); r.rc != 0 {
			t.Errorf("c/revoke.sig, by a P-256 identity, is not taken: %v", r)
		}
	} else {
		t.Log("this ssh-keygen reads no P-256 key (OpenSSH built without OpenSSL), so c/revoke.sig is not tried: a known variance (PROTOCOL.md Appendix A)")
	}
	for _, v := range sigs {
		if r := ra.sh(fmt.Sprintf("ig_revcheck %s %s %s", va, vdoc, abs(t, filepath.Join(vectors, v)))); r.rc != 0 {
			t.Errorf("vector %s is not taken as A's revocation: %v", v, r)
		}
	}
	bad, _ := filepath.Glob(filepath.Join(vectors, "revoke", "bad-*.sig"))
	if len(bad) == 0 {
		t.Fatal("no revoke/bad-*.sig vectors")
	}
	vb := strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "b", "address")))
	for _, v := range append(bad, "b") {
		cmd := fmt.Sprintf("ig_revcheck %s %s %s", va, vdoc, abs(t, v))
		if v == "b" { // A's revocation for another box, and under another identity
			cmd = fmt.Sprintf("ig_revcheck %s %s %[3]s || ig_revcheck %[4]s %[5]s %[3]s", vb, vdoc, abs(t, filepath.Join(vectors, sigs[0])), va, abs(t, filepath.Join(vectors, "b", "identity.doc")))
		}
		if r := ra.sh(cmd); r.rc == 0 {
			t.Errorf("%s is taken as a revocation: %v", v, r)
		}
	}
	rbRec := filepath.Join(w.work, "rb.json")
	writeFile(t, rbRec, rb.revocation("rb"))
	untyped := filepath.Join(w.work, "rb-untyped.json")
	rb.must(`jq -c 'del(.type)' ` + rbRec + ` > ` + untyped)
	if out := rb.must("ig_record " + rbRec + "; ig_record " + untyped); out != strings.Repeat(rb.addr.String()+"\n", 2) {
		t.Errorf("a record, and one that names no type: %q", out)
	}
	// A working key's signature over the same statement: good under its
	// certificate, and no revocation. (That the server refuses it is
	// irongall-server's to test.)
	wk := filepath.Join(w.work, "wk.json")
	rb.must(fmt.Sprintf(`printf 'irongall-revoke-v1\n%%s\n' %[1]s | ssh-keygen -q -Y sign -n irongall-revoke-v1:%[1]s -f "$IG/work/%[2]d-cert.pub" > "$W/wk.sig"
ig_certified %[1]s "$IG/identity.doc" irongall-revoke-v1:%[1]s "$W/wk.sig" <(printf 'irongall-revoke-v1\n%%s\n' %[1]s) > /dev/null
jq -cn --arg i "$(ig_b64 "$IG/identity.doc")" --arg s "$(ig_b64 "$W/wk.sig")" '{identity:$i, revocation_signature:$s}' > %[3]s`, rb.addr, rb.num(), wk))
	if r := rb.sh("ig_record " + wk); r.rc == 0 {
		t.Errorf("a working key's signature is read as a record: %v", r)
	}
	// The operator says RB is revoked, and shows nothing, or what is not its
	// revocation: a working key's signature, another box's revocation, and
	// another box's signature with this box's document.
	rcRec := filepath.Join(w.work, "rc.json")
	writeFile(t, rcRec, rc.revocation("rc"))
	mixed := filepath.Join(w.work, "mixed.json")
	rb.must(`jq -c --slurpfile b ` + rbRec + ` '.identity = $b[0].identity' ` + rcRec + ` > ` + mixed)
	wordOnly := func(what string) {
		t.Helper()
		if r := ra.send(rb.addr.String(), "to a box the server calls revoked"); r.rc == 0 || !strings.Contains(r.err, "showed no revocation that verifies") || ra.has("peers/"+rb.addr.String()+"/revoke.sig") || !ra.bare() {
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
	ra.mustSend(rb, "to a box the server calls revoked")
	if d := rb.recv(); len(d.mail) != 1 {
		t.Errorf("the same send once the server lets it: %v", d)
	}
	// A real revocation: the box learns it from the proof, and the mail
	// waiting for it goes; a second changes nothing.
	rd.mustSend(ra, "one")
	rd.mustSend(ra, "two")
	ra.mustSend(rd, "waiting in the box that is revoked")
	rd.revoke()
	if d := rd.recv(); d.rc == 0 || !strings.Contains(d.said, "REVOKED: this box's own address is revoked") {
		t.Errorf("a revoked box's recv: %v", d)
	}
	if r := rd.send(ra.addr.String(), "from a revoked box"); r.rc == 0 || !strings.Contains(r.err, "REVOKED") || !rd.bare() {
		t.Errorf("a revoked box's send: %v", r)
	}
	n := len(w.srv.Requests())
	reads := func(a protocol.Address, since int) int {
		return len(slices.DeleteFunc(w.calls(since), func(c string) bool { return c != "GET /v1/"+a.String() }))
	}
	if d := ra.recv(); len(d.mail) != 0 || d.refused("revoked") != 2 || reads(rd.addr, n) != 1 || !ra.has("peers/"+rd.addr.String()+"/revoke.sig") || w.srv.Count(ra.addr) != 0 {
		t.Errorf("mail from a box revoked since: %v, %d reads of it", d, reads(rd.addr, n))
	}
	// The operator then hides the revocation, and delivers mail that sender's
	// working key signed, which its certificate still covers.
	late := rd.line(ra.addr, "00000000-0000-4000-8000-00000000d001", "signed with a key that still verifies", 0)
	w.inject(ra, rd.addr, "", late, rd.sign(ra.addr, late))
	forge.Hides(t, w.srv)
	if d := ra.recv(); len(d.mail) != 0 || d.refused("revoked") != 1 {
		t.Errorf("a kept revocation against a server that hides it: %v", d)
	}
	n = len(w.srv.Requests())
	if r := ra.send(rd.addr.String(), "to a revoked box"); r.rc == 0 || !strings.Contains(r.err, "REVOKED: "+rd.addr.String()+" is revoked") || len(w.srv.Requests()) != n || !ra.bare() {
		t.Errorf("a send to a box this box holds a revocation of: %v, %q", r, w.calls(n))
	}
	// No answer about a sender, or a 2xx that is no box this script reads,
	// stops the drain with the message on the server; the next drain asks
	// again.
	rb.mustSend(rc, "waits for an answer")
	stopped := func(what string) {
		t.Helper()
		if d := rc.recv(); d.rc == 0 || len(d.mail) != 0 || w.srv.Count(rc.addr) != 1 || len(rc.files("quarantine")) != 0 {
			t.Errorf("%s: %v", what, d)
		}
	}
	w.failing(rb, protocol.CodeUnavailable)
	stopped("no answer about the sender")
	for _, v := range []string{"box-bad-prekey-a-number.json", "box-bad-revoked-certificates-a-number.json"} {
		w.showing(rb, mustRead(t, filepath.Join(vectors, "answer", v)))
		stopped(v + " over the box served")
	}
	w.honest()
	if d := rc.recv(); d.rc != 0 || len(d.mail) != 1 {
		t.Errorf("the drain once the server answers: %v", d)
	}
}

// keptCerts is the revocation of certificates a box keeps of address a, as
// its statement.
func (b *sbox) keptCerts(a protocol.Address) string {
	return b.must(`jq -r .revoked_certificates "$IG/peers/` + a.String() + `/revoked-certs.json" | base64 -d`)
}

// A revocation of certificates is the identity's own signature over exact
// text; a kept one revokes every serial through its own, and one that no
// longer verifies is a fault.
func TestScriptReadsARevocationOfCertificates(t *testing.T) {
	w := newWorld(t)
	p := w.box()
	va := strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "a", "address")))
	vec := func(n string) string { return abs(t, filepath.Join(vectors, n)) }
	ok4, okTop := vec("revoked/ok-through-4"), vec("revoked/ok-through-the-highest")
	if out := p.must(fmt.Sprintf("ig_certscheck %[1]s %[2]s %[3]s.txt %[3]s.sig; ig_certscheck %[1]s %[2]s %[3]s.txt %[3]s.sha256.sig; ig_certscheck %[1]s %[2]s %[4]s.txt %[4]s.sig", va, vec("a/identity.doc"), ok4, okTop)); out != "4\n4\n9007199254740991\n" {
		t.Errorf("the vectors that are a revocation of certificates: %q", out)
	}
	bad, _ := filepath.Glob(filepath.Join(vectors, "revoked", "bad-*.txt"))
	for _, v := range bad {
		if r := p.sh(fmt.Sprintf("ig_certscheck %s %s %s %s", va, vec("a/identity.doc"), abs(t, v), abs(t, strings.TrimSuffix(v, ".txt")+".sig"))); r.rc == 0 {
			t.Errorf("%s is taken as a revocation of A's certificates", filepath.Base(v))
		}
	}
	vb := strings.TrimSpace(mustReadString(t, filepath.Join(vectors, "b", "address")))
	if r := p.sh(fmt.Sprintf("ig_certscheck %[1]s %[2]s %[3]s.txt %[3]s.sig || ig_certscheck %[4]s %[2]s %[3]s.txt %[3]s.sig", vb, vec("b/identity.doc"), ok4, va)); r.rc == 0 {
		t.Error("A's revocation of certificates is taken for another box, or under another identity")
	}
	out := p.must(fmt.Sprintf(`d="$IG/peers/%[1]s"; mkdir -p "$d"; cp %[2]s "$d/identity.doc"
rec(){ jq -cn --arg i "$(ig_b64 %[2]s)" --arg l "$(ig_b64 "$1")" --arg g "$(ig_b64 "$2")" '{identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$d/revoked-certs.json"; }
rec %[3]s.txt %[3]s.sig; for n in 1 3 4 5 9007199254740991; do ig_certrevoked %[1]s $n; echo -n "$? "; done
rec %[4]s.txt %[4]s.sig; ig_certrevoked %[1]s 9007199254740991; echo -n "$? "
rec %[3]s.txt %[4]s.sig; ig_certrevoked %[1]s 2; echo -n "$? "
echo '{}' > "$d/revoked-certs.json"; ig_certrevoked %[1]s 2; echo "$?"`, va, vec("a/identity.doc"), ok4, okTop))
	if out != "0 0 0 1 1 0 3 3\n" {
		t.Errorf("a kept revocation through 4, through the highest, under another's signature, and one that holds none: %q", out)
	}
}

// Certificates revoked: a working key taken, a prekey published with it at
// the highest serial there is, the box's next certificate passing it, and the
// identity's revocation ending what the taken key can still sign.
func TestScriptAfterAWorkingKeyIsTaken(t *testing.T) {
	w := newWorld(t)
	ca, cb, cc := w.box(), w.box(), w.box()
	op := w.operator()
	cb.mustSend(cc, "signed under the first certificate, and read after it was revoked")
	lastQuery := func(to *sbox) string {
		rs := w.srv.Requests()
		for i := len(rs) - 1; i >= 0; i-- {
			if rs[i].Method == http.MethodPost && rs[i].Path == "/v1/"+to.addr.String()+"/messages" {
				return rs[i].Query
			}
		}
		return ""
	}
	n1, first := cb.num(), w.prekey(cb)
	ca.mustSend(cb, "before the theft")
	if q := lastQuery(cb); q != fmt.Sprintf("prekey_serial=%d&certificate_serial=%d", n1, n1) {
		t.Errorf("a send does not name its prekey by both serials: %q", q)
	}
	// CB's working key is taken. With it the thief holds a pass, and
	// publishes a prekey of the operator's under CB's certificate, at the
	// highest serial there is.
	taken := filepath.Join(w.work, "taken")
	writeFile(t, taken, []byte(cb.read(fmt.Sprintf("work/%d", n1))))
	writeFile(t, taken+"-cert.pub", []byte(cb.read(fmt.Sprintf("work/%d-cert.pub", n1))))
	thiefs := w.statement(cb, top, op.recipient(), notAfter(), taken+"-cert.pub")
	body, _ := json.Marshal(protocol.PrekeyRequest{Prekey: thiefs.st, PrekeySignature: thiefs.sig})
	writeFile(t, filepath.Join(w.work, "top.json"), body)
	cb.must(fmt.Sprintf(`h=$(ig_pass %d) && ig_api PUT "/v1/$(cat "$IG/address")/prekey" "$W/top.json" -H "Authorization: $h" > /dev/null; rm -f "$IG/pass.new"`, n1))
	if p, _ := w.served(cb); p != top {
		t.Fatalf("the thief's prekey was not taken: %d", p)
	}
	ca.mustSend(cb, "encrypted to the thief")
	peer := "peers/" + cb.addr.String() + "/"
	if ca.read(peer+"serial") != fmt.Sprintln(top) || lastQuery(cb) != fmt.Sprintf("prekey_serial=%d&certificate_serial=%d", top, n1) {
		t.Fatalf("CA's send to the thief's prekey: %q", lastQuery(cb))
	}
	w.serving(cb, first)
	if r := ca.send(cb.addr.String(), "x"); r.rc == 0 || !strings.Contains(r.err, fmt.Sprintf("prekey serial %d is below one already seen", n1)) {
		t.Errorf("an earlier statement under one certificate: %v", r)
	}
	w.honest()
	// The owner renews as ever: the next certificate passes the thief's
	// statement, and senders follow.
	cb.must("ig_rekey")
	n2 := cb.num()
	if p, c := w.served(cb); n2 <= n1 || n2 >= top || p != n2 || c != n2 {
		t.Errorf("a renewal past the top serial: %d, served %d under %d", n2, p, c)
	}
	ca.mustSend(cb, "after the renewal")
	if ca.read(peer+"serial") != fmt.Sprintln(n2) || ca.read(peer+"cert-serial") != fmt.Sprintln(n2) || lastQuery(cb) != fmt.Sprintf("prekey_serial=%d&certificate_serial=%d", n2, n2) {
		t.Errorf("CA's send after the renewal: %q", lastQuery(cb))
	}
	if d := cb.recv(); !slices.Equal(slices.Sorted(slices.Values(d.bodies())), []string{"after the renewal", "before the theft"}) || d.refused("undecryptable") != 1 {
		t.Errorf("what CB reads after its renewal: %v", d)
	}
	thief := func(to *sbox, msgID, body string) {
		l := envelope(t, cb.addr, to.addr, []byte(cb.read("identity.doc")), msgID, body, 0)
		w.inject(to, cb.addr, "", l, w.signWith(taken+"-cert.pub", to.addr, l))
	}
	thief(ca, "00000000-0000-4000-8000-00000000c001", "signed by the thief, before the revocation")
	if d := ca.recv(); !slices.Equal(d.bodies(), []string{"signed by the thief, before the revocation"}) {
		t.Errorf("control: mail the taken key signs, while nothing revokes it: %v", d)
	}
	// A revocation the working key signs is none; the identity's, through
	// the first certificate, is published with no pass. (What the server
	// takes of either is irongall-server's to test.)
	cb.certs("CBw", n1, cb.file(fmt.Sprintf("work/%d-cert.pub", n2)))
	cb.must(fmt.Sprintf(`ig_certified %s "$IG/identity.doc" irongall-revoke-certs-v1:%[1]s "$W/CBw.sig" "$W/CBw.certs" > /dev/null`, cb.addr))
	if r := cb.sh(fmt.Sprintf(`ig_certscheck %s "$IG/identity.doc" "$W/CBw.certs" "$W/CBw.sig"`, cb.addr)); r.rc == 0 {
		t.Errorf("a revocation of certificates the working key signed is taken: %v", r)
	}
	cb.publish(cb.certs("CB2", n1, cb.file("identity")))
	// Mail the thief signs now, and mail under the box's new certificate.
	thief(ca, "00000000-0000-4000-8000-00000000c002", "signed by the thief, after the revocation")
	cb.mustSend(ca, "under the new certificate")
	n := len(w.srv.Requests())
	reads := func() int {
		return len(slices.DeleteFunc(w.calls(n), func(c string) bool { return c != "GET /v1/"+cb.addr.String() }))
	}
	if d := ca.recv(); !slices.Equal(d.bodies(), []string{"under the new certificate"}) || d.refused("certificate_revoked") != 1 || reads() != 1 ||
		ca.keptCerts(cb.addr) != mustReadString(t, filepath.Join(w.work, "CB2.certs")) || strings.Count(ca.read(peer+"revoked-certs.json"), "\n") != 1 || ca.has(peer+"revoke.sig") {
		t.Errorf("after the revocation: %v, %d reads", d, reads())
	}
	thief(ca, "00000000-0000-4000-8000-00000000c003", "signed by the thief, the revocation hidden")
	forge.Hides(t, w.srv)
	if d := ca.recv(); len(d.mail) != 0 || d.refused("certificate_revoked") != 1 {
		t.Errorf("a kept revocation of certificates against a server that hides it: %v", d)
	}
	w.honest()
	if d := cc.recv(); len(d.mail) != 0 || d.refused("certificate_revoked") != 1 {
		t.Errorf("the box's own unread mail under that certificate: %v", d)
	}
	// CC never saw a later statement of CB's, and holds the revocation: a
	// server that serves the thief's prekey gets nothing encrypted to it.
	w.serving(cb, thiefs)
	if r := cc.send(cb.addr.String(), "not to a prekey under a revoked certificate"); r.rc == 0 || !strings.Contains(r.err, "signed under a certificate its identity has revoked") || cc.has(peer+"serial") || !cc.bare() {
		t.Errorf("a prekey statement under a revoked certificate: %v", r)
	}
	w.honest()
	cc.mustSend(cb, "not to a prekey under a revoked certificate")
	if cc.read(peer+"cert-serial") != fmt.Sprintln(n2) {
		t.Errorf("the send, the server honest, went under %q", cc.read(peer+"cert-serial"))
	}
	// A lower revocation never replaces a higher one, whatever a server
	// shows; a kept one that no longer verifies is a fault of the box.
	cb.mustSend(ca, "another, for a second lookup")
	w.showing(cb, mustRead(t, cb.certs("CB1", n1-1, cb.file("identity"))))
	if d := ca.recv(); len(d.mail) != 1 || ca.keptCerts(cb.addr) != mustReadString(t, filepath.Join(w.work, "CB2.certs")) {
		t.Errorf("a lower revocation replaced a higher one: %v", d)
	}
	w.honest()
	cb.mustSend(ca, "held while the kept revocation is broken")
	kept := ca.read(peer + "revoked-certs.json")
	ca.must(fmt.Sprintf(`jq -cn --arg i "$(ig_b64 "$IG/%sidentity.doc")" --arg l "$(ig_b64 "$W/CB1.certs")" --arg g "$(ig_b64 "$W/CB2.sig")" '{identity:$i, revoked_certificates:$l, revoked_certificates_signature:$g}' > "$IG/%[1]srevoked-certs.json"`, peer))
	q := len(ca.files("quarantine"))
	if d := ca.recv(); d.rc == 0 || len(d.mail) != 0 || w.srv.Count(ca.addr) != 1 || len(ca.files("quarantine")) != q || !strings.Contains(d.said, "does not verify") {
		t.Errorf("a kept revocation swapped for one that does not verify: %v", d)
	}
	writeFile(t, ca.file(peer+"revoked-certs.json"), []byte(kept))
	if d := ca.recv(); d.rc != 0 || len(d.mail) != 1 {
		t.Errorf("after the kept revocation was put back: %v", d)
	}
}

// A box whose current certificate is revoked has no pass the server takes
// and no mail a sender may seal to it, until one renewal; a box never makes a
// certificate its identity revoked.
func TestScriptUnderItsOwnRevokedCertificate(t *testing.T) {
	w := newWorld(t)
	ca, cd, ce := w.box(), w.box(), w.box()
	nd := cd.num()
	cd.publish(cd.certs("CD1", nd, cd.file("identity")))
	if out := cd.must(`ig_recv > /dev/null 2>&1 && echo drained; ig_code`); out != "certificate_revoked\n" {
		t.Errorf("a drain under a revoked certificate: %q", out)
	}
	forge.Hides(t, w.srv) // so that the answer this sender meets is the server's own
	if out := ca.must(`printf 'to a box whose certificate is revoked' | ig_send ` + cd.addr.String() + ` > /dev/null 2>&1 && echo sent; ig_code`); out != "prekey_expired\n" || !ca.bare() {
		t.Errorf("a send to a box whose certificate is revoked: %q", out)
	}
	w.honest()
	cd.must("ig_rekey")
	if _, c := w.served(cd); c <= nd {
		t.Errorf("CD renewed under %d", c)
	}
	ca.mustSend(cd, "to a box whose certificate is revoked")
	if d := cd.recv(); !slices.Equal(d.bodies(), []string{"to a box whose certificate is revoked"}) {
		t.Errorf("after CD's renewal: %v", d)
	}
	x := ce.num() + 1000000 // a slip of a digit
	ce.publish(ce.certs("CE1", x, ce.file("identity")))
	if out := ce.must(`ig_lookup "$(cat "$IG/address")"; echo "$? $(ig_certskept "$(cat "$IG/address")")"`); out != fmt.Sprintf("1 %d\n", x) {
		t.Errorf("CE's lookup of its own revocation of certificates: %q", out)
	}
	ce.must("ig_rekey")
	if _, c := w.served(ce); ce.num() != x+1 || c != x+1 {
		t.Errorf("a renewal above a revocation far ahead of the clock: %d, served %d", ce.num(), c)
	}
	ce.publish(ce.certs("CE2", top, ce.file("identity")))
	if r := ce.sh(`ig_lookup "$(cat "$IG/address")"; ig_rekey`); r.rc == 0 || !strings.Contains(r.err, "revoked its certificates through the highest serial there is") {
		t.Errorf("a renewal with no serial left: %v", r)
	}
}

// A box makes no certificate above the highest serial there is (#69): not
// past an earlier attempt that took the highest and left nothing it can send,
// and not when what it published is the highest, its server holding no box
// for it to read.
func TestScriptMakesNoCertificateAboveTheHighest(t *testing.T) {
	w := newWorld(t)
	cf := w.box()
	n := cf.num()
	above := func() bool {
		return cf.has(fmt.Sprintf("prekeys/%d.agekey", uint64(top)+1)) || cf.has(fmt.Sprintf("work/%d-cert.pub", uint64(top)+1))
	}
	writeFile(t, cf.file(fmt.Sprintf("prekeys/%d.txt.sig", uint64(top))), []byte("not a signature\n"))
	if r := cf.sh("ig_rekey"); r.rc == 0 || !strings.Contains(r.err, "certificate serial is the highest there is") || cf.num() != n || above() {
		t.Errorf("a renewal past an attempt at the highest serial: %v", r)
	}
	if err := os.Remove(cf.file(fmt.Sprintf("prekeys/%d.txt.sig", uint64(top)))); err != nil {
		t.Fatal(err)
	}
	writeFile(t, cf.file("serial"), fmt.Appendln(nil, uint64(top)))
	w.failing(cf, protocol.CodeNoSuchMailbox)
	if r := cf.sh("ig_rekey"); r.rc == 0 || !strings.Contains(r.err, "certificate serial is the highest there is") || above() {
		t.Errorf("a renewal from the highest serial, published: %v", r)
	}
}

// A kept revocation of a peer's certificates that does not verify is a fault
// of the box, where the server shows none to keep instead (#69): a send to
// the peer posts nothing, and a drain of its mail stops with the mail on the
// server.
func TestScriptStopsAtAKeptRevocationThatDoesNotVerify(t *testing.T) {
	w := newWorld(t)
	ca, cb := w.box(), w.box()
	ca.mustSend(cb, "pins CB")
	writeFile(t, ca.file("peers/"+cb.addr.String()+"/revoked-certs.json"), mustRead(t, cb.certs("CB-not-its-own", 1, ca.file("identity"))))
	n := w.posts(cb.addr)
	if r := ca.send(cb.addr.String(), "not past a revocation that does not verify"); r.rc == 0 || !strings.Contains(r.err, "does not verify") || w.posts(cb.addr) != n || !ca.bare() {
		t.Errorf("a send: %v", r)
	}
	cb.mustSend(ca, "waits past a revocation that does not verify")
	if d := ca.recv(); d.rc == 0 || len(d.mail) != 0 || w.srv.Count(ca.addr) != 1 || !strings.Contains(d.said, "does not verify") {
		t.Errorf("a drain: %v", d)
	}
}

// A sender reads its recipient's box before every post, keeps what
// verifies, and seals to what it then holds; no answer is not "none held".
func TestScriptAsksBeforeItPosts(t *testing.T) {
	w := newWorld(t)
	sa, sb, sc, sd, se := w.box(), w.box(), w.box(), w.box(), w.box()
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
	if d := sb.recv(); !slices.Equal(d.bodies(), []string{"asked first", "waits for an answer"}) {
		t.Errorf("SB's mail: %v", d)
	}
	// SB's working key is taken. SB renews, and its identity revokes the
	// certificate the thief holds a key under. An operator that helps the
	// thief goes on serving the old statement.
	n1 := sb.num()
	old := w.prekey(sb)
	sb.must("ig_rekey")
	sb.publish(sb.certs("SB1", n1, sb.file("identity")))
	certs := mustReadString(t, filepath.Join(w.work, "SB1.certs"))
	peer := "peers/" + sb.addr.String() + "/"
	w.reading(sb.addr, func(br *protocol.BoxResponse) {
		br.Prekey, br.PrekeySignature, br.RevokedCertificates, br.RevokedCertificatesSignature = old.st, old.sig, nil, nil
	})
	sc.send(sb.addr.String(), "sealed to the old prekey")
	var q string
	for _, r := range w.srv.Requests() {
		if r.Method == http.MethodPost && r.Path == "/v1/"+sb.addr.String()+"/messages" {
			q = r.Query
		}
	}
	if q != fmt.Sprintf("prekey_serial=%d&certificate_serial=%d", n1, n1) || sc.read(peer+"cert-serial") != fmt.Sprintln(n1) || sc.has(peer+"revoked-certs.json") {
		t.Errorf("control: a sender shown no revocation does not seal to the old prekey: %q", q)
	}
	// The same operator, the revocation not hidden: SE has never met SB.
	w.serving(sb, old)
	n = w.posts(sb.addr)
	if r := se.send(sb.addr.String(), "never sealed to the old prekey"); r.rc == 0 || !strings.Contains(r.err, "signed under a certificate its identity has revoked") || w.posts(sb.addr) != n ||
		se.keptCerts(sb.addr) != certs || se.has(peer+"serial") || !se.bare() {
		t.Errorf("a sender that asks before it sends: %v", r)
	}
	w.honest()
	se.mustSend(sb, "never sealed to the old prekey")
	if se.read(peer+"cert-serial") != fmt.Sprintln(sb.num()) {
		t.Errorf("SE's send, the server honest, went under %q", se.read(peer+"cert-serial"))
	}
	// What a box was shown once holds after the server hides it.
	if out := sd.must(`ig_lookup ` + sb.addr.String() + `; echo $?`); out != "1\n" || sd.keptCerts(sb.addr) != certs {
		t.Errorf("SD's lookup: %q", out)
	}
	w.reading(sb.addr, func(br *protocol.BoxResponse) {
		br.Prekey, br.PrekeySignature, br.RevokedCertificates, br.RevokedCertificatesSignature = old.st, old.sig, nil, nil
	})
	n = w.posts(sb.addr)
	if r := sd.send(sb.addr.String(), "never sealed either"); r.rc == 0 || !strings.Contains(r.err, "signed under a certificate its identity has revoked") || w.posts(sb.addr) != n {
		t.Errorf("after the server turned: %v", r)
	}
	w.honest()
	if d := sb.recv(); !slices.Equal(d.bodies(), []string{"never sealed to the old prekey"}) {
		t.Errorf("SB's mail: %v", d)
	}
}

// own is the record of box b's identity's revocation of its certificates
// through serial.
func (b *sbox) own(serial uint64) []byte {
	return mustRead(b.w.t, b.certs("own-certs", serial, b.file("identity")))
}

// A box's own revocations: a renewal takes what is held of them; a clock far
// ahead deletes no key that mail waits for; a certificate its identity
// revoked signs no mail; a box that holds its own revocation of its address
// signs nothing more.
func TestScriptUnderItsOwnRevocations(t *testing.T) {
	w := newWorld(t)
	s1, s2, s3, s4 := w.box(), w.box(), w.box(), w.box()
	x := s1.num() + 10*365*86400
	writeFile(t, filepath.Join(w.work, "s1.json"), s1.own(x))
	s1.publish(filepath.Join(w.work, "s1.json"))
	if s1.has("revoked-certs.json") {
		t.Fatal("the box holds the revocation it published by hand")
	}
	time.Sleep(time.Second)
	s1.must("ig_rekey")
	if out := s1.must(`ig_certskept "$(cat "$IG/address")"`); s1.num() <= x || out != fmt.Sprintln(x) {
		t.Errorf("a renewal under a revocation through a serial ten years ahead, which the box never held: %d against %d, kept %q", s1.num(), x, out)
	}
	s1.mustSend(s4, "sealed to a prekey about to retire")
	time.Sleep(time.Second)
	s4.must("ig_rekey")
	keys := func() int { k, _ := filepath.Glob(s4.file("prekeys/*.agekey")); return len(k) }
	k0 := keys()
	if d := (at{s4, 70 * 24 * time.Hour}).recv(); d.rc == 0 || keys() != k0 {
		t.Errorf("a drain at a clock 70 days ahead: %v, %d keys then %d", d, k0, keys())
	}
	if d := s4.recv(); !slices.Equal(d.bodies(), []string{"sealed to a prekey about to retire"}) {
		t.Errorf("the mail sealed to the retired prekey, once the clock is right: %v", d)
	}
	writeFile(t, s3.file("revoked-certs.json"), s3.own(s3.num()))
	n := w.posts(s4.addr)
	if r := s3.send(s4.addr.String(), "signed under a certificate its identity revoked"); r.rc == 0 || !strings.Contains(r.err, "has revoked the certificate it signs under") || !s3.bare() || w.posts(s4.addr) != n {
		t.Errorf("a seal under a certificate the box's own identity revoked: %v", r)
	}
	time.Sleep(time.Second)
	s3.must("ig_rekey")
	if r := s3.send(s4.addr.String(), "signed under a certificate its identity revoked"); r.rc != 0 || !strings.HasPrefix(r.out, `{"type":"sent",`) {
		t.Errorf("the send once the renewal is taken: %v", r)
	}
	if d := s4.recv(); !slices.Equal(d.bodies(), []string{"signed under a certificate its identity revoked"}) {
		t.Errorf("its mail: %v", d)
	}
	s2.revoke()
	n = len(w.srv.Requests())
	if r := s2.send(s3.addr.String(), "from a revoked address"); r.rc == 0 || !strings.Contains(r.err, "REVOKED: this box's own address is revoked") || !s2.bare() {
		t.Errorf("a send from a box that holds its own revocation: %v", r)
	}
	if out := s2.must(`ig_recv > /dev/null 2>&1 && echo drained; ig_rekey > /dev/null 2>&1 && echo renewed; ig_pass > /dev/null 2>&1 && echo signed; true`); out != "" || len(w.srv.Requests()) != n {
		t.Errorf("a box that holds its own revocation: %q, calls %q", out, w.calls(n))
	}
}
