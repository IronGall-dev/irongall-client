package sh_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/http"
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

// The script's box made, sending and reading, against a server that forges
// (test.sh's §1 to §6 until 2026-10-21).

// served is the serial of box a's prekey as the server serves it, and of the
// certificate it is signed under.
func (w *world) served(b *sbox) (prekey, cert uint64) {
	w.t.Helper()
	st, sig := w.srv.Prekey(b.addr)
	id, err := protocol.ParseIdentity([]byte(b.read("identity.doc")))
	if err != nil {
		w.t.Fatal(err)
	}
	p, c, err := protocol.VerifyPrekey(id, st, sig, time.Now())
	if err != nil {
		w.t.Fatalf("the statement served for %s: %v", b.addr, err)
	}
	return p.Serial, c.Serial()
}

// envelope is an envelope's line from box from to address to, carrying the
// identity document doc, sent ago before now.
func envelope(t *testing.T, from, to protocol.Address, doc []byte, msgID, body string, ago time.Duration) []byte {
	t.Helper()
	e, err := protocol.NewEnvelope(from, to, body, time.Now().Add(-ago))
	if err != nil {
		t.Fatal(err)
	}
	e.MsgID, e.Identity = msgID, doc
	l, err := e.Line()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// line is an envelope's line as box b writes one to to.
func (b *sbox) line(to protocol.Address, msgID, body string, ago time.Duration) []byte {
	return envelope(b.w.t, b.addr, to, []byte(b.read("identity.doc")), msgID, body, ago)
}

// signWith signs line for box to with the working key whose certificate is
// cert, as ssh-keygen signs one: its signature block.
func (w *world) signWith(cert string, to protocol.Address, line []byte) []byte {
	w.t.Helper()
	f := filepath.Join(w.t.TempDir(), "P")
	if err := os.WriteFile(f, line, 0o600); err != nil {
		w.t.Fatal(err)
	}
	b := &sbox{w: w, dir: w.work}
	return []byte(b.must(fmt.Sprintf("ssh-keygen -q -Y sign -n dromas-msg-v1:%s -f %s < %s", to, cert, f)))
}

// sign signs line for to with b's working key in use.
func (b *sbox) sign(to protocol.Address, line []byte) []byte {
	return b.w.signWith(b.file(fmt.Sprintf("work/%d-cert.pub", b.num())), to, line)
}

// inject puts the parts, encrypted to to's prekey as the server holds it, in
// box to, under id or, given none, its hash: as only the operator can. It
// returns the id.
func (w *world) inject(to *sbox, id string, parts ...[]byte) string {
	w.t.Helper()
	ct := forge.Encrypt(w.t, w.srv, to.addr, parts...)
	return w.put(to, id, ct)
}

// put puts a ciphertext in box to, as inject does.
func (w *world) put(to *sbox, id string, ct []byte) string {
	if id == "" {
		h := sha256.Sum256(ct)
		id = hex.EncodeToString(h[:])
	}
	w.srv.Inject(to.addr, id, ct)
	return id
}

// randomID is an id no ciphertext hashes to.
func randomID() string {
	h := sha256.Sum256([]byte(time.Now().String()))
	return hex.EncodeToString(h[:])
}

// bare reports whether a send left nothing behind: no outbox, and none of
// the files it wrote to post its message (dr_spent).
func (b *sbox) bare() bool {
	for _, f := range []string{"outbox", "body.txt", "send.P", "seal.P", "seal.sig", "seal.age", "seal.query", "box.json", "receipt.json"} {
		if exists(b.file(f)) {
			return false
		}
	}
	return true
}

// A send leaves no copy of its body outside sent/, posted or refused at its
// post: every file of the box is read, not a list of the files a send
// writes.
func TestASendLeavesNoCopyOfItsBody(t *testing.T) {
	w := newWorld(t)
	a, b := w.box(), w.box()
	copies := func(body string) []string {
		var held []string
		_ = filepath.WalkDir(a.dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				if d != nil && d.IsDir() && d.Name() == "sent" {
					return filepath.SkipDir
				}
				return err
			}
			if s, err := os.ReadFile(p); err == nil && strings.Contains(string(s), body) {
				held = append(held, strings.TrimPrefix(p, a.dir+string(filepath.Separator)))
			}
			return nil
		})
		return held
	}
	posted := "posted " + randomID()
	a.mustSend(b, posted)
	if held := copies(posted); held != nil {
		t.Errorf("a send that was posted left its body in %v", held)
	}
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost {
			forge.Refuse(rw, protocol.CodeUnavailable)
			return
		}
		next.ServeHTTP(rw, r)
	})
	refused := "refused " + randomID()
	if r := a.send(b.addr.String(), refused); r.rc == 0 {
		t.Fatalf("a send the server refused: %v", r)
	}
	if held := copies(refused); held != nil {
		t.Errorf("a send the server refused left its body in %v", held)
	}
}

// boxLine is the line init and addr print.
func (w *world) boxLine(b *sbox) string {
	return fmt.Sprintf(`{"type":"box","address":"%s","link":"%s/to/%s"}`+"\n", b.addr, w.srv.URL, b.addr)
}

// init: an address that is the identity's hash and a box in use at once,
// its first number this machine's clock, keys and the pass 0600, a pass and
// no token; init again changes nothing, and an unknown option is refused.
func TestScriptInit(t *testing.T) {
	w := newWorld(t)
	if r := w.empty().sh("dr_recv"); r.rc == 0 || !strings.Contains(r.err, "no box in") {
		t.Errorf("recv where there is no box: %v", r)
	}
	a := w.empty()
	out := a.must("dr_init")
	t0 := time.Now().Unix()
	a.addr = mustAddress(t, a.dir)
	if out != w.boxLine(a) {
		t.Errorf("dr_init printed %q", out)
	}
	if sha256.Sum256([]byte(a.read("identity.doc"))) != a.addr {
		t.Error("the address is not the identity document's hash")
	}
	n := a.num()
	if p, c := w.served(a); p != n || c != n || !slices.Equal(w.calls(0), []string{"PUT /v1/" + a.addr.String()}) {
		t.Errorf("the box is not in use at once, at its number %d, by one call: served %d under %d, calls %q", n, p, c, w.calls(0))
	}
	if int64(n) > t0 || t0-int64(n) >= 300 {
		t.Errorf("the box's first number %d is not this machine's clock, %d", n, t0)
	}
	for _, f := range []string{"identity", fmt.Sprintf("work/%d", n), "pass", fmt.Sprintf("prekeys/%d.agekey", n)} {
		if fi, err := os.Stat(a.file(f)); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: %v %v, not 0600", f, fi.Mode(), err)
		}
	}
	var serial, start, end int64
	if _, err := fmt.Sscan(a.must(fmt.Sprintf(`dr_cert "$DR/prekeys/%d.txt.sig" "$DR/identity.doc" %s`, n, a.addr)), &serial, &start, &end); err != nil || serial != int64(n) ||
		end-time.Now().Unix() <= 64*86400-60 || end-time.Now().Unix() > 64*86400 {
		t.Errorf("the prekey statement is not under a certificate numbered %d that is good for 64 days: %d %d %d, %v", n, serial, start, end, err)
	}
	if a.has("token") || !strings.HasPrefix(a.read("pass"), `dromas-pass address="`+a.addr.String()+`", not_after="`) {
		t.Errorf("the box keeps a token, or no pass it signed: %q", a.read("pass"))
	}
	if out := a.must("dr_init"); out != w.boxLine(a) {
		t.Errorf("dr_init again: %q", out)
	}
	if r := a.sh("dr_init classic"); r.rc == 0 || !strings.Contains(r.err, "unknown option classic") {
		t.Errorf("an unknown option, the old classic: %v", r)
	}
}

// Two sends in a row and both read, to an address or a link; a link to
// another server or what is no address refused; what the server holds; what
// the reader asks it, pins, prints and keeps.
func TestScriptSendsAndReads(t *testing.T) {
	w := newWorld(t)
	a, b := w.box(), w.box()
	posted := forge.Capture(w.srv, http.MethodPost, "/messages")
	a.mustSend(b, "hello B")
	if r := a.send(w.srv.URL+"/to/"+b.addr.String(), "second, \"quoted\" <tags> & ünïcode\n"); r.rc != 0 {
		t.Fatalf("the second send, to B's link: %v", r)
	}
	if out := a.must("dr_addr"); out != w.boxLine(a) {
		t.Errorf("dr_addr: %q", out)
	}
	for _, l := range []string{"https://elsewhere.example/to/" + b.addr.String(), w.srv.URL + ".example/to/" + b.addr.String()} {
		if r := a.send(l, "x"); r.rc == 0 || !strings.Contains(r.err, "a link to another server: this box's server is "+w.srv.URL) {
			t.Errorf("a link to another server, %s: %v", l, r)
		}
	}
	for _, l := range []string{w.srv.URL + "/to/" + b.addr.String() + "/", w.srv.URL + "/v1/" + b.addr.String(), strings.ToUpper(b.addr.String())} {
		if r := a.send(l, "x"); r.rc == 0 || !strings.Contains(r.err, "not an address or a link to one") {
			t.Errorf("neither an address nor a link, %s: %v", l, r)
		}
	}
	if w.srv.Count(b.addr) != 2 || !a.bare() {
		t.Errorf("a refused destination made mail: %d held", w.srv.Count(b.addr))
	}
	if strings.Contains(string(*posted), "SSH SIGNATURE") || strings.Contains(string(*posted), `"from"`) {
		t.Error("a post carries a signature or an envelope in the clear")
	}
	w.honest()
	n := len(w.srv.Requests())
	d := b.recv()
	if d.rc != 0 || !slices.Equal(d.bodies(), []string{"hello B", "second, \"quoted\" <tags> & ünïcode\n"}) {
		t.Fatalf("B's drain: %v", d)
	}
	var reads []string
	for _, c := range w.calls(n) {
		if strings.HasPrefix(c, "GET /v1/") && !strings.Contains(c[len("GET /v1/"):], "/") {
			reads = append(reads, c)
		}
	}
	if !slices.Equal(reads, []string{"GET /v1/" + a.addr.String()}) || b.read("peers/"+a.addr.String()+"/identity.doc") != a.read("identity.doc") {
		t.Errorf("B asked about a sender it never met other than by one read of its box, or pinned another identity: %q", reads)
	}
	if strings.Contains(strings.Join(d.mail, ""), `"identity"`) {
		t.Error("a delivered line carries the identity document")
	}
	inbox := b.files("inbox")
	if w.srv.Count(b.addr) != 0 || len(inbox) != 2 {
		t.Errorf("not both acked and kept: %d held, inbox %q", w.srv.Count(b.addr), inbox)
	}
	var seen []string
	for l := range strings.Lines(b.read("seen")) {
		seen = append(seen, strings.Fields(l)[0]+".json")
	}
	slices.Sort(seen)
	for _, f := range inbox {
		if l := b.read("inbox/" + f); l == "" || strings.Contains(l, "\n") {
			t.Errorf("inbox/%s is not one line, with no line feed", f)
		}
	}
	if !slices.Equal(inbox, seen) {
		t.Errorf("inbox/ is not named by the hashes in seen: %q, %q", inbox, seen)
	}
}

// A retry, sealed again to a new ciphertext with the same msg_id, is
// delivered once. (That the server stores a byte-identical post once is
// dromas-server's to test.)
func TestScriptDeliversARetryOnce(t *testing.T) {
	w := newWorld(t)
	a, b := w.box(), w.box()
	if err := os.WriteFile(a.file("retry.P"), a.line(b.addr, "11111111-2222-4333-8444-555555555555", "once", 0), 0o600); err != nil {
		t.Fatal(err)
	}
	post := fmt.Sprintf(`dr_seal %s "$DR/retry" && dr_owner POST "/v1/%s/messages?$(cat "$DR/seal.query")" "$DR/seal.age" > /dev/null`, b.addr, b.addr)
	a.must(post + "\n" + post)
	if w.srv.Count(b.addr) != 2 {
		t.Fatalf("two seals of one envelope are %d ciphertexts", w.srv.Count(b.addr))
	}
	if d := b.recv(); len(d.mail) != 1 || !strings.Contains(d.said, "duplicate") {
		t.Errorf("a retry is not delivered once: %v", d)
	}
}

// listing puts an operator in front of the server that rewrites each list it
// answers with edit (forge.Lists).
func (w *world) listing(edit func(*forge.Listed)) { forge.Lists(w.t, w.srv, edit) }

// Mail a server forges, a replay, and what is no message: each REFUSED,
// kept in refused/ with its reason, and acked; nothing pinned by it. A from the
// server lists is never read.
func TestScriptRefusesForgedMail(t *testing.T) {
	w := newWorld(t)
	a, b, c, d := w.box(), w.box(), w.box(), w.box()
	op := w.operator()
	opCert := filepath.Join(op.dir, "work-cert.pub")
	pinned := func() string { return b.read("peers/" + a.addr.String() + "/identity.doc") }
	// A genuine message from A, to pin it, and kept to relabel and replay.
	posted := forge.Capture(w.srv, http.MethodPost, "/messages")
	a.mustSend(b, "genuine")
	genuine := *posted
	w.honest()
	if dr := b.recv(); len(dr.mail) != 1 {
		t.Fatalf("the genuine message: %v", dr)
	}
	refusals := 0
	refused := func(what, want string, d drain) {
		t.Helper()
		refusals++
		if len(d.mail) != 0 || !strings.Contains(d.said, want) {
			t.Errorf("%s: %v", what, d)
		}
	}
	// In A's name, with A's identity document, under the operator's certificate.
	forged := func(from *sbox) []byte {
		l := envelope(t, from.addr, b.addr, []byte(from.read("identity.doc")), "00000000-0000-4000-8000-000000000000", "PAPAYA", 0)
		return slices.Concat(l, w.signWith(opCert, b.addr, l))
	}
	w.inject(b, "", forged(a))
	r := b.sh("dr_recv")
	refusals++
	if !strings.Contains(r.out, `"code":"bad_signature","message":"it is not signed for this box by a working key the sender's identity certified"}`) || r.err != "" || w.srv.Count(b.addr) != 0 || pinned() != a.read("identity.doc") {
		t.Errorf("mail in A's name under the operator's certificate: %v", r)
	}
	var l struct{ Type, ID, Code, Message string }
	if !strings.HasPrefix(r.out, `{"type":"refused","id":"`) || strings.Count(r.out, "\n") != 1 || jsonLine(r.out, &l) != nil || len(l.ID) != 64 {
		t.Errorf("a refusal is not one line of JSON on stdout, its type first: %q", r.out)
	}
	w.inject(b, "", forged(d))
	refused("first contact, mail in D's name under the operator's certificate", "bad_signature", b.recv())
	if b.has("peers/" + d.addr.String()) {
		t.Error("the forgery pinned D")
	}
	// A from the server made up, with a line feed and a signer after it,
	// beside the operator's own mail: the from is never read, so the mail is
	// the operator's, as its signature says, and nothing is built from it.
	opDoc := []byte(mustReadString(t, filepath.Join(op.dir, "identity.doc")))
	ol := envelope(t, op.addr, b.addr, opDoc, "00000000-0000-4000-8000-000000000001", "PAPAYA", 0)
	w.inject(b, "", ol, w.signWith(opCert, b.addr, ol))
	madeUp := a.addr.String() + "\n* " + strings.Split(string(opDoc), "\n")[1]
	w.listing(func(l *forge.Listed) {
		for i := range l.Messages {
			l.Messages[i].From = madeUp
		}
	})
	if dr := b.recv(); len(dr.mail) != 1 || !strings.Contains(dr.mail[0], `"from":"`+op.addr.String()+`"`) || w.srv.Count(b.addr) != 0 {
		t.Errorf("the operator's mail under a from it made up, with a newline: %v", dr)
	}
	w.honest()
	if out := b.must(`grep -rqs '^\*' "$DR/peers" "$DR/signers" && echo planted || true`); out != "" {
		t.Error("a signer line was built from a from the server made up")
	}
	// A's genuine ciphertext, listed as C's: a replay of A's, whoever the list
	// names; then A's again, under its own id, and a new one.
	w.put(b, randomID(), genuine)
	w.listing(func(l *forge.Listed) {
		for i := range l.Messages {
			l.Messages[i].From = c.addr.String()
		}
	})
	refused("A's message listed as C's", "replay", b.recv())
	w.honest()
	if b.has("peers/" + c.addr.String()) {
		t.Error("the message listed as C's pinned C")
	}
	w.put(b, "", genuine)
	if dr := b.recv(); len(dr.mail) != 0 || dr.said != "" || w.srv.Count(b.addr) != 0 {
		t.Errorf("a replay under an id already handled is more than acked again: %v", dr)
	}
	w.put(b, randomID(), genuine)
	refused("a replay under a new id", "replay", b.recv())
	// A genuine new message under an id that is not its hash; one older than 33 days; a key twice.
	wl := a.line(b.addr, "44444444-2222-4333-8444-555555555555", "wrong id", 0)
	w.inject(b, randomID(), wl, a.sign(b.addr, wl))
	refused("a genuine message under an id that is not its hash", "not the SHA-256 of its ciphertext", b.recv())
	old := a.line(b.addr, "22222222-2222-4333-8444-555555555555", "old", 34*24*time.Hour)
	w.inject(b, "", old, a.sign(b.addr, old))
	refused("sent_at older than 33 days", "older than 33 days", b.recv())
	dup := fmt.Appendf(nil, `{"v":1,"from":"%s","from":"%s","to":"%s","sent_at":"%s","msg_id":"55555555-2222-4333-8444-555555555555","identity":"%s","body":"twice"}`+"\n",
		c.addr, a.addr, b.addr, time.Now().UTC().Format(protocol.TimeLayout), b64(a.read("identity.doc")))
	w.inject(b, "", dup, a.sign(b.addr, dup))
	refused("an envelope with a key twice", "no member named twice", b.recv())
	// Each part has one place: what follows the first END line is never read,
	// and a line before the envelope, a blank line before the signature, or no
	// signature is no message.
	fromA := a.line(b.addr, "66666666-2222-4333-8444-555555555551", "real, from A", 0)
	fromASig := a.sign(b.addr, fromA)
	hidden := c.line(b.addr, "66666666-2222-4333-8444-555555555552", "hidden, from C", 0)
	w.inject(b, "", fromA, fromASig, hidden, c.sign(b.addr, hidden))
	if dr := b.recv(); !slices.Equal(dr.bodies(), []string{"real, from A"}) || strings.Contains(dr.said+strings.Join(dr.mail, ""), c.addr.String()) || b.has("peers/"+c.addr.String()) {
		t.Errorf("a second signed envelope after the first one's signature: %v", dr)
	}
	for _, parts := range [][][]byte{{[]byte("\n"), fromA, fromASig}, {fromA, []byte("\n"), fromASig}, {fromA}} {
		w.inject(b, "", parts...)
	}
	refusals += 3
	if dr := b.recv(); len(dr.mail) != 0 || dr.refused("bad_message") != 3 || !strings.Contains(dr.said, "bad_message: what was decrypted is not an envelope line and then a signature block") {
		t.Errorf("a line before the envelope, a blank line before the signature, or no signature: %v", dr)
	}
	// The two refusals of A's genuine ciphertext share its hash, so one file.
	q, _ := filepath.Glob(b.file("refused/*.json"))
	reasons, _ := filepath.Glob(b.file("refused/*.reason"))
	if len(q) != refusals-1 || len(reasons) != refusals-1 || len(b.files("inbox")) != 3 {
		t.Errorf("not every refusal kept in refused/ with its reason, or one delivered: %d refusals, %d kept in refused/, %d reasons, inbox %q", refusals, len(q), len(reasons), b.files("inbox"))
	}
	// Each keeps the ciphertext and the id the script hashed, and none of
	// the server's strings (dr_kept; #454 item 1).
	for _, f := range q {
		var kept map[string]any
		if err := protocol.Unmarshal(mustRead(t, f), &kept); err != nil || !slices.Equal(slices.Sorted(maps.Keys(kept)), []string{"ciphertext", "id"}) {
			t.Errorf("refused/%s keeps the members %v, want ciphertext and id alone: %v", filepath.Base(f), slices.Sorted(maps.Keys(kept)), err)
		}
	}
	for _, f := range reasons {
		code, _, _ := strings.Cut(mustReadString(t, f), ": ")
		if !slices.Contains([]string{"bad_identity", "bad_message", "bad_signature", "reattributed", "replay", "bad_id", "stale", "bad_envelope"}, code) {
			t.Errorf("%s: %q is no code", f, code)
		}
	}
	// A listed from of A's address and a line feed is never read, and a
	// listed id with a line feed added is compared in jq, never through a
	// shell variable, which drops it.
	lf := a.line(b.addr, "77777777-2222-4333-8444-555555555551", "a from with a line feed", 0)
	w.inject(b, "", lf, a.sign(b.addr, lf))
	w.listing(func(l *forge.Listed) { l.Messages[0].From = a.addr.String() + "\n" })
	if dr := b.recv(); !slices.Equal(dr.bodies(), []string{"a from with a line feed"}) || w.srv.Count(b.addr) != 0 {
		t.Errorf("A's message under a from with a line feed: %v", dr)
	}
	lfid := a.line(b.addr, "77777777-2222-4333-8444-555555555552", "an id with a line feed", 0)
	w.inject(b, "", lfid, a.sign(b.addr, lfid))
	w.listing(func(l *forge.Listed) { l.Messages[0].ID += "\n" })
	if dr := b.recv(); len(dr.mail) != 0 || w.srv.Count(b.addr) != 1 {
		t.Errorf("a listed id with a line feed added was fetched as the id it was cut to: %v", dr)
	}
	w.honest()
	b.recv()
	// A body with the line breaks some readers split on, raw: still one line.
	seps := "a\u0085b c d"
	a.mustSend(b, seps)
	dr := b.recv()
	if len(dr.mail) != 1 || strings.Count(dr.mail[0], "\n") != 1 || strings.ContainsAny(dr.mail[0], "\u0085  ") || !slices.Equal(dr.bodies(), []string{seps}) {
		t.Errorf("U+0085, U+2028 and U+2029 in a body: %v", dr)
	}
}

// jsonLine reads one line of JSON into v.
func jsonLine(s string, v any) error { return json.Unmarshal([]byte(s), v) }

func mustReadString(t *testing.T, name string) string { return string(mustRead(t, name)) }

// b64 is s in standard base64, as a byte member carries it.
func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

// keyOf is a prekey statement's key, its fourth line.
func keyOf(st string) string { return strings.Split(st, "\n")[3] }

// withLine is a text with its line n, from 1, replaced.
func withLine(s []byte, n int, l string) []byte {
	ls := strings.Split(string(s), "\n")
	ls[n-1] = l
	return []byte(strings.Join(ls, "\n"))
}

// stmt is a prekey statement and its signature.
type stmt struct{ st, sig []byte }

// prekey is box b's statement as the server holds it.
func (w *world) prekey(b *sbox) stmt {
	st, sig := w.srv.Prekey(b.addr)
	return stmt{st, sig}
}

// statement is a prekey statement for box b, at serial, for key, until
// notAfter, signed with the key file signer as ssh-keygen signs one.
func (w *world) statement(b *sbox, serial uint64, key, notAfter, signer string) stmt {
	w.t.Helper()
	st := fmt.Appendf(nil, "dromas-prekey-v1\n%s\n%d\n%s\n%s\n", b.addr, serial, key, notAfter)
	f := filepath.Join(w.t.TempDir(), "st")
	if err := os.WriteFile(f, st, 0o600); err != nil {
		w.t.Fatal(err)
	}
	sig := []byte((&sbox{w: w, dir: w.work}).must(fmt.Sprintf("ssh-keygen -q -Y sign -n dromas-prekey-v1:%s -f %s < %s", b.addr, signer, f)))
	return stmt{st, sig}
}

// serving serves box b's read with the statement given in place of its own.
func (w *world) serving(b *sbox, s stmt) {
	w.reading(b.addr, func(br *protocol.BoxResponse) { br.Prekey, br.PrekeySignature = s.st, s.sig })
}

// The sender's checks: what a box is served is checked before anything is
// encrypted, and what fails one sends nothing and keeps nothing.
func TestScriptChecksTheBoxItIsServed(t *testing.T) {
	w := newWorld(t)
	a, b, c, d := w.box(), w.box(), w.box(), w.box()
	op := w.operator()
	a.mustSend(b, "pins B")
	b1 := b.num()
	refused := func(what string, s *sbox, to string, want string) {
		t.Helper()
		n := len(w.srv.Requests())
		r := s.send(to, "secret")
		for _, c := range w.calls(n) {
			if strings.HasPrefix(c, "POST ") {
				t.Errorf("%s: posted", what)
			}
		}
		if r.rc == 0 || !strings.Contains(r.err, want) || !s.bare() || s.has("seal.age") || s.has("seal.query") {
			t.Errorf("%s: %v", what, r)
		}
	}
	st, _ := w.srv.Prekey(b.addr)
	w.reading(b.addr, func(br *protocol.BoxResponse) { br.Prekey = withLine(br.Prekey, 4, op.recipient()) })
	refused("the operator swaps B's prekey", a, b.addr.String(), "not signed by a working key its identity certified")
	w.honest()
	if r := a.send(b.addr.String(), "bad \xff byte"); r.rc == 0 || !strings.Contains(r.err, "not UTF-8") || !a.bare() || w.posts(b.addr) != 1 {
		t.Errorf("a body that is not UTF-8: %v", r)
	}
	// First contact, the recipient's identity forged by the server: the
	// operator's, with a statement its own working key signed for C's address.
	opSt := w.statement(c, 99, op.recipient(), notAfter(), filepath.Join(op.dir, "work-cert.pub"))
	opDoc := mustRead(t, filepath.Join(op.dir, "identity.doc"))
	w.reading(c.addr, func(br *protocol.BoxResponse) { br.Identity, br.Prekey, br.PrekeySignature = opDoc, opSt.st, opSt.sig })
	refused("first contact, a server-forged identity for the recipient", d, c.addr.String(), "does not hash")
	if d.has("peers/" + c.addr.String()) {
		t.Error("the forged identity was pinned")
	}
	// A key holder's padded identity document hashes to its own address: an
	// operator that serves it as a box is refused it, so one key never gets a
	// second address.
	e := &sbox{w: w, dir: filepath.Join(w.work, "E")}
	e.must(`mkdir -p "$DR"; cd "$DR"; ssh-keygen -q -t ed25519 -N '' -C '' -f identity; printf 'dromas-v1\n%s\n \n' "$(cut -d' ' -f1,2 identity.pub)" > identity.doc; sha256sum < identity.doc | cut -c1-64 > address
ssh-keygen -q -t ed25519 -N '' -C '' -f work; ssh-keygen -q -s identity -I dromas-cert-v1 -n "$(cat address)" -z 1 -V "$(date -u -d '1 hour ago' +%Y%m%d%H%M%SZ):$(date -u -d '64 days' +%Y%m%d%H%M%SZ)" -O clear work.pub
age-keygen -o agekey 2> /dev/null`)
	e.addr = mustAddress(t, e.dir)
	eSt := w.statement(e, 1, strings.TrimSpace(e.must(`age-keygen -y "$DR/agekey"`)), notAfter(), e.file("work-cert.pub"))
	eDoc := []byte(e.read("identity.doc"))
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == e.addr {
			fakeserver.WriteJSON(rw, http.StatusOK, protocol.BoxResponse{Identity: eDoc, Prekey: eSt.st, PrekeySignature: eSt.sig})
			return
		}
		next.ServeHTTP(rw, r)
	})
	refused("a padded identity document that hashes to its own address", a, e.addr.String(), "not a two-line identity document")
	if a.has("peers/" + e.addr.String()) {
		t.Error("the padded identity was pinned")
	}
	// What a thief of B's working key in use could sign, with the server's help.
	bw := b.file(fmt.Sprintf("work/%d-cert.pub", b1))
	key := keyOf(string(st))
	for _, c := range []struct{ what, notAfter, signer, want string }{
		{"an expired prekey, validly signed, at a higher serial", "2020-01-01T00:00:00Z", bw, "expired"},
		{"a not_after of never", "never", bw, "no valid not_after"},
		{"a statement the identity itself signed, with no certificate", notAfter(), b.file("identity"), "not signed by a working key its identity certified"},
	} {
		w.serving(b, w.statement(b, b1+9, key, c.notAfter, c.signer))
		refused(c.what, a, b.addr.String(), c.want)
		if s := strings.TrimSpace(a.read("peers/" + b.addr.String() + "/serial")); s != fmt.Sprint(b1) {
			t.Errorf("%s: its serial was recorded, %s", c.what, s)
		}
	}
	// An age recipient of a type nobody defines: a published test key.
	other := keyOf(mustReadString(t, filepath.Join(vectors, "prekey", "unsupported-type.txt")))
	w.serving(b, w.statement(b, b1+9, other, notAfter(), bw))
	want := fmt.Sprintf(`{"type":"error","code":"unsupported_prekey_type","message":"REFUSED: %s's prekey is an age recipient of a type this script cannot encrypt to, so nothing is sent"}`+"\n", b.addr)
	refused("a prekey of a type nobody defines", a, b.addr.String(), want)
	if a.read("peers/"+b.addr.String()+"/serial") != fmt.Sprintln(b1) {
		t.Error("a prekey of a type nobody defines was recorded")
	}
}

// notAfter is a prekey's not_after 33 days out, the most a server takes.
func notAfter() string { return time.Now().Add(33 * 24 * time.Hour).UTC().Format(protocol.TimeLayout) }

// A send the server refuses or fails says so and keeps nothing to post
// again; a server's word that a box is revoked, with nothing shown, revokes
// nothing; the same send run again goes.
func TestScriptKeepsNothingOfAFailedSend(t *testing.T) {
	w := newWorld(t)
	a, b := w.box(), w.box()
	for _, c := range []struct {
		code protocol.Code
		want string
	}{
		{protocol.CodeTooLarge, "nothing is sent"},
		{protocol.CodeRevoked, "showed no revocation that verifies"},
		{protocol.CodeUnavailable, "nothing is sent"},
	} {
		w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodPost {
				forge.Refuse(rw, c.code)
				return
			}
			next.ServeHTTP(rw, r)
		})
		if r := a.send(b.addr.String(), "secret"); r.rc == 0 || !strings.Contains(r.err, c.want) || !a.bare() || w.srv.Count(b.addr) != 0 || a.has("peers/"+b.addr.String()+"/revoke.sig") {
			t.Errorf("a post answered %s: %v", c.code, r)
		}
	}
	w.honest()
	a.mustSend(b, "secret")
	if w.srv.Count(b.addr) != 1 {
		t.Error("the same send run again did not go")
	}
}
