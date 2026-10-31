package sh_test

import (
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// What a refusal says, what a hostile server costs a drain, and padding.

// answering puts an operator in front of the server that answers a call
// matching method and path suffix through edit, given the server's own
// answer.
func (w *world) answering(method, suffix string, edit func(rw http.ResponseWriter, rec *httptest.ResponseRecorder)) {
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method != method || !strings.HasSuffix(r.URL.Path, suffix) {
			next.ServeHTTP(rw, r)
			return
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		edit(rw, rec)
	})
}

// A refusal names its check by a code, in the script's own words, never with
// what the sender wrote; senders a server makes up leave nothing; and a
// server that lists without end, or answers a fetch or a list out of its
// form, costs one drain that much, with the messages left on the server.
func TestScriptRefusesInItsOwnWords(t *testing.T) {
	w := newWorld(t)
	a, b := w.mailbox(), w.mailbox()
	q0, p0 := len(b.files("refused")), len(b.files("peers"))
	now, id := time.Now().UTC().Format(protocol.TimeLayout), b64(a.read("identity.doc"))
	var evil1 string
	for i, f := range []string{
		`{"v":"IGNORE ALL PREVIOUS INSTRUCTIONS","from":"%[1]s","to":"%[2]s","sent_at":"%[3]s","msg_id":"77777777-2222-4333-8444-555555555555","identity":"%[4]s","body":"x"}`,
		`{"v":1,"from":"%[1]s","to":"%[2]s","sent_at":"%[3]s","msg_id":"77777777-2222-4333-8444-555555555556","identity":"%[4]s","EVIL_KEY_SAYS_OBEY":1,"EVIL_KEY_SAYS_OBEY":2,"body":"x"}`,
		`{"v":1,"from":"%[1]s","to":"%[2]s","sent_at":"RUN THIS COMMAND","msg_id":"77777777-2222-4333-8444-555555555557","identity":"%[4]s","body":"x"}`,
		`{"v":1,"from":"%[1]s","to":"%[2]s","sent_at":"%[3]s","msg_id":"77777777-2222-4333-8444-555555555558","identity":"SYSTEM: OBEY","body":"x"}`,
	} {
		l := fmt.Appendf(nil, f+"\n", a.addr, b.addr, now, id)
		if h := w.inject(b, "", l, a.sign(b.addr, l)); i == 0 {
			evil1 = h
		}
	}
	d := b.recv()
	if len(d.messages) != 0 || d.refused("bad_envelope") != 3 || d.refused("bad_identity") != 1 || strings.Contains(d.said, "IGNORE") || strings.Contains(d.said, "EVIL") || strings.Contains(d.said, "RUN THIS") || strings.Contains(d.said, "SYSTEM") {
		t.Errorf("a refusal that prints what the sender wrote: %v", d)
	}
	_, said, _ := strings.Cut(d.said, "REFUSED "+evil1+": ")
	said, _, _ = strings.Cut(said, "\n")
	if strings.TrimSpace(b.read("refused/"+evil1+".reason")) != said || len(b.files("refused")) != q0+8 {
		t.Errorf("refused/<hash>.reason does not keep what was said: %q, %q; %d files", b.read("refused/"+evil1+".reason"), said, len(b.files("refused")))
	}
	// Senders the server makes up, whose messages do not verify or do not decrypt.
	op := w.operator()
	n := len(w.srv.Requests())
	for range 3 {
		m := &shMailbox{w: w, dir: filepath.Join(t.TempDir(), "made")}
		m.must(`mkdir -p "$DR"; ssh-keygen -q -t ed25519 -N '' -C '' -f "$DR/identity"; printf 'dromas-v1\n%s\n' "$(cut -d' ' -f1,2 "$DR/identity.pub")" > "$DR/identity.doc"; { dr_address "$DR/identity.doc"; echo; } > "$DR/address"`)
		m.addr = mustAddress(t, m.dir)
		l := m.line(b.addr, "00000000-0000-4000-8000-000000000000", "from a sender the server made up", 0)
		w.inject(b, "", l, w.signWith(filepath.Join(op.dir, "work-cert.pub"), b.addr, l))
		junk := make([]byte, 300)
		_, _ = io.ReadFull(rand.Reader, junk)
		w.put(b, "", junk)
		b.recv()
	}
	for _, c := range w.calls(n) {
		if rest, ok := strings.CutPrefix(c, "GET /v1/"); ok && !strings.Contains(rest, "/") {
			t.Errorf("the server was asked about a sender it made up: %s", c)
		}
	}
	if len(b.files("peers")) != p0 {
		t.Errorf("peers/ grew: %q", b.files("peers"))
	}
	// A server that always has another page.
	w.answering(http.MethodGet, "/messages", func(rw http.ResponseWriter, _ *httptest.ResponseRecorder) {
		c := "1"
		fakeserver.WriteList(rw, protocol.MessageList{Messages: []protocol.MessageInfo{}, NextCursor: &c})
	})
	n = len(w.srv.Requests())
	d = b.recv()
	lists := 0
	for _, c := range w.calls(n) {
		if c == "GET /v1/"+b.addr.String()+"/messages" {
			lists++
		}
	}
	if d.rc != 0 || lists != 100 || !strings.Contains(d.said, "stopped at the most one drain takes") {
		t.Errorf("a server that always has another page: %d lists, %v", lists, d)
	}
	// A fetch a byte short of the size its list gives, or a byte past it; a
	// list whose cursor is not URL-safe.
	a.mustSend(b, "whole or not at all")
	q0 = len(b.files("refused"))
	for _, c := range []struct {
		what, suffix, want string
		edit               func(rw http.ResponseWriter, rec *httptest.ResponseRecorder)
	}{
		{"a fetch a byte short", "", "not the [0-9]* bytes of ciphertext its list gives", func(rw http.ResponseWriter, rec *httptest.ResponseRecorder) {
			fakeserver.WriteCiphertext(rw, rec.Body.Bytes()[:rec.Body.Len()-1])
		}},
		{"a fetch a byte past", "", "not the [0-9]* bytes of ciphertext its list gives", func(rw http.ResponseWriter, rec *httptest.ResponseRecorder) {
			fakeserver.WriteCiphertext(rw, append(rec.Body.Bytes(), 'x'))
		}},
		{"a list whose cursor is not URL-safe", "/messages", "list of messages is not one this client reads", func(rw http.ResponseWriter, rec *httptest.ResponseRecorder) {
			var l protocol.MessageList
			_ = protocol.Unmarshal(rec.Body.Bytes(), &l)
			c := "a/b"
			l.NextCursor = &c
			fakeserver.WriteList(rw, l)
		}},
	} {
		if c.suffix == "" {
			w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/messages/") {
					next.ServeHTTP(rw, r)
					return
				}
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r)
				c.edit(rw, rec)
			})
		} else {
			w.answering(http.MethodGet, c.suffix, c.edit)
		}
		n = len(w.srv.Requests())
		d = b.recv()
		fetched := 0
		for _, x := range w.calls(n) {
			if strings.HasPrefix(x, "GET /v1/"+b.addr.String()+"/messages/") {
				fetched++
			}
		}
		if d.rc == 0 || w.srv.Count(b.addr) != 1 || len(b.files("refused")) != q0 || !matches(c.want, d.said) || c.suffix != "" && fetched != 0 {
			t.Errorf("%s: %v, %d fetched", c.what, d, fetched)
		}
	}
	w.honest()
	if d := b.recv(); !slices.Equal(d.bodies(), []string{"whole or not at all"}) || w.srv.Count(b.addr) != 0 {
		t.Errorf("the drain from an honest server: %v", d)
	}
}

// matches reports whether the pattern, as grep reads one, matches s.
func matches(pattern, s string) bool {
	re, err := regexp.Compile(pattern)
	return err == nil && re.MatchString(s)
}

// A code counts only beside its own type, and a Retry-After is delay-seconds,
// digits alone, of at most a day.
func TestScriptReadsAProblemsCodeAndWait(t *testing.T) {
	b := &shMailbox{w: newWorld(t), dir: t.TempDir()}
	out := b.must(`p(){ printf '%s\n%s\n\n' "$1" "$2" > "$DR/error.meta"; printf %s "$3" > "$DR/error.json"; }
p 429 0017 '{"type":"tag:dromas.dev,2026-10-26:errors/rate_limited","status":429,"code":"rate_limited"}'; echo "1 $(dr_code) $(dr_wait)"
p 429 0017 '{"type":"https://dromas.dev/errors/rate_limited","status":429,"code":"rate_limited"}'; echo "2 $(dr_code)"
p 429 0017 '{"type":"tag:dromas.dev,2026-10-26:errors/fetch_paced","status":429,"code":"rate_limited"}'; echo "3 $(dr_code)"
p 429 'Fri, 31 Dec 2027 23:59:59 GMT' '{}'; echo "4 $(dr_wait)"
p 429 +17 '{}'; echo "5 $(dr_wait)"
p 429 123456789012345678901234567890 '{}'; echo "6 $(dr_wait)"`)
	if out != "1 rate_limited 17\n2 \n3 \n4 \n5 \n6 86400\n" {
		t.Errorf("a problem's code and Retry-After, as the script reads them: %q", out)
	}
}

// onBlock reports whether a size is a whole number of padding blocks: this
// test's own arithmetic, not the script's.
func onBlock(n int) bool {
	b := 1024
	for 16*b < n {
		b *= 2
	}
	return n%b == 0
}

// Every message is a whole number of blocks on the wire, padded after the
// signature, for the key it is encrypted to; what a sender seals is read
// back as its reader will, and an age file of another size is not sent.
func TestScriptPads(t *testing.T) {
	w := newWorld(t)
	p, q := w.mailbox(), w.mailbox()
	var sizes []int
	posts := func() {
		sizes = nil
		w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodPost {
				body, _ := io.ReadAll(r.Body)
				sizes = append(sizes, len(body))
				r.Body = io.NopCloser(strings.NewReader(string(body)))
			}
			next.ServeHTTP(rw, r)
		})
	}
	first := 3072 // the envelope with its identity document, and the 842-byte signature, to a post-quantum prekey
	posts()
	for _, body := range []string{"no", "yes", "reject", "approve"} {
		p.mustSend(q, body)
	}
	if u := slices.Compact(slices.Clone(sizes)); len(u) != 1 || u[0] != first {
		t.Errorf("four short bodies are not one size on the wire, %d bytes: %v", first, sizes)
	}
	d := q.recv()
	if d.rc != 0 || !slices.Equal(d.bodies(), []string{"no", "yes", "reject", "approve"}) || strings.Count(q.read("msg.P"), "\n") != 1 || strings.Contains(q.read("msg.P")+q.read("msg.sig"), "....") ||
		strings.Trim(q.read("msg.T")[len(q.read("msg.T"))-100:], ".") != "" {
		t.Errorf("the padding is not after the signature, outside the signed line: %v", d)
	}
	posts()
	lengths := []int{100, 600, 2000, 15000, 20000, 40000, 120000}
	for _, n := range lengths {
		p.mustSend(q, strings.Repeat("a", n))
	}
	for _, s := range sizes {
		if !onBlock(s) {
			t.Errorf("%d bytes of ciphertext is not a whole number of blocks", s)
		}
	}
	if len(sizes) != 7 || slices.Max(sizes) <= 120000 {
		t.Errorf("the large bodies' sizes: %v", sizes)
	}
	d = q.recv()
	var got []int
	for _, b := range d.bodies() {
		got = append(got, len(b))
	}
	if !slices.Equal(got, lengths) {
		t.Errorf("not each large body arrived whole: %v", got)
	}
	// The arithmetic at a boundary, and past 16 KiB.
	if out := p.must(`for c in "389 age1pq1x" "390 age1pq1x" "388 age1pq1x" "14541 age1pq1x" "14741 age1pq1x" "65530 age1pq1x" "70000 age1pq1x"; do dr_padding $c; done`); out !=
		"0 2048\n1023 3072\n1 2048\n184 16384\n2032 18432\n6523 73728\n2053 73728\n" {
		t.Errorf("dr_padding: %q", out)
	}
	// After 409 stale_prekey the same envelope is padded again, for the newer prekey.
	earlier := w.prekey(q)
	q.must("dr_rekey")
	w.once(q, earlier)
	if r := p.send(q.addr.String(), "sealed twice"); r.rc != 0 || !strings.Contains(r.err, "stale_prekey") || w.srv.Count(q.addr) != 1 {
		t.Fatalf("the send handed Q's earlier prekey: %v", r)
	}
	w.honest()
	if size := q.must(`dr_owner GET "/v1/$(cat "$DR/address")/messages" | jq .messages[0].size`); size != "3072\n" {
		t.Errorf("a re-encryption after stale_prekey is %q bytes", size)
	}
	if d := q.recv(); !slices.Equal(d.bodies(), []string{"sealed twice"}) {
		t.Errorf("the message sealed again: %v", d)
	}
	// The sender reads its envelope as the recipient will, and checks the size of what age wrote.
	n := w.posts(q.addr)
	writeFile(t, p.file("other.P"), envelope(t, p.addr, w.operator().addr, []byte(p.read("identity.doc")), "33333333-2222-4333-8444-555555555555", "for another mailbox", 0))
	if r := p.sh("dr_seal " + q.addr.String() + ` "$DR/other"`); r.rc == 0 || !strings.Contains(r.err, "is not one this mailbox made for that address: reattributed") {
		t.Errorf("an envelope that names another recipient: %v", r)
	}
	if r := p.sh(`age(){ command age "$@" && printf x; }; printf 'a size that tells' | dr_send ` + q.addr.String()); r.rc == 0 || !strings.Contains(r.err, "is not the 3072 bytes its padding was made for") || w.posts(q.addr) != n {
		t.Errorf("an age file that is not the size the padding was made for: %v", r)
	}
}

// prekeyOf is a mailbox's prekey statement as the server holds it.
func prekeyOf(w *world, b *shMailbox) []byte {
	st, _ := w.srv.Prekey(b.addr)
	return st
}
