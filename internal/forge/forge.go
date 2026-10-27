// Package forge is how a test plays the hostile operator in front of
// internal/fakeserver: a read of a box served otherwise than the server holds
// it, mail put in a box as only the operator can, a call answered as a server
// that is down. The Go client's tests and the script's share it, so each
// forgery is written once, as an operator could make it.
package forge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
	"golang.org/x/crypto/ssh"
)

// ReadOf reports whether r is a read of a box, GET /v1/<address>, and of
// which box.
func ReadOf(r *http.Request) (protocol.Address, bool) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/v1/")
	if !ok || r.Method != http.MethodGet || strings.Contains(rest, "/") {
		return protocol.Address{}, false
	}
	a, err := protocol.ParseAddress(rest)
	return a, err == nil
}

// Serve answers r, a read of a box, with the box s holds, edited first: an
// operator that serves a box otherwise than it holds it. A revoked box is
// served as it was before, from its last prekey, with none of what its
// identity signed about it, so edit can make it look like any box.
func Serve(t testing.TB, s *fakeserver.Server, w http.ResponseWriter, r *http.Request, next http.Handler, edit func(*protocol.BoxResponse)) {
	t.Helper()
	a, _ := ReadOf(r)
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, r)
	var br protocol.BoxResponse
	var p protocol.Problem
	switch {
	case rec.Code == http.StatusOK && protocol.Unmarshal(rec.Body.Bytes(), &br) == nil:
	case rec.Code == http.StatusGone && protocol.Unmarshal(rec.Body.Bytes(), &p) == nil && p.Record != nil:
		br.Identity = p.Record.Identity
		br.Prekey, br.PrekeySignature = s.Prekey(a)
	default:
		t.Fatalf("an operator edits the read of a box, and the server answered %d", rec.Code)
	}
	edit(&br)
	fakeserver.WriteJSON(w, http.StatusOK, br)
}

// Carry answers r as next answers it, but that a 410 revoked carries rec in
// place of the record its server holds, or none for nil: an operator that
// says an address is revoked and shows another record, or none.
func Carry(w http.ResponseWriter, r *http.Request, next http.Handler, rec *protocol.Revocations) {
	got := httptest.NewRecorder()
	next.ServeHTTP(got, r)
	if got.Code == http.StatusGone {
		Refuse(w, protocol.CodeRevoked, func(p *protocol.Problem) { p.Record = rec })
		return
	}
	for k, v := range got.Header() {
		w.Header()[k] = v
	}
	w.WriteHeader(got.Code)
	_, _ = w.Write(got.Body.Bytes())
}

// Hides puts an operator in front of s that serves every box without what
// its identity signed about it: a revoked box as if it were not, and no
// revocation of a box's certificates.
func Hides(t testing.TB, s *fakeserver.Server) {
	s.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if _, ok := ReadOf(r); !ok {
			next.ServeHTTP(w, r)
			return
		}
		Serve(t, s, w, r, next, func(br *protocol.BoxResponse) { br.RevokedCertificates, br.RevokedCertificatesSignature = nil, nil })
	})
}

// Capture records the body of the next request to s matching method and
// path suffix: JSON, or a send's ciphertext.
func Capture(s *fakeserver.Server, method, suffix string) *[]byte {
	var got []byte
	s.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == method && strings.HasSuffix(r.URL.Path, suffix) && got == nil {
			got, _ = io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(got))
		}
		next.ServeHTTP(w, r)
	})
	return &got
}

// FailOnce answers the first request to s matching method and path suffix
// with a 503, as a server that is down would.
func FailOnce(s *fakeserver.Server, method, suffix string) {
	failed := false
	s.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == method && strings.HasSuffix(r.URL.Path, suffix) && !failed {
			failed = true
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Refuse answers as the server refuses a call, with code under its own
// status and type; each of with sets a member it carries.
func Refuse(w http.ResponseWriter, code protocol.Code, with ...func(*protocol.Problem)) {
	p := protocol.Problem{Type: code.TypeURI(), Title: code.Title(), Status: int64(code.Status()), Code: code, Detail: "forged by the test"}
	for _, set := range with {
		set(&p)
	}
	w.Header().Set("Content-Type", protocol.ProblemContentType)
	w.WriteHeader(code.Status())
	_ = json.NewEncoder(w).Encode(p)
}

// Line is an envelope's line as a sender writes it: from the box whose
// identity document it carries, to a box, sent at at.
func Line(t testing.TB, doc []byte, from, to protocol.Address, body string, at time.Time) []byte {
	t.Helper()
	env, err := protocol.NewEnvelope(from, to, body, at)
	if err != nil {
		t.Fatal(err)
	}
	env.Identity = doc
	l, err := env.Line()
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// Sign signs an envelope's line for a recipient, as the stock tools do.
func Sign(t testing.TB, s ssh.Signer, line []byte, to protocol.Address) []byte {
	t.Helper()
	sig, err := protocol.Sign(s, line, protocol.MessageNamespace(to))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// Encrypt encrypts the parts, one after the other, to a box's current
// prekey as s holds it.
func Encrypt(t testing.TB, s *fakeserver.Server, to protocol.Address, parts ...[]byte) []byte {
	t.Helper()
	st, _ := s.Prekey(to)
	p, err := protocol.ParsePrekey(st)
	if err != nil {
		t.Fatal(err)
	}
	r, err := p.Recipient()
	if err != nil {
		t.Fatal(err)
	}
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range parts {
		if _, err := w.Write(part); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return ct.Bytes()
}

// Seal encrypts what a sender encrypts, an envelope's line and then whatever
// follows it, to a box's current prekey as s holds it, and stores it in that
// box, as only the operator can. It returns the id it is stored under: the
// hash of the ciphertext.
func Seal(t testing.TB, s *fakeserver.Server, to protocol.Address, plaintext ...[]byte) string {
	t.Helper()
	ct := Encrypt(t, s, to, plaintext...)
	h := sha256.Sum256(ct)
	id := hex.EncodeToString(h[:])
	s.Inject(to, id, ct)
	return id
}

// Listed is a list as an operator writes it: the members PROTOCOL.md §11.11
// gives one, and a from beside each entry, which it gives none and a reader
// ignores, as it does every member it does not know (§3.3).
type Listed struct {
	Count      int64         `json:"count"`
	Messages   []ListedEntry `json:"messages"`
	NextCursor *string       `json:"next_cursor"`
}

// ListedEntry is one entry of a Listed: its members, and a from of any
// value, written only when it is set.
type ListedEntry struct {
	protocol.MessageInfo
	From any `json:"from,omitempty"`
}

// List answers r, a box's list, with each page it answers edited first, and
// any other request as next does: an operator's own list, a from beside each
// entry among what it can write.
func List(t testing.TB, w http.ResponseWriter, r *http.Request, next http.Handler, edit func(*Listed)) {
	if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/messages") {
		next.ServeHTTP(w, r)
		return
	}
	rec := httptest.NewRecorder()
	next.ServeHTTP(rec, r)
	for k, v := range rec.Header() {
		if k != "Content-Length" {
			w.Header()[k] = v
		}
	}
	var l protocol.MessageList
	if rec.Code != http.StatusOK {
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
		return
	}
	if err := protocol.Unmarshal(rec.Body.Bytes(), &l); err != nil {
		t.Errorf("an operator edits a list, and the server's is none: %v", err)
		return
	}
	listed := Listed{Count: l.Count, NextCursor: l.NextCursor, Messages: make([]ListedEntry, len(l.Messages))}
	for i, m := range l.Messages {
		listed.Messages[i].MessageInfo = m
	}
	edit(&listed)
	fakeserver.WriteJSON(w, http.StatusOK, listed)
}

// Lists has s answer every list with it edited first (List).
func Lists(t testing.TB, s *fakeserver.Server, edit func(*Listed)) {
	s.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) { List(t, w, r, next, edit) })
}
