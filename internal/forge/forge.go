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
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
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
// box as mail from a sender, as only the operator can. It returns the id it
// is stored under: the hash of the ciphertext.
func Seal(t testing.TB, s *fakeserver.Server, to, from protocol.Address, plaintext ...[]byte) string {
	t.Helper()
	ct := Encrypt(t, s, to, plaintext...)
	h := sha256.Sum256(ct)
	id := hex.EncodeToString(h[:])
	s.Inject(to, id, from, ct)
	return id
}
