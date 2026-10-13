package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// TestForgeries plays the operator, who controls every byte the server sends
// and stores. Each forgery must be refused by the client: never delivered,
// never encrypted to, never pinned. Refused mail is quarantined and acked, so
// it leaves the server, and the refusal never blocks the claimed sender.
//
//	a sender the server relabels          A's message listed as C's            → refused: C did not sign it
//	a from that is not an address         the server's from is a path          → refused, and nothing is named by it
//	mail made in another box's name       O signs an envelope carrying A's identity → refused: not under a certificate of A's identity
//	a second message after the signature  C's signed envelope in the padding   → A's is delivered, and nothing after its signature is read
//	a forged identity on a send           C's identity served as B's           → the send refuses, nothing pinned
//	swapped prekey                        C's valid prekey served as B's       → the send refuses to encrypt
//	an expired prekey                     B's prekey past its not_after        → the send refuses to encrypt
//	rollback of a peer's prekey           B's older prekey served again        → the send refuses (serial went down)
//	a stolen working key, replaced since  a new prekey under B's old certificate → the send refuses (certificate serial went down)
//	rollback of the box's own prekey      the box's own older prekey served    → rekey refuses (it published a higher one)
//	replay under a new id                 a delivered ciphertext, stored again → refused as a replay
//	sent_at older than 33 days            an envelope dated 33 days and 1 s ago → refused as stale
//	not encrypted to this box             A's message to C, stored in B's box  → refused: it does not decrypt
//	an id that is not the hash            a message listed under another id    → refused; files are named by the hash
func TestForgeries(t *testing.T) {
	ctx := context.Background()
	refusedFor := func(t *testing.T, res *client.Result, code, why string) {
		t.Helper()
		if len(res.Delivered) != 0 || len(res.Refused) != 1 || res.Refused[0].Code != code || !strings.Contains(res.Refused[0].Reason, why) {
			t.Fatalf("delivered %d, refused %v; want refused as %s for %q", len(res.Delivered), res.Refused, code, why)
		}
	}
	// relabel makes the server say every message in b's box is from another
	// sender: it rewrites the list and the fetch.
	relabel := func(e *env, was, now string) {
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/messages") {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(bytes.ReplaceAll(rec.Body.Bytes(), []byte(was), []byte(now)))
		})
	}

	t.Run("a sender the server relabels", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "from A")
		relabel(e, a.Address().String(), c.Address().String())
		res := receive(t, b)
		refusedFor(t, res, protocol.RefusedAttribution, "another box than the one that signed")
		if !exists(filepath.Join(b.Dir(), "quarantine", res.Refused[0].ID+".json")) {
			t.Fatal("not quarantined")
		}
		if e.srv.Count(b.Address()) != 0 {
			t.Fatal("refused mail was not acked")
		}
		if exists(filepath.Join(b.Dir(), "peers", c.Address().String())) {
			t.Fatal("the box the server named was pinned")
		}
	})

	t.Run("a from that is not an address", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "hi")
		relabel(e, a.Address().String(), "../../"+strings.Repeat("x", 58))
		refusedFor(t, receive(t, b), protocol.RefusedAttribution, "another box than the one that signed")
		if names, _ := filepath.Glob(filepath.Join(b.Dir(), "peers", "*")); len(names) != 0 {
			t.Fatalf("something was kept under peers/: %v", names)
		}
	})

	t.Run("mail made in another box's name", func(t *testing.T) {
		e := newEnv(t)
		a, b, o := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		// The forger's own working key and certificate sign an envelope that
		// carries A's identity document and says it is from A. The signature
		// is good. The certificate is the forger's.
		line := e.line(a.Identity().Document(), a.Address(), b.Address(), "from A, says the forger")
		e.seal(b, a.Address(), line, sign(t, worker(t, o), line, b.Address()))
		refusedFor(t, receive(t, b), protocol.RefusedSignature, "not signed under a certificate of the sender's identity")
		if exists(filepath.Join(b.Dir(), "peers", a.Address().String())) {
			t.Fatal("a sender whose signature did not verify was pinned")
		}
	})

	t.Run("a second message after the signature", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		genuine := e.line(a.Identity().Document(), a.Address(), b.Address(), "real, from A")
		hidden := e.line(c.Identity().Document(), c.Address(), b.Address(), "hidden, from C")
		id := e.seal(b, a.Address(), genuine, sign(t, worker(t, a), genuine, b.Address()), hidden, sign(t, worker(t, c), hidden, b.Address()))
		res := receive(t, b)
		if len(res.Delivered) != 1 {
			t.Fatalf("delivered %d, refused %v", len(res.Delivered), res.Refused)
		}
		d := res.Delivered[0]
		if d.ID != id || d.Envelope.From != a.Address() || bodyOf(t, d) != "real, from A" || !bytes.Equal(d.Plaintext, genuine) {
			t.Fatalf("what was delivered is not A's message: %s", d.Line)
		}
		if bytes.Contains(d.Line, []byte("\n")) || bytes.Contains(d.Line, []byte(c.Address().String())) || bytes.Contains(d.Line, []byte("identity")) {
			t.Fatalf("the line to print is not the checked envelope alone: %s", d.Line)
		}
		if in, _ := os.ReadFile(filepath.Join(b.Dir(), "inbox", d.ID+".json")); !bytes.Equal(in, d.Line) {
			t.Fatal("inbox/ does not hold the checked line")
		}
		if exists(filepath.Join(b.Dir(), "peers", c.Address().String())) {
			t.Fatal("the sender hidden after the signature was pinned")
		}
	})

	t.Run("a forged identity on a send", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		st, sig := e.srv.Prekey(c.Address())
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Path == "/v1/"+b.Address().String()+"/identity" {
				fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: c.Identity().Document(), Prekey: st, PrekeySignature: sig})
				return
			}
			next.ServeHTTP(w, r)
		})
		if _, err := a.Send(ctx, b.Address(), "secret"); err == nil || !strings.Contains(err.Error(), "does not hash") {
			t.Fatalf("send: %v, want a refusal of the identity", err)
		}
		if exists(filepath.Join(a.Dir(), "peers", b.Address().String())) {
			t.Fatal("a forged identity was pinned")
		}
	})

	t.Run("swapped prekey", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		st, sig := e.srv.Prekey(c.Address())
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Path == "/v1/"+b.Address().String()+"/identity" {
				fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.Identity().Document(), Prekey: st, PrekeySignature: sig})
				return
			}
			next.ServeHTTP(w, r)
		})
		var refused *client.RefusedError
		if _, err := a.Send(ctx, b.Address(), "secret"); !errors.As(err, &refused) {
			t.Fatalf("send: %v, want REFUSED", err)
		}
		if e.srv.Count(b.Address()) != 0 {
			t.Fatal("something was sent")
		}
		if exists(filepath.Join(a.Dir(), "peers", b.Address().String())) {
			t.Fatal("a peer whose prekey did not verify was pinned")
		}
	})

	t.Run("an expired prekey", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		e.clock.Add(protocol.PrekeyLifetime)
		if _, err := a.Rekey(ctx, ""); err != nil { // a certificate that still signs mail
			t.Fatal(err)
		}
		if _, err := a.Send(ctx, b.Address(), "too late"); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("send: %v, want a refusal of the expired prekey", err)
		}
		if e.srv.Count(b.Address()) != 0 {
			t.Fatal("something was sent")
		}
	})

	t.Run("rollback of a peer's prekey", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		st, sig := e.srv.Prekey(b.Address())
		if _, err := b.Rekey(ctx, ""); err != nil {
			t.Fatal(err)
		}
		send(t, a, b, "sees serial 2")
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Path == "/v1/"+b.Address().String()+"/identity" {
				fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.Identity().Document(), Prekey: st, PrekeySignature: sig})
				return
			}
			next.ServeHTTP(w, r)
		})
		if _, err := a.Send(ctx, b.Address(), "secret"); err == nil || !strings.Contains(err.Error(), "rollback") {
			t.Fatalf("send: %v, want a rollback refusal", err)
		}
	})

	t.Run("a stolen working key, replaced since", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		stolen := worker(t, b) // read before the renewal deletes it
		old, _ := e.srv.Prekey(b.Address())
		if _, err := b.Rekey(ctx, ""); err != nil {
			t.Fatal(err)
		}
		send(t, a, b, "sees certificate 2")
		// The thief, with a server's help, offers a prekey of its own under
		// the old certificate, which has weeks to run: a higher prekey
		// serial than any A has seen, so only the certificate's gives it away.
		p, err := protocol.ParsePrekey(old)
		if err != nil {
			t.Fatal(err)
		}
		p.Serial = 9
		sig, err := protocol.Sign(stolen, p.Statement(), protocol.PrekeyNamespace(b.Address()))
		if err != nil {
			t.Fatal(err)
		}
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Path == "/v1/"+b.Address().String()+"/identity" {
				fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.Identity().Document(), Prekey: p.Statement(), PrekeySignature: sig})
				return
			}
			next.ServeHTTP(w, r)
		})
		if _, err := a.Send(ctx, b.Address(), "secret"); err == nil || !strings.Contains(err.Error(), "under certificate 1, below 2") {
			t.Fatalf("send: %v, want a refusal of the older certificate", err)
		}
	})

	t.Run("rollback of the box's own prekey", func(t *testing.T) {
		e := newEnv(t)
		b := e.box(protocol.Classic)
		st, sig := e.srv.Prekey(b.Address())
		if _, err := b.Rekey(ctx, ""); err != nil {
			t.Fatal(err)
		}
		published, _ := e.srv.Prekey(b.Address())
		// Serial 1 again: rekey would take serial 2, whose key it already
		// published, and publish it again under a new statement.
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Path == "/v1/"+b.Address().String()+"/identity" {
				fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.Identity().Document(), Prekey: st, PrekeySignature: sig})
				return
			}
			next.ServeHTTP(w, r)
		})
		if _, err := b.Rekey(ctx, ""); err == nil || !strings.Contains(err.Error(), "rollback") {
			t.Fatalf("rekey: %v, want a rollback refusal", err)
		}
		if now, _ := e.srv.Prekey(b.Address()); !bytes.Equal(now, published) {
			t.Fatal("a prekey was published over a rollback")
		}
	})

	t.Run("replay under a new id", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		sent := capture(e, http.MethodPost, "/v1/"+b.Address().String())
		send(t, a, b, "once")
		e.srv.SetMiddle(nil)
		receive(t, b)
		var req protocol.SendRequest
		_ = json.Unmarshal(*sent, &req)
		other := sha256.Sum256([]byte("another id"))
		e.srv.Inject(b.Address(), hex.EncodeToString(other[:]), a.Address(), req.Ciphertext)
		refusedFor(t, receive(t, b), client.RefusedReplay, "replay")
	})

	t.Run("sent_at older than 33 days", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		env, err := protocol.NewEnvelope(a.Address(), b.Address(), "stale", e.clock.Now().Add(-protocol.TTL-time.Second))
		if err != nil {
			t.Fatal(err)
		}
		env.Identity = a.Identity().Document()
		line, sig, err := protocol.SignEnvelope(env, worker(t, a))
		if err != nil {
			t.Fatal(err)
		}
		e.seal(b, a.Address(), line, sig)
		refusedFor(t, receive(t, b), protocol.RefusedStale, "older than 33 days")
	})

	t.Run("not encrypted to this box", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		// A's message to C, stored in B's box as it is.
		sent := capture(e, http.MethodPost, "/v1/"+c.Address().String())
		send(t, a, c, "for C's key")
		e.srv.SetMiddle(nil)
		var req protocol.SendRequest
		_ = json.Unmarshal(*sent, &req)
		id := sha256.Sum256(req.Ciphertext)
		e.srv.Inject(b.Address(), hex.EncodeToString(id[:]), a.Address(), req.Ciphertext)
		refusedFor(t, receive(t, b), client.RefusedDecrypt, "does not decrypt")
	})

	t.Run("an id that is not the hash", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		realID := send(t, a, b, "listed under another id").ID
		h := sha256.Sum256([]byte("not the hash"))
		fake := hex.EncodeToString(h[:])
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			r.URL.Path = strings.Replace(r.URL.Path, fake, realID, 1)
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			w.WriteHeader(rec.Code)
			_, _ = w.Write(bytes.ReplaceAll(rec.Body.Bytes(), []byte(realID), []byte(fake)))
		})
		res := receive(t, b)
		refusedFor(t, res, client.RefusedID, "not the SHA-256")
		if res.Refused[0].ID != realID || !exists(filepath.Join(b.Dir(), "quarantine", realID+".json")) {
			t.Fatalf("quarantined as %s, not by the ciphertext's hash", res.Refused[0].ID)
		}
		if exists(filepath.Join(b.Dir(), "inbox", fake+".json")) || exists(filepath.Join(b.Dir(), "quarantine", fake+".json")) {
			t.Fatal("a file was named by the server's id")
		}
	})
}
