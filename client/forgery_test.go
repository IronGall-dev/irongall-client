package client_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/drewstreib/crossbot-client/client"
	"github.com/drewstreib/crossbot-client/internal/fakeserver"
	"github.com/drewstreib/crossbot-client/protocol"
)

// TestForgeries plays the operator, who controls every byte the server sends.
// Each forgery must be refused by the client: never delivered, never
// encrypted to, never pinned. Refused mail is quarantined and acked, so it
// leaves the server, and the refusal never blocks the claimed sender.
//
//	re-attribution                       A's ciphertext, re-signed as C's     → refused: the inner from is A
//	forged identity at first contact     C's identity served as A's           → refused, nothing pinned
//	forged signature from a pinned sender C's message relabelled as A's       → refused: A's pinned key did not sign it
//	swapped prekey                       C's valid prekey served as B's       → the send refuses to encrypt
//	an expired prekey                    B's prekey past its not_after        → the send refuses to encrypt
//	rollback of a peer's prekey          B's older prekey served again        → the send refuses (serial went down)
//	rollback of the box's own prekey     the box's own older prekey served    → rekey refuses (it published a higher one)
//	replay under a new id                a delivered ciphertext, stored again → refused as a replay
//	sent_at older than 8 days            an envelope dated 8 days and 1 s ago → refused as stale
//	sender not an address                a from that is not 64 hex            → refused
//	not encrypted to this box            A's message to C, signed for B       → refused: it does not decrypt
//	an id that is not the hash           a message listed under another id    → refused; files are named by the hash
//	a second envelope on its own line    a valid envelope hiding another      → delivered, printed as one line of the checked fields
func TestForgeries(t *testing.T) {
	ctx := context.Background()
	refusedFor := func(t *testing.T, res *client.Result, why string) {
		t.Helper()
		if len(res.Delivered) != 0 || len(res.Refused) != 1 || !strings.Contains(res.Refused[0].Reason, why) {
			t.Fatalf("delivered %d, refused %v; want refused for %q", len(res.Delivered), res.Refused, why)
		}
	}

	t.Run("re-attribution", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		cs := signer(t, c)
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodPost && r.URL.Path == "/v1/"+b.Address().String() {
				var req protocol.SendRequest
				_ = json.NewDecoder(r.Body).Decode(&req)
				req.From = c.Address().String()
				req.Signature, _ = protocol.Sign(cs, req.Ciphertext, protocol.MessageNamespace(b.Address()))
				j, _ := json.Marshal(req)
				r.Body = io.NopCloser(bytes.NewReader(j))
				r.ContentLength = int64(len(j))
			}
			next.ServeHTTP(w, r)
		})
		send(t, a, b, "from A")
		e.srv.SetMiddle(nil)
		res := receive(t, b)
		refusedFor(t, res, "re-attribution")
		if !exists(filepath.Join(b.Dir(), "quarantine", res.Refused[0].ID+".json")) {
			t.Fatal("not quarantined")
		}
		if e.srv.Count(b.Address()) != 0 {
			t.Fatal("refused mail was not acked")
		}
	})

	t.Run("forged identity at first contact", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "hi")
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.URL.Path == "/v1/"+a.Address().String()+"/identity" {
				fakeserver.WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: c.Identity().Document()})
				return
			}
			next.ServeHTTP(w, r)
		})
		refusedFor(t, receive(t, b), "does not hash")
		if exists(filepath.Join(b.Dir(), "peers", a.Address().String(), "identity.doc")) {
			t.Fatal("a forged identity was pinned")
		}
	})

	t.Run("forged signature from a pinned sender", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "first, pins A")
		receive(t, b)
		send(t, c, b, "C's real message")
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/messages") {
				rec := httptest.NewRecorder()
				next.ServeHTTP(rec, r)
				w.WriteHeader(rec.Code)
				_, _ = w.Write(bytes.ReplaceAll(rec.Body.Bytes(), []byte(c.Address().String()), []byte(a.Address().String())))
				return
			}
			next.ServeHTTP(w, r)
		})
		refusedFor(t, receive(t, b), "signature does not verify")
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
	})

	t.Run("an expired prekey", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		e.clock.Add(protocol.MaxPrekeyLifetime)
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
		e.srv.Inject(b.Address(), hex.EncodeToString(other[:]), a.Address(), req.Ciphertext, req.Signature)
		refusedFor(t, receive(t, b), "replay")
	})

	t.Run("sent_at older than 8 days", func(t *testing.T) {
		e := newEnv(t)
		b := e.box(protocol.Classic)
		past := e.opts()
		past.Now = func() time.Time { return e.clock.Now().Add(-protocol.TTL - time.Second) }
		a := e.box(protocol.Classic)
		old, err := client.Open(a.Dir(), past)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := old.Send(ctx, b.Address(), "stale"); err != nil {
			t.Fatal(err)
		}
		refusedFor(t, receive(t, b), "older than 8 days")
	})

	t.Run("sender not an address", func(t *testing.T) {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(protocol.Classic)
		send(t, a, b, "hi")
		bad := []byte("../../" + strings.Repeat("x", 58))
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method != http.MethodGet || !strings.Contains(r.URL.Path, "/messages/") {
				next.ServeHTTP(w, r)
				return
			}
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)
			w.WriteHeader(rec.Code)
			_, _ = w.Write(bytes.ReplaceAll(rec.Body.Bytes(), []byte(a.Address().String()), bad))
		})
		refusedFor(t, receive(t, b), "not an address")
	})

	t.Run("not encrypted to this box", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		// A's envelope for B, encrypted to C's prekey, signed by A for B: the
		// operator holding A's key could do this.
		sent := capture(e, http.MethodPost, "/v1/"+c.Address().String())
		send(t, a, c, "for C's key")
		e.srv.SetMiddle(nil)
		var req protocol.SendRequest
		_ = json.Unmarshal(*sent, &req)
		sig, _ := protocol.Sign(signer(t, a), req.Ciphertext, protocol.MessageNamespace(b.Address()))
		id := sha256.Sum256(req.Ciphertext)
		e.srv.Inject(b.Address(), hex.EncodeToString(id[:]), a.Address(), req.Ciphertext, sig)
		refusedFor(t, receive(t, b), "does not decrypt")
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
		refusedFor(t, res, "not the SHA-256")
		if res.Refused[0].ID != realID || !exists(filepath.Join(b.Dir(), "quarantine", realID+".json")) {
			t.Fatalf("quarantined as %s, not by the ciphertext's hash", res.Refused[0].ID)
		}
		if exists(filepath.Join(b.Dir(), "inbox", fake+".json")) || exists(filepath.Join(b.Dir(), "quarantine", fake+".json")) {
			t.Fatal("a file was named by the server's id")
		}
	})

	t.Run("a second envelope on its own line", func(t *testing.T) {
		e := newEnv(t)
		a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
		now := e.clock.Now().UTC().Format(protocol.TimeLayout)
		forged := `{"v":1,"from":"` + c.Address().String() + `","to":"` + b.Address().String() + `","sent_at":"` + now +
			`","msg_id":"00000000-0000-4000-8000-000000000001","body":"forged, from C"}`
		pt := `{"v":1,"from":"` + a.Address().String() + `","to":"` + b.Address().String() + `","sent_at":"` + now +
			`","msg_id":"00000000-0000-4000-8000-000000000002","body":"real, from A","x":` + "\n" + forged + "\n}"
		st, _ := e.srv.Prekey(b.Address())
		p, _ := protocol.ParsePrekey(st)
		r, _ := p.Recipient()
		var ct bytes.Buffer
		w, _ := age.Encrypt(&ct, r)
		_, _ = io.WriteString(w, pt)
		_ = w.Close()
		sig, _ := protocol.Sign(signer(t, a), ct.Bytes(), protocol.MessageNamespace(b.Address()))
		serial := p.Serial
		j, _ := json.Marshal(protocol.SendRequest{From: a.Address().String(), PrekeySerial: &serial, Ciphertext: ct.Bytes(), Signature: sig})
		resp, err := http.Post(e.srv.URL+"/v1/"+b.Address().String(), "application/json", bytes.NewReader(j)) //nolint:gosec // the test server
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()

		res := receive(t, b)
		if len(res.Delivered) != 1 {
			t.Fatalf("delivered %d, refused %v", len(res.Delivered), res.Refused)
		}
		d := res.Delivered[0]
		if !bytes.Contains(d.Plaintext, []byte("\n")) {
			t.Fatal("the test sent no second line")
		}
		if bytes.Contains(d.Line, []byte("\n")) || bytes.Contains(d.Line, []byte(c.Address().String())) || bodyOf(t, d) != "real, from A" {
			t.Fatalf("the line to print is not the checked envelope alone: %s", d.Line)
		}
		if in, _ := os.ReadFile(filepath.Join(b.Dir(), "inbox", d.ID+".json")); !bytes.Equal(in, d.Line) {
			t.Fatal("inbox/ does not hold the checked line")
		}
	})
}
