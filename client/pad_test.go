package client_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// posted records the ciphertext of every send to box b that reaches the
// server, in order.
func posted(e *env, b protocol.Address) *[][]byte {
	var got [][]byte
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/"+b.String()+"/messages") {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req protocol.SendRequest
			if json.Unmarshal(body, &req) == nil {
				got = append(got, req.Ciphertext)
			}
		}
		next.ServeHTTP(w, r)
	})
	return &got
}

// Every send is padded: what the server gets is a whole number of blocks, and
// bodies of different lengths are one size. The padding is after the
// signature, so the recipient's line, the sender's sent/ record and its
// outbox never held any; and the line and the record carry no identity
// document either.
func TestSendPadsEveryMessage(t *testing.T) {
	for _, c := range []struct {
		kt     protocol.KeyType
		first  int // the smallest block's size for this key type
		bodies []string
	}{
		{protocol.PostQuantum, 3072, []string{"no", "yes", "reject", "approve", strings.Repeat("a", 184)}},
		{protocol.Classic, 2048, []string{"no", "yes", "reject", "approve", strings.Repeat("a", 619)}},
	} {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(c.kt)
		sizes := posted(e, b.Address())
		for _, body := range c.bodies {
			send(t, a, b, body)
		}
		// And bodies of other sizes: each on a block, a larger one on a larger block.
		for _, n := range []int{600, 2000, 15000, 20000, 40000, 70000} {
			send(t, a, b, strings.Repeat("b", n))
		}
		if len(*sizes) != len(c.bodies)+6 {
			t.Fatalf("%s: the server got %d sends", c.kt, len(*sizes))
		}
		for i, ct := range *sizes {
			if n := len(ct); n != protocol.PaddedSize(n) {
				t.Errorf("%s, send %d: %d bytes of ciphertext is not a whole number of %d-byte blocks", c.kt, i, n, protocol.PadBlock(n))
			}
			if i < len(c.bodies) && len(ct) != c.first {
				t.Errorf("%s: a body of %d bytes is %d bytes of ciphertext, want %d", c.kt, len(c.bodies[i]), len(ct), c.first)
			}
		}
		res := receive(t, b)
		if len(res.Delivered) != len(*sizes) {
			t.Fatalf("%s: delivered %d of %d", c.kt, len(res.Delivered), len(*sizes))
		}
		for i, d := range res.Delivered[:len(c.bodies)] {
			if bodyOf(t, d) != c.bodies[i] {
				t.Errorf("%s: delivered %q, sent %q", c.kt, bodyOf(t, d), c.bodies[i])
			}
			if strings.Contains(string(d.Line), `"identity"`) || strings.Contains(string(d.Line), "....") {
				t.Errorf("%s: the delivered line carries the identity document or the padding: %s", c.kt, d.Line)
			}
			// What was signed is one line, the envelope with the sender's
			// identity document, and no padding is part of it.
			if !bytes.HasSuffix(d.Plaintext, []byte("}\n")) || bytes.Count(d.Plaintext, []byte("\n")) != 1 || !strings.Contains(string(d.Plaintext), `"identity":"`) {
				t.Errorf("%s: what was signed is not the envelope's one line: %q", c.kt, d.Plaintext)
			}
		}
		for name, rec := range sentRecords(t, a) {
			if strings.Contains(string(rec), `"identity"`) || strings.Contains(string(rec), "....") {
				t.Errorf("%s: sent/%s carries the identity document or the padding", c.kt, name)
			}
		}
	}
}

// The padding is made for the key a message is encrypted to. After
// stale_prekey the newer prekey may be of the other type, whose age file is
// 1,459 bytes smaller or larger: the same signed envelope is padded again,
// for that one, and lands on a block again. Here the box renews between the
// sender's lookup and its post, as the server stands in for by serving the
// statement it held before, once.
func TestAReencryptionToTheOtherKeyTypeIsPaddedAgain(t *testing.T) {
	for _, c := range []struct {
		from, to      protocol.KeyType
		before, after int
	}{
		{protocol.PostQuantum, protocol.Classic, 3072, 2048},
		{protocol.Classic, protocol.PostQuantum, 2048, 3072},
	} {
		e := newEnv(t)
		a, b := e.box(protocol.Classic), e.box(c.from)
		ctx := context.Background()
		statement, signature := e.srv.Prekey(b.Address())
		if _, err := b.Rekey(ctx, c.to); err != nil {
			t.Fatal(err)
		}
		var sizes []int
		var sealed []byte // the outbox's envelope at the first post
		old := true
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			switch {
			case old && r.Method == http.MethodGet && r.URL.Path == "/v1/"+b.Address().String():
				old = false
				fakeserver.WriteJSON(w, http.StatusOK, protocol.BoxResponse{Identity: b.Identity().Document(), Prekey: statement, PrekeySignature: signature})
				return
			case r.Method == http.MethodPost && r.URL.Path == "/v1/"+b.Address().String()+"/messages":
				body, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(body))
				var req protocol.SendRequest
				if json.Unmarshal(body, &req) == nil {
					sizes = append(sizes, len(req.Ciphertext))
				}
				if sealed == nil {
					outbox, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P"))
					if len(outbox) == 1 {
						sealed, _ = os.ReadFile(outbox[0])
					}
				}
			}
			next.ServeHTTP(w, r)
		})
		if _, err := a.Send(ctx, b.Address(), "kept"); err != nil {
			t.Fatalf("%s → %s: %v", c.from, c.to, err)
		}
		// The first post is to the old prekey, refused as stale; the second is to the new one.
		if len(sizes) != 2 || sizes[0] != c.before || sizes[1] != c.after {
			t.Fatalf("%s → %s: the server got %d sends, %v bytes", c.from, c.to, len(sizes), sizes)
		}
		res := receive(t, b)
		if len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "kept" {
			t.Fatalf("%s → %s: delivered %d", c.from, c.to, len(res.Delivered))
		}
		if sealed == nil || !bytes.Equal(res.Delivered[0].Plaintext, sealed) {
			t.Fatalf("%s → %s: the re-encrypted message is not the same signed envelope", c.from, c.to)
		}
	}
}

// An outbox entry that is not an envelope from this box to that address is
// never sealed: the sender reads it as its recipient would.
func TestSealRefusesAnEntryItsRecipientWould(t *testing.T) {
	e := newEnv(t)
	a, b, other := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	ctx := context.Background()
	failOnce(e, http.MethodGet, "/v1/"+b.Address().String())
	if _, err := a.Send(ctx, b.Address(), "to b"); err == nil {
		t.Fatal("the send should have failed")
	}
	outbox, _ := filepath.Glob(filepath.Join(a.Dir(), "outbox", "*.P"))
	if len(outbox) != 1 {
		t.Fatalf("outbox holds %d", len(outbox))
	}
	p, _ := os.ReadFile(outbox[0])
	// The same entry, now naming another recipient inside.
	forged := strings.Replace(string(p), `"to":"`+b.Address().String(), `"to":"`+other.Address().String(), 1)
	if err := os.WriteFile(outbox[0], []byte(forged), 0o600); err != nil { //nolint:gosec // a test's own directory
		t.Fatal(err)
	}
	sizes := posted(e, b.Address())
	if _, err := a.Flush(ctx); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("flush sealed an envelope for another box: %v", err)
	}
	if len(*sizes) != 0 {
		t.Fatalf("the server got %d sends", len(*sizes))
	}
}
