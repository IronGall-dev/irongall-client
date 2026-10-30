package client_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// posted records the ciphertext of every send to mailbox b that reaches the
// server, in order.
func posted(e *env, b protocol.Address) *[][]byte {
	var got [][]byte
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/v1/"+b.String()+"/messages") {
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			got = append(got, body) // the body is the ciphertext
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
	t.Parallel()
	for _, c := range []struct {
		kt     protocol.KeyType
		first  int // the smallest block's size for this key type
		bodies []string
	}{
		{protocol.PostQuantum, 3072, []string{"no", "yes", "reject", "approve", strings.Repeat("a", 126)}},
	} {
		e := newEnv(t)
		a, b := e.mailbox(), e.mailbox()
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

// An outbox entry that is not an envelope from this mailbox to that address is
// never sealed: the sender reads it as its recipient would.
func TestSealRefusesAnEntryItsRecipientWould(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b, other := e.mailbox(), e.mailbox(), e.mailbox()
	ctx := context.Background()
	forge.FailOnce(e.srv, http.MethodGet, "/v1/"+b.Address().String())
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
		t.Fatalf("flush sealed an envelope for another mailbox: %v", err)
	}
	if len(*sizes) != 0 {
		t.Fatalf("the server got %d sends", len(*sizes))
	}
}
