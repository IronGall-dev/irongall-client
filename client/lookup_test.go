package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// lookups records, for each read of a box, whether it carried a pass.
func lookups(e *env) (seen func() map[string]bool) {
	var mu sync.Mutex
	got := map[string]bool{}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if _, ok := readOf(r); ok {
			mu.Lock()
			got[r.URL.Path] = r.Header.Get("Authorization") != ""
			mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
	return func() map[string]bool {
		mu.Lock()
		defer mu.Unlock()
		out := map[string]bool{}
		for k, v := range got {
			out[k] = v
		}
		return out
	}
}

// A box's lookups of another box carry its pass, so a server counts them
// against the box and not against the address it calls from (PROTOCOL.md
// §4.1, §8): the recipient's box before a send, and a sender's in a drain.
// What a box asks about itself carries none, since its pass may be what is
// wrong.
func TestLookupsCarryThePass(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	seen := lookups(e)
	send(t, a, b, "asked about with a pass")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	got := seen()
	for _, p := range []string{boxPath(b), boxPath(a)} {
		if carried, asked := got[p]; !asked || !carried {
			t.Errorf("GET %s: asked %v, with a pass %v", p, asked, carried)
		}
	}
	seen = lookups(e)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if carried, asked := seen()[boxPath(b)]; !asked || carried {
		t.Errorf("a box's read of its own box: asked %v, with a pass %v", asked, carried)
	}
}

// A lookup whose pass the server refuses is asked again without one: what
// was refused is the asker's pass, and the post after it says what that
// means.
func TestALookupWhosePassIsRefusedAsksWithout(t *testing.T) {
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	var mu sync.Mutex
	without := 0
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		_, lookup := readOf(r)
		if lookup && r.Header.Get("Authorization") != "" {
			w.Header().Set("Content-Type", protocol.ProblemContentType)
			w.Header().Set("WWW-Authenticate", protocol.PassScheme)
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(protocol.Problem{Type: protocol.CodeUnauthorized.TypeURI(), Title: "Unauthorized", Status: http.StatusUnauthorized, Code: protocol.CodeUnauthorized})
			return
		}
		if lookup {
			mu.Lock()
			without++
			mu.Unlock()
		}
		next.ServeHTTP(w, r)
	})
	send(t, a, b, "asked again without the pass")
	mu.Lock()
	defer mu.Unlock()
	if without != 1 {
		t.Fatalf("%d lookups asked again without the pass, want the read of the recipient's box", without)
	}
}

// A server that holds an address revoked answers 410 to whatever is sent for
// it, with no check. A revocation published there again is taken as done
// once the record it then asks for verifies, and is not otherwise.
func TestARevocationPublishedToARevokedBox(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a := e.box(protocol.Classic)
	rec := revoke(t, e, a)
	if _, err := client.Revoke(ctx, e.opts(), rec); err != nil {
		t.Fatalf("published again to a server that holds it: %v", err)
	}
	says(e, protocol.CodeRevoked, http.MethodPut, "/revocations")
	b := e.box(protocol.Classic)
	other, err := b.Revocation()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Revoke(ctx, e.opts(), other); err == nil {
		t.Fatal("a 410 from a server that holds no revocation was taken as done")
	}
}
