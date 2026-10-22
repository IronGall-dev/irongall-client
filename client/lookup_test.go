package client_test

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/forge"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// lookups records, for each read of a box, whether it carried a pass.
func lookups(e *env) (seen func() map[string]bool) {
	var mu sync.Mutex
	got := map[string]bool{}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if _, ok := forge.ReadOf(r); ok {
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

// A box's lookups carry no pass (PROTOCOL.md §4.1, §8): the read is public,
// and a server reads none on it. Not the
// recipient's box before a send, not a sender's in a drain, and not a box's
// read of its own.
func TestLookupsCarryNoPass(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	seen := lookups(e)
	send(t, a, b, "asked about with no pass")
	if res := receive(t, b); len(res.Delivered) != 1 {
		t.Fatalf("delivered %d", len(res.Delivered))
	}
	got := seen()
	for _, p := range []string{boxPath(b), boxPath(a)} {
		if carried, asked := got[p]; !asked || carried {
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
	other, err := b.Revocation(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Revoke(ctx, e.opts(), other); err == nil {
		t.Fatal("a 410 from a server that holds no revocation was taken as done")
	}
}
