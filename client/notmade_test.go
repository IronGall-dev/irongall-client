package client_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A statement the box's server serves in its name that it did not make, here
// one a thief signed with a taken working key, for a key of the other type,
// is said where an owner looks, and changes nothing a command does (#74): the
// renewal goes above it, of the box's own type, never the served one's (#61).
// A read that serves the box's own statement clears it.
func TestAStatementTheBoxDidNotMakeIsSaid(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	b := e.box(protocol.PostQuantum)
	stolen, n := worker(t, b), numberOf(t, b)
	st, _ := e.srv.Prekey(b.Address())
	p, err := protocol.ParsePrekey(st)
	if err != nil {
		t.Fatal(err)
	}
	k, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	p.Serial, p.Key = n+5, k.Recipient().String()
	sig, err := protocol.Sign(stolen, p.Statement(), protocol.PrekeyNamespace(b.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == boxPath(b) {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.BoxResponse{Identity: b.Identity().Document(), Prekey: p.Statement(), PrekeySignature: sig})
			return
		}
		next.ServeHTTP(w, r)
	})
	e.clock.Add(25 * time.Hour)
	res := receive(t, b)
	if res.NotMade == nil || res.NotMade.Serial != n+5 || res.NotMade.CertificateSerial != n || res.Renewed == nil || res.Renewed.Type() != protocol.PostQuantum {
		t.Fatalf("recv shown a statement it did not make: %+v, renewed %+v", res.NotMade, res.Renewed)
	}
	if st, err := b.Status(); err != nil || st.PrekeyNotMade == nil || len(st.Attention) != 1 || !strings.Contains(st.Attention[0], "did not make") {
		t.Fatalf("status: %+v, %v", st, err)
	}
	e.srv.SetMiddle(nil)
	if _, err := b.Rekey(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if st, err := b.Status(); err != nil || st.PrekeyNotMade != nil || len(st.Attention) != 0 {
		t.Fatalf("status once its server serves its own: %+v, %v", st, err)
	}
}

// A renewal the server took, and a fault of the box after it, is a renewal
// taken: Rekey and the remedy return the new prekey with the fault, and the
// box holds it as the one it published (#110).
func TestAFaultAfterARenewalWasTakenLeavesItTaken(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	for _, c := range []struct {
		name  string
		renew func(*client.Box) (*protocol.Prekey, error)
	}{
		{"prekey renew", func(b *client.Box) (*protocol.Prekey, error) { return b.Rekey(ctx, "") }},
		{"the remedy", func(b *client.Box) (*protocol.Prekey, error) {
			r, err := b.RenewAndRevoke(ctx, "")
			if r == nil {
				return nil, err
			}
			return r.Prekey, err
		}},
	} {
		b := e.box(protocol.Classic)
		old := numberOf(t, b)
		e.clock.Add(2 * time.Second)
		// The older working key's public half cannot be deleted: a fault of
		// the box once the new prekey is taken.
		pub := workFile(b, old, ".pub")
		if err := os.Remove(pub); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(pub, "in the way"), 0o700); err != nil {
			t.Fatal(err)
		}
		p, err := c.renew(b)
		if p == nil || err == nil || servedSerial(t, e, b) != p.Serial || numberOf(t, b) != p.Serial {
			t.Errorf("%s with a fault after the server took it: %+v, %v", c.name, p, err)
		}
	}
}

// An init whose registration was never taken, and whose first statement has
// since expired, registers with a new one (#87): one that can no longer be
// sent is spent, as a renewal's is.
func TestAnInitWhoseFirstStatementExpiredRegisters(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	dir := t.TempDir()
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodPut && strings.Count(r.URL.Path, "/") == 2 {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := client.Init(ctx, dir, e.opts(), protocol.Classic); err == nil {
		t.Fatal("registered while the server was down")
	}
	e.srv.SetMiddle(nil)
	e.clock.Add(protocol.PrekeyLifetime + time.Hour)
	b, err := client.Init(ctx, dir, e.opts(), protocol.Classic)
	if err != nil {
		t.Fatalf("init once the first statement expired: %v", err)
	}
	if servedSerial(t, e, b) != numberOf(t, b) {
		t.Fatalf("the server serves %d, the box published %d", servedSerial(t, e, b), numberOf(t, b))
	}
}
