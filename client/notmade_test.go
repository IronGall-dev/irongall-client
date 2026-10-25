package client_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"golang.org/x/crypto/ssh"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/internal/fakeserver"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// A statement the box's server serves in its name that it did not make is
// said where an owner looks, by its kind, recommending that the address be
// revoked (#74, #428): one signed with a taken working key, under the box's
// own certificate, and one under a certificate the identity made for someone
// else's key. recv renews nothing above either; prekey renew, its owner's,
// does, of the box's own type, never the served one's (#61). A read that
// serves the box's own statement clears it.
func TestRecvRenewsNothingAboveAStatementTheBoxDidNotMake(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		own  bool
		// above is how far above the box's own the other certificate is
		// numbered: 0, its own serial, which only the key it certifies tells
		// from the box's own.
		above uint64
	}{{"under its own certificate", true, 0}, {"under a later certificate it did not make", false, 10}, {"under a certificate it did not make at its own serial", false, 0}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			e := newEnv(t)
			b := e.box(protocol.PostQuantum)
			n := numberOf(t, b)
			signer, certSerial := worker(t, b), n
			if !c.own {
				_, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				stranger, err := ssh.NewSignerFromKey(key)
				if err != nil {
					t.Fatal(err)
				}
				certSerial = n + c.above
				cert, err := protocol.NewCertificate(b.Identity(), identityKey(t, b), stranger.PublicKey(), certSerial, e.clock.Now())
				if err != nil {
					t.Fatal(err)
				}
				if signer, err = ssh.NewCertSigner(cert.PublicKey().(*ssh.Certificate), stranger); err != nil {
					t.Fatal(err)
				}
			}
			st, _ := e.srv.Prekey(b.Address())
			p, err := protocol.ParsePrekey(st)
			if err != nil {
				t.Fatal(err)
			}
			k, err := age.GenerateX25519Identity()
			if err != nil {
				t.Fatal(err)
			}
			p.Serial, p.Key = certSerial+5, k.Recipient().String()
			sig, err := protocol.Sign(signer, p.Statement(), protocol.PrekeyNamespace(b.Address()))
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
			res, _ := b.Receive(ctx)
			if res == nil || res.NotMade == nil || res.NotMade.Serial != certSerial+5 || res.NotMade.CertificateSerial != certSerial || res.NotMade.OwnCertificate != c.own {
				t.Fatalf("recv shown a statement it did not make: %+v", res)
			}
			if res.Renewed != nil || res.RenewErr == nil {
				t.Fatalf("recv renewed above a statement the box did not make: renewed %+v, %v", res.Renewed, res.RenewErr)
			}
			if !strings.Contains(res.NotMade.Words(), "revocation publish") {
				t.Errorf("no recommendation to revoke the address: %s", res.NotMade.Words())
			}
			if st, err := b.Status(t.Context()); err != nil || st.PrekeyNotMade == nil || !strings.Contains(strings.Join(st.Attention, " "), "did not make") {
				t.Fatalf("status: %+v, %v", st, err)
			}
			// Under its own certificate, whose working key another holds, it
			// signs no mail: the entry waits for the box's next certificate.
			to := e.box(protocol.PostQuantum)
			_, err = b.Send(ctx, to.Address(), "while another holds its working key")
			if (err != nil) != c.own {
				t.Fatalf("a send while a statement the box did not make is served: %v", err)
			}
			// Its owner's renewal goes above it, of the box's own type.
			if p, err := b.Rekey(ctx, ""); err != nil || p.Serial <= certSerial+5 || p.Type() != protocol.PostQuantum {
				t.Fatalf("prekey renew above a statement the box did not make: %+v, %v", p, err)
			}
			if c.own {
				if sent, err := b.Flush(ctx); err != nil || len(sent) != 1 {
					t.Fatalf("the waiting entry once the box has its next certificate: %d sent, %v", len(sent), err)
				}
			}
			e.srv.SetMiddle(nil)
			if _, err := b.Rekey(ctx, ""); err != nil {
				t.Fatal(err)
			}
			if st, err := b.Status(t.Context()); err != nil || st.PrekeyNotMade != nil {
				t.Fatalf("status once its server serves its own: %+v, %v", st, err)
			}
		})
	}
}

// A renewal the server took, and a fault of the box after it, is a renewal
// taken: Rekey and the remedy return the new prekey with the fault, and the
// box holds it as the one it published (#110).
func TestAFaultAfterARenewalWasTakenLeavesItTaken(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
