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

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A statement the mailbox's server serves in its name that it did not make is
// said where an owner looks, by its kind, recommending that the address be
// revoked (#74, #428): one signed with a taken working key, under the mailbox's
// own certificate, and one under a certificate the identity made for someone
// else's key. recv renews nothing above either; prekey renew, its owner's,
// does, of the mailbox's own type, never the served one's (#61). A read that
// serves the mailbox's own statement clears it.
func TestRecvRenewsNothingAboveAStatementTheMailboxDidNotMake(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name string
		own  bool
		// above is how far above the mailbox's own the other certificate is
		// numbered: 0, its own serial, which only the key it certifies tells
		// from the mailbox's own.
		above uint64
	}{{"under its own certificate", true, 0}, {"under a later certificate it did not make", false, 10}, {"under a certificate it did not make at its own serial", false, 0}} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			e := newEnv(t)
			b := e.mailbox(protocol.PostQuantum)
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
				if r.Method == http.MethodGet && r.URL.Path == mailboxPath(b) {
					fakeserver.WriteJSON(w, http.StatusOK, protocol.MailboxResponse{Identity: b.Identity().Document(), Prekey: p.Statement(), PrekeySignature: sig})
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
				t.Fatalf("recv renewed above a statement the mailbox did not make: renewed %+v, %v", res.Renewed, res.RenewErr)
			}
			if !strings.Contains(res.NotMade.Words(), "revocation publish") {
				t.Errorf("no recommendation to revoke the address: %s", res.NotMade.Words())
			}
			if st, err := b.Status(t.Context()); err != nil || st.PrekeyNotMade == nil || !strings.Contains(strings.Join(st.Attention, " "), "did not make") {
				t.Fatalf("status: %+v, %v", st, err)
			}
			// Under its own certificate, whose working key another holds, it
			// signs no message: the entry waits for the mailbox's next certificate.
			to := e.mailbox(protocol.PostQuantum)
			_, err = b.Send(ctx, to.Address(), "while another holds its working key")
			if (err != nil) != c.own {
				t.Fatalf("a send while a statement the mailbox did not make is served: %v", err)
			}
			// Its owner's renewal goes above it, of the mailbox's own type.
			if p, err := b.Rekey(ctx, ""); err != nil || p.Serial <= certSerial+5 || p.Type() != protocol.PostQuantum {
				t.Fatalf("prekey renew above a statement the mailbox did not make: %+v, %v", p, err)
			}
			if c.own {
				if sent, err := b.Flush(ctx); err != nil || len(sent) != 1 {
					t.Fatalf("the waiting entry once the mailbox has its next certificate: %d sent, %v", len(sent), err)
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

// seal holds a send by the record of the mailbox's last read of itself
// (noteServed, which only known writes), and a send makes no such read: a
// statement signed with the mailbox's own working key, served since that read,
// lets a send through, and once a read of itself has shown it (revocation
// ask of its own address), the next send waits (#442 item 1).
func TestASendIsHeldByTheMailboxsLastReadOfItself(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	b, to := e.mailbox(protocol.PostQuantum), e.mailbox(protocol.PostQuantum)
	n := numberOf(t, b)
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
	sig, err := protocol.Sign(worker(t, b), p.Statement(), protocol.PrekeyNamespace(b.Address()))
	if err != nil {
		t.Fatal(err)
	}
	e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
		if r.Method == http.MethodGet && r.URL.Path == mailboxPath(b) {
			fakeserver.WriteJSON(w, http.StatusOK, protocol.MailboxResponse{Identity: b.Identity().Document(), Prekey: p.Statement(), PrekeySignature: sig})
			return
		}
		next.ServeHTTP(w, r)
	})
	if _, err := b.Send(ctx, to.Address(), "before the mailbox has read itself"); err != nil {
		t.Fatalf("a send before the mailbox has read the statement: %v", err)
	}
	if _, err := b.Ask(ctx, b.Address()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Send(ctx, to.Address(), "once the mailbox has read itself"); err == nil || !strings.Contains(err.Error(), "someone else holds the working key") {
		t.Fatalf("a send once the mailbox has read the statement: %v", err)
	}
}

// A renewal the server took, and a fault of the mailbox after it, is a renewal
// taken: Rekey and the remedy return the new prekey with the fault, and the
// mailbox holds it as the one it published (#110).
func TestAFaultAfterARenewalWasTakenLeavesItTaken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newEnv(t)
	for _, c := range []struct {
		name  string
		renew func(*client.Mailbox) (*protocol.Prekey, error)
	}{
		{"prekey renew", func(b *client.Mailbox) (*protocol.Prekey, error) { return b.Rekey(ctx, "") }},
		{"the remedy", func(b *client.Mailbox) (*protocol.Prekey, error) {
			r, err := b.RenewAndRevoke(ctx, "")
			if r == nil {
				return nil, err
			}
			return r.Prekey, err
		}},
	} {
		b := e.mailbox(protocol.Classic)
		old := numberOf(t, b)
		e.clock.Add(2 * time.Second)
		// The older working key's public half cannot be deleted: a fault of
		// the mailbox once the new prekey is taken.
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
		t.Fatalf("the server serves %d, the mailbox published %d", servedSerial(t, e, b), numberOf(t, b))
	}
}

// A mailbox reads its own record at its server by every rule but its
// certificate's dates (PROTOCOL.md §12.4): a record its server took under a
// rule since changed, a certificate made for 65 days, one begun two hours
// back or one valid from 1970, is never one its mailbox cannot renew past.
// recv renews past each as past any record of its own. A record that does
// not verify at all stops the renewal, saying the way out, and the remedy,
// which goes on past what it cannot use, is that way.
func TestARenewalGoesPastItsOwnRecordWhateverItsDates(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name          string
		after, before func(now uint64) uint64
	}{
		{"made for 65 days", func(n uint64) uint64 { return n - 3600 }, func(n uint64) uint64 { return n + 65*86400 }},
		{"begun two hours back", func(n uint64) uint64 { return n - 7200 }, func(n uint64) uint64 { return n + 64*86400 }},
		{"valid from 1970", func(uint64) uint64 { return 0 }, func(n uint64) uint64 { return n + 64*86400 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t)
			b := e.mailbox(protocol.PostQuantum)
			n := numberOf(t, b)
			unix := uint64(e.clock.Now().Unix())
			cert := &ssh.Certificate{
				Key: workKey(t, b).PublicKey(), Serial: n, CertType: ssh.UserCert, KeyId: protocol.CertificateKeyID,
				ValidPrincipals: []string{b.Address().String()}, ValidAfter: c.after(unix), ValidBefore: c.before(unix),
			}
			if err := cert.SignCert(rand.Reader, identityKey(t, b)); err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewCertSigner(cert, workKey(t, b))
			if err != nil {
				t.Fatal(err)
			}
			st, _ := e.srv.Prekey(b.Address())
			sig, err := protocol.Sign(signer, st, protocol.PrekeyNamespace(b.Address()))
			if err != nil {
				t.Fatal(err)
			}
			e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
				if r.Method == http.MethodGet && r.URL.Path == mailboxPath(b) {
					fakeserver.WriteJSON(w, http.StatusOK, protocol.MailboxResponse{Identity: b.Identity().Document(), Prekey: st, PrekeySignature: sig})
					return
				}
				next.ServeHTTP(w, r)
			})
			e.clock.Add(25 * time.Hour)
			res, err := b.Receive(context.Background())
			if err != nil || res.Renewed == nil || res.RenewErr != nil || res.NotMade != nil {
				t.Fatalf("recv over its own record under a certificate %s: %+v, %v", c.name, res, err)
			}
		})
	}
	t.Run("a record that does not verify", func(t *testing.T) {
		t.Parallel()
		ctx := context.Background()
		e := newEnv(t)
		b, other := e.mailbox(protocol.PostQuantum), e.mailbox(protocol.PostQuantum)
		st, _ := e.srv.Prekey(b.Address())
		forged, err := protocol.Sign(worker(t, other), st, protocol.PrekeyNamespace(b.Address()))
		if err != nil {
			t.Fatal(err)
		}
		e.srv.SetMiddle(func(w http.ResponseWriter, r *http.Request, next http.Handler) {
			if r.Method == http.MethodGet && r.URL.Path == mailboxPath(b) {
				fakeserver.WriteJSON(w, http.StatusOK, protocol.MailboxResponse{Identity: b.Identity().Document(), Prekey: st, PrekeySignature: forged})
				return
			}
			next.ServeHTTP(w, r)
		})
		e.clock.Add(25 * time.Hour)
		res, _ := b.Receive(ctx)
		if res == nil || res.Renewed != nil || res.RenewErr == nil || !strings.Contains(res.RenewErr.Error(), "dromas cert revoke-earlier") {
			t.Fatalf("recv over a record that does not verify: %+v", res)
		}
		if _, err := b.RenewAndRevoke(ctx, ""); err != nil {
			t.Fatalf("the remedy past a record that does not verify: %v", err)
		}
		e.srv.SetMiddle(nil)
		if st, err := b.Status(ctx); err != nil || len(st.Attention) != 0 {
			t.Fatalf("status after the remedy: %+v, %v", st, err)
		}
	})
}
