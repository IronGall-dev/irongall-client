package sh_test

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/internal/forge"
	"github.com/dromas-dev/dromas-client/protocol"
)

// The script's mailbox, in identity mode, beside Go mailboxes of each mode
// (PROTOCOL.md §5.1): it writes to and reads from both, follows each as it
// renews, and applies each sender's mode at check 7 by what it holds.

// goBodies drains Go mailbox g, and returns the bodies it delivered, sorted,
// as their JSON strings.
func goBodies(t *testing.T, g *client.Mailbox) []string {
	t.Helper()
	res, err := g.Receive(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Refused) != 0 {
		t.Errorf("the Go mailbox refused %+v", res.Refused)
	}
	var bodies []string
	for _, d := range res.Delivered {
		bodies = append(bodies, string(d.Envelope.Body))
	}
	slices.Sort(bodies)
	return bodies
}

// A script mailbox and a Go mailbox exchange messages with the Go mailbox in
// identity mode, as init makes it, and in working-key mode, as init --offline
// makes it, through a renewal of each.
func TestTheScriptAndAGoMailboxOfEachMode(t *testing.T) {
	for _, mode := range []string{"identity mode", "working-key mode"} {
		workingKey := mode == "working-key mode"
		t.Run(mode, func(t *testing.T) {
			w := newWorld(t)
			ctx := t.Context()
			s := w.mailbox()
			g, gb := w.goMailbox(workingKey)
			exchange := func(when string) {
				t.Helper()
				s.mustSend(gb, "from the script, "+when)
				if got := goBodies(t, g); !slices.Equal(got, []string{`"from the script, ` + when + `"`}) {
					t.Errorf("%s: the Go mailbox read %q", when, got)
				}
				if _, err := g.Send(ctx, s.addr, "from Go, "+when); err != nil {
					t.Fatalf("%s: %v", when, err)
				}
				if d := s.recv(); d.rc != 0 || !slices.Equal(d.bodies(), []string{"from Go, " + when}) {
					t.Errorf("%s: the script read %v", when, d)
				}
			}
			exchange("first")
			peer := "peers/" + gb.addr.String() + "/"
			if _, rank := w.served(gb); s.read(peer+"rank") != strconv.FormatUint(rank, 10)+"\n" || (rank == 0) == workingKey {
				t.Errorf("the script recorded the Go mailbox's statement by a signer of rank %q, served by one of %d", s.read(peer+"rank"), rank)
			}
			if s.has(peer+"revoked-certs.json") != workingKey {
				t.Errorf("the script holds a revocation of the Go mailbox's certificates: %v, in %s", s.has(peer+"revoked-certs.json"), mode)
			}
			if _, err := g.Rekey(ctx); err != nil {
				t.Fatal(err)
			}
			exchange("after Go's renewal")
			s.must("dr_rekey")
			exchange("after the script's renewal")
		})
	}
}

// stripping serves every read of mailbox a with no revocation of its
// certificates, while strip says so, as a server whose stores lag behind its
// trip does, and counts the reads of a and of its revocations.
func (w *world) stripping(a protocol.Address, strip func() bool) (reads *atomic.Int32) {
	reads = new(atomic.Int32)
	w.srv.SetMiddle(func(rw http.ResponseWriter, r *http.Request, next http.Handler) {
		if x, ok := forge.ReadOf(r); ok && x == a {
			reads.Add(1)
			if strip() {
				forge.Serve(w.t, w.srv, rw, r, next, func(br *protocol.MailboxResponse) {
					br.RevokedCertificates, br.RevokedCertificatesSignature = nil, nil
				})
				return
			}
		}
		next.ServeHTTP(rw, r)
	})
	return reads
}

// A reader that holds no trip of a sender reads it once more, once for each
// sender in a drain, before it refuses a certificate's signature as
// bad_signature (PROTOCOL.md §12.3, check 7): a trip that reached the
// sender's server late is taken, and one never shown refuses each message
// after two reads. Where the server holds no mailbox for the sender, the
// reader reads its revocations.
func TestTheScriptReadsASenderAgainBeforeItRefusesACertificate(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	late, never, forgotten := w.mailbox(), w.mailbox(), w.mailbox()
	g, gb := w.goMailbox(true)
	for _, to := range []*shMailbox{late, never, never, forgotten} {
		if _, err := g.Send(ctx, to.addr, "under a certificate"); err != nil {
			t.Fatal(err)
		}
	}
	var first atomic.Bool
	reads := w.stripping(gb.addr, func() bool { return first.CompareAndSwap(false, true) })
	if d := late.recv(); d.rc != 0 || !slices.Equal(d.bodies(), []string{"under a certificate"}) || reads.Load() != 2 {
		t.Errorf("a trip shown at the second read: %v, %d reads", d, reads.Load())
	}
	reads = w.stripping(gb.addr, func() bool { return true })
	if d := never.recv(); d.rc != 0 || len(d.messages) != 0 || d.refused("bad_signature") != 2 || !strings.Contains(d.said, "its sender's address is in identity mode") || reads.Load() != 2 || never.has("peers/"+gb.addr.String()+"/revoked-certs.json") {
		t.Errorf("a trip never shown: %v, %d reads", d, reads.Load())
	}
	w.honest()
	w.srv.Forget(gb.addr)
	n := len(w.srv.Requests())
	if d := forgotten.recv(); d.rc != 0 || !slices.Equal(d.bodies(), []string{"under a certificate"}) || !slices.Contains(w.calls(n), "GET /v1/"+gb.addr.String()+"/revocations") {
		t.Errorf("a sender its server forgot: %v, %q", d, w.calls(n))
	}
}

// A Go mailbox in identity mode switches to working-key mode: the script,
// which held it in identity mode, reads its first message under a certificate
// at the read it makes of the sender, and refuses a message its identity
// signed before the switch and the script read after, which is the switch's
// cost (PROTOCOL.md §15.11).
func TestTheScriptFollowsAGoMailboxThatSwitches(t *testing.T) {
	w := newWorld(t)
	ctx := t.Context()
	s := w.mailbox()
	g, gb := w.goMailbox(false)
	if _, err := g.Send(ctx, s.addr, "by the identity, read before the switch"); err != nil {
		t.Fatal(err)
	}
	if d := s.recv(); !slices.Equal(d.bodies(), []string{"by the identity, read before the switch"}) {
		t.Fatalf("before the switch: %v", d)
	}
	other := w.mailbox()
	if _, err := g.Send(ctx, other.addr, "by the identity, read after the switch"); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Switch(ctx); err != nil {
		t.Fatal(err)
	}
	if _, rank := w.served(gb); rank == 0 {
		t.Fatal("the switch published no statement under a certificate")
	}
	if _, err := g.Send(ctx, s.addr, "under the first certificate"); err != nil {
		t.Fatal(err)
	}
	d := s.recv()
	if d.rc != 0 || !slices.Contains(d.bodies(), "under the first certificate") || strings.Contains(d.said, "REFUSED") || !s.has("peers/"+gb.addr.String()+"/revoked-certs.json") {
		t.Errorf("after the switch: %v", d)
	}
	s.mustSend(gb, "to the mailbox that switched")
	if got := goBodies(t, g); !slices.Contains(got, `"to the mailbox that switched"`) {
		t.Errorf("the Go mailbox read %q", got)
	}
	// A message the identity signed before the switch, read after it: the
	// switch re-posted it as a retry under the certificate, so the reader
	// delivers that copy and refuses the identity's.
	if d := other.recv(); d.rc != 0 || d.refused("certificate_revoked") != 1 || !slices.Equal(d.bodies(), []string{"by the identity, read after the switch"}) {
		t.Errorf("the identity's message read after the switch: %v", d)
	}
}
