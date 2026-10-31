package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dromas-dev/dromas-client/client/internal/sign"
	"github.com/dromas-dev/dromas-client/protocol"
)

// A mailbox is in one of two modes (PROTOCOL.md §5). In identity mode, the
// default, its identity signs its prekey statements, its passes and its
// messages. In working-key mode its identity certifies a working key with
// each prekey, and the working key signs them. The mode is read from the
// revocation of its certificates the mailbox keeps, never kept apart from it
// (PROTOCOL.md §12.1): with none it is in identity mode, and with one,
// through any serial, in working-key mode, for good. The first such
// revocation is the trip (PROTOCOL.md §10.2), which the identity signs; every
// holder of it then refuses the identity's own signature on a statement, a
// pass or a message.
//
// A mailbox records each trip it makes before signing it (intent "trip"), as
// begin records a renewal, and keeps that record for good. A trip it keeps
// with no such record, once it has published a statement of its own, it did
// not make: whoever signed it holds its identity. It says so, recommends
// revoking the address, and signs nothing more but that revocation
// (ForeignTripError, sign). One that has published nothing, a restore or an
// init, takes a trip a server serves or its owner hands over as its mode,
// and records it then (keepRevokedCerts).

// ForeignTripError is a trip to working-key mode this mailbox keeps and did
// not make: its identity signed it, so the identity is in other hands.
type ForeignTripError struct {
	// Through is the serial the revocation of certificates runs through.
	Through uint64
}

func (e *ForeignTripError) Error() string {
	return fmt.Sprintf("this mailbox keeps a revocation of its certificates, through serial %d, that its identity signed and this mailbox did not make: it moves the address to working-key mode, which only the identity's holder can do, so the identity is in other hands. This mailbox signs nothing more but its address's revocation: dromas revocation publish, with the address in full, ends the address for good, and its correspondents need a new one", e.Through)
}

// checks is what the mailbox says at each signature (sign): whether it holds
// its own revocation, and its mode.
func (b *Mailbox) checks() sign.Checks {
	return sign.Checks{Finished: b.finished, Mode: b.mode}
}

// mode is the mailbox's mode, from the revocation of its certificates it
// keeps, or a [ForeignTripError] for one it did not make. A kept revocation
// that no longer verifies is an error, never identity mode.
func (b *Mailbox) mode() (sign.Mode, error) {
	certs, err := b.revokedCerts(b.id.Address())
	if err != nil || certs == nil {
		return sign.IdentityMode, err
	}
	var made bool
	if err := b.view(func(s store) error { made = s.get(bucketIntent, "trip") != nil; return nil }); err != nil {
		return sign.WorkingKeyMode, err
	}
	if !made {
		return sign.WorkingKeyMode, &ForeignTripError{Through: certs.Through}
	}
	return sign.WorkingKeyMode, nil
}

// inWorkingKeyMode reports whether the mailbox is in working-key mode, by a
// trip it did not make among them.
func (b *Mailbox) inWorkingKeyMode() (bool, error) {
	m, err := b.mode()
	var foreign *ForeignTripError
	if errors.As(err, &foreign) {
		err = nil
	}
	return m == sign.WorkingKeyMode, err
}

// signer is what signs a mailbox's statements, passes and messages: its
// identity in identity mode (sign.Identity), or a working key in working-key
// mode (sign.Work).
type signer interface {
	Statement(*protocol.Prekey) ([]byte, error)
	Message(line []byte, to protocol.Address) ([]byte, error)
	Pass(a protocol.Address, server string, now time.Time) (string, time.Time, error)
}

// signerOf is the signer of statement n, as this mailbox signed it: its
// identity, or working key n under its certificate, which it returns too. A
// statement of the mode the mailbox is no longer in has no signer: sign says
// why.
func (b *Mailbox) signerOf(n uint64) (signer, *protocol.Certificate, error) {
	rank, err := b.rankOf(n)
	if err != nil {
		return nil, nil, err
	}
	if rank == 0 {
		id, err := b.certifier.Identity()
		if err != nil {
			return nil, nil, err
		}
		return id, nil, nil
	}
	w, c, err := b.worker(n)
	if err != nil {
		return nil, nil, err
	}
	return w, c, nil
}

// rankOf is the rank of the signer of statement n, as this mailbox keeps it:
// 0 for its identity, n for working key n (PROTOCOL.md §5).
func (b *Mailbox) rankOf(n uint64) (uint64, error) {
	rec, err := b.prekeyOf(n)
	if err != nil {
		return 0, err
	}
	if rec == nil {
		return 0, fmt.Errorf("the mailbox's state file keeps no statement of prekey %d", n)
	}
	o, err := protocol.PrekeyOrder(rec.Statement, rec.Signature)
	if err != nil {
		return 0, fmt.Errorf("the mailbox's state file keeps a statement of prekey %d that does not parse: %w", n, err)
	}
	return o.Rank, nil
}

// currentSigner is the signer of the statement this mailbox published last.
func (b *Mailbox) currentSigner() (signer, *protocol.Certificate, error) {
	n, err := b.publishedSerial()
	if err != nil {
		return nil, nil, err
	}
	if n == 0 {
		return nil, nil, errors.New("this mailbox has published no prekey: dromas init registers it, and dromas prekey renew recovers one restored from its identity")
	}
	return b.signerOf(n)
}

// usesRevoked reports whether this mailbox's own revocation of its
// certificates covers the signer of the statement it published last: a
// certificate at or below it, or its identity, which ranks 0, once it holds
// any. Such a mailbox takes no messages and signs none until it publishes a
// statement under a certificate above it. One it cannot read covers nothing
// here: whoever reads it to apply it says so.
func (b *Mailbox) usesRevoked() bool {
	n, err := b.publishedSerial()
	if err != nil || n == 0 {
		return false
	}
	rank, err := b.rankOf(n)
	return err == nil && b.ownRevokes(rank)
}

// noRoom is the refusal of working-key mode at a server whose maximum leaves
// a certificate no time to sign messages in.
func noRoom(max time.Duration) error {
	return refuse("this mailbox's server takes no certificate longer than %d seconds, which leaves none to sign messages under: a message is signed only under a certificate with more than %d days left, and one begins an hour before it is made, so working-key mode is refused here; identity mode, the default, needs no certificate", int64(max/time.Second), protocol.TTL/(24*time.Hour))
}

// certificateLifetime is how long a certificate this mailbox makes runs: the
// longest its server takes, max_certificate_lifetime in its document
// (PROTOCOL.md §11.18), read once a command, and never past
// protocol.LastDate. A maximum that leaves no room to sign messages, the TTL
// and the hour a certificate begins before it is made, refuses working-key
// mode (noRoom).
func (b *Mailbox) certificateLifetime(ctx context.Context) (time.Duration, error) {
	if b.lifetime > 0 {
		return b.lifetime, nil
	}
	var d protocol.ServerDocument
	if _, err := b.call(ctx, http.MethodGet, protocol.DocumentPath, nil, nil, &d); err != nil {
		return 0, fmt.Errorf("this mailbox's server's document could not be read, so no certificate is made: a certificate runs for the longest the server takes, which the document names: %w", err)
	}
	life := time.Duration(math.MaxInt64)
	if d.MaxCertificateLifetime < uint64(math.MaxInt64/int64(time.Second)) {
		life = time.Duration(d.MaxCertificateLifetime) * time.Second //nolint:gosec // bounded above
	}
	if life <= protocol.TTL+protocol.MaxSkew {
		return 0, noRoom(life)
	}
	if last := protocol.LastDate.Sub(b.now().Add(-protocol.MaxSkew)); life > last {
		life = last.Truncate(time.Second)
	}
	b.lifetime = life
	return life, nil
}

// trip makes the trip to working-key mode, unless the mailbox keeps one: a
// revocation of its certificates through the serial below the one its clock
// gives above known (protocol.SerialAt), signed by its identity, published
// to its server as §10.3's record, and kept (PROTOCOL.md §10.2). The number is
// recorded first, as the trip this mailbox makes, and an attempt that did not
// finish is made again at that number. A server that holds a higher one
// answers conflict: the mailbox reads itself (known), which keeps that one.
// It reports whether its server holds the trip by it: one it kept before is
// the caller's to publish where its server holds none.
func (b *Mailbox) trip(ctx context.Context, known uint64) (bool, error) {
	own := b.id.Address()
	if held, err := b.revokedCerts(own); err != nil || held != nil {
		return false, err
	}
	var through uint64
	if err := b.view(func(s store) error {
		var err error
		through, err = decimal(s.get(bucketIntent, "trip"), "trip")
		return err
	}); err != nil {
		return false, err
	}
	if through == 0 {
		through = max(protocol.SerialAt(b.now(), known)-1, 1)
		if err := noneAbove(through); err != nil {
			return false, err
		}
		if err := b.update(func(s store) error {
			return s.put(bucketIntent, "trip", fmt.Appendf(nil, "%d", through))
		}); err != nil {
			return false, err
		}
	}
	step("trip begun")
	certs, err := protocol.NewRevokedCertificates(own, through)
	if err != nil {
		return false, err
	}
	sig, err := b.certifier.RevokedCertificates(certs)
	if err != nil {
		return false, err
	}
	rec := &protocol.Revocations{Identity: b.id.Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
	switch err := b.publishRecord(ctx, own, rec); {
	case err == nil:
		step("trip published")
		if err := b.keepRevokedCerts(own, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
			return false, err
		}
	case code(err) == protocol.CodeConflict:
		if _, kerr := b.known(ctx); kerr != nil {
			return false, errors.Join(err, kerr)
		}
		if held, herr := b.revokedCerts(own); herr != nil || held == nil {
			return false, errors.Join(err, herr)
		}
	default:
		return false, err
	}
	step("trip kept")
	return true, nil
}

// publishTrip publishes the revocation of its certificates this mailbox keeps
// to its server, which holds none: at a server that never held the address,
// before the first statement under a certificate, and on 409 identity_mode
// (PROTOCOL.md §11.7). A server that holds a higher one answers conflict, and
// the mailbox keeps that one (known).
func (b *Mailbox) publishTrip(ctx context.Context) error {
	rec, err := b.certificatesRecord()
	if err != nil {
		return err
	}
	if rec == nil {
		return errors.New("this mailbox keeps no revocation of its certificates to publish")
	}
	err = b.publishRecord(ctx, b.id.Address(), rec)
	if code(err) == protocol.CodeConflict {
		_, err = b.known(ctx)
	}
	return err
}

// Mode is the mailbox's mode, as it keeps it (PROTOCOL.md §5): "identity" or
// "working_key". A trip the mailbox did not make is its error, a
// [ForeignTripError], beside "working_key".
func (b *Mailbox) Mode(ctx context.Context) (string, error) {
	return reading(ctx, b, func() (string, error) {
		m, err := b.mode()
		return modeName(m), err
	})
}

// modeName is how a mode is named in what a mailbox prints.
func modeName(m sign.Mode) string {
	if m == sign.WorkingKeyMode {
		return "working_key"
	}
	return "identity"
}

// SwitchCost is what moving a mailbox to working-key mode costs, said before
// anything is done (PROTOCOL.md §15).
const SwitchCost = "Moving this mailbox to working-key mode is for good. Every message it sent, signed by its identity, that a reader has not read yet is refused by that reader once it holds the revocation that moves the address, and is lost: the switch posts again each one sent/ keeps from the last 33 days, under the new certificate, and a reader that read the first copy drops the second by its msg_id. Until its server takes its first statement under a certificate, this mailbox sends and drains nothing"

// Switched is what [Mailbox.Switch] did.
type Switched struct {
	// Prekey is the first statement under a certificate, when this call
	// published it.
	Prekey *protocol.Prekey
	// Retried are the messages sent/ kept that were posted again under the
	// certificate, and NotRetried why the rest wait in the outbox, or nil.
	Retried    []*Sent
	NotRetried error
}

// Switch moves a mailbox in identity mode to working-key mode, at the cost
// SwitchCost says, which its caller says first: it makes the trip, through
// the serial below its clock (trip), publishes its first statement under a
// certificate above it, and posts again as retries the messages sent/ keeps
// that are younger than protocol.TTL: each with its msg_id, dated anew at
// its post and signed under the certificate (PROTOCOL.md §12.2). A switch is
// recorded before the trip (intent "switch"), so one cut short goes on where
// it stopped, at the next Switch; recv publishes the first statement too,
// as a renewal of a mailbox its own revocation covers. A server whose
// maximum leaves a certificate no room refuses it before anything is done
// (noRoom).
func (b *Mailbox) Switch(ctx context.Context) (*Switched, error) {
	return locked(ctx, b, func() (*Switched, error) { return b.switchMode(ctx) })
}

func (b *Mailbox) switchMode(ctx context.Context) (*Switched, error) {
	var switching bool
	if err := b.view(func(s store) error { switching = s.get(bucketIntent, "switch") != nil; return nil }); err != nil {
		return nil, err
	}
	m, err := b.mode()
	if err != nil {
		return nil, err
	}
	published, err := b.publishedSerial()
	if err != nil {
		return nil, err
	}
	switch {
	case switching:
	case m == sign.WorkingKeyMode:
		return nil, refuse("this mailbox is in working-key mode already")
	case published == 0:
		return nil, refuse("this mailbox has published no statement to switch from: dromas init --offline makes or restores a mailbox in working-key mode")
	}
	// What its server holds of it first, its revocations kept: a trip it did
	// not make stops the switch before anything is recorded.
	st, err := b.readOwn(ctx, false, false)
	if err != nil {
		return nil, err
	}
	if _, err := b.mode(); err != nil {
		return nil, err
	}
	if !switching {
		if _, err := b.certificateLifetime(ctx); err != nil {
			return nil, err
		}
		if err := b.update(func(s store) error { return s.put(bucketIntent, "switch", []byte{}) }); err != nil {
			return nil, err
		}
		step("switch begun")
	}
	made, err := b.trip(ctx, st.known)
	if err != nil {
		return nil, err
	}
	st.trip = st.trip || made
	out := &Switched{}
	if b.usesRevoked() {
		p, at, err := b.renewFrom(ctx, st)
		if err != nil {
			return out, err
		}
		out.Prekey = p
		if err := b.prune(at); err != nil {
			return out, err
		}
	}
	if err := b.retries(); err != nil {
		return out, err
	}
	if err := b.update(func(s store) error { return s.del(bucketIntent, "switch") }); err != nil {
		return out, err
	}
	step("retries written")
	out.Retried, out.NotRetried = b.flush(ctx)
	return out, nil
}

// retries writes into the outbox, as entries to post again, the messages
// sent/ keeps that were sent less than protocol.TTL ago, each as its
// envelope was posted with the mailbox's identity document, unless the
// outbox holds one of that name already. A record that does not read as an
// envelope this mailbox made is passed over.
func (b *Mailbox) retries() error {
	names, err := filepath.Glob(b.path("sent", "*.json"))
	if err != nil {
		return err
	}
	for _, name := range names {
		stem := b.path("outbox", strings.TrimSuffix(filepath.Base(name), ".json"))
		if exists(stem + ".P") {
			continue
		}
		raw, err := os.ReadFile(name) //nolint:gosec // a path inside the mailbox's own directory
		if err != nil {
			return err
		}
		env, ok := b.sentEnvelope(filepath.Base(stem), raw)
		if !ok || !env.SentAt.After(b.now().Add(-protocol.TTL)) {
			continue
		}
		env.Identity = b.id.Document()
		line, err := env.Line()
		if err != nil {
			continue
		}
		if err := writeFile(stem+".P", line); err != nil {
			return err
		}
	}
	return nil
}

// sentEnvelope is the envelope a sent/ record named <address>.<msg_id>, name,
// keeps, read back as one this mailbox made for that address under that
// msg_id (recordSent).
func (b *Mailbox) sentEnvelope(name string, raw []byte) (*protocol.Envelope, bool) {
	to, msgID, _ := strings.Cut(name, ".")
	peer, err := protocol.ParseAddress(to)
	if err != nil {
		return nil, false
	}
	var rec struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	if protocol.Unmarshal(raw, &rec) != nil {
		return nil, false
	}
	env, err := protocol.OpenEnvelopeRecord(rec.Envelope, b.id.Address(), peer)
	if err != nil || env.MsgID != msgID {
		return nil, false
	}
	return env, true
}
