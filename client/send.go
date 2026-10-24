package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// Fields are an envelope's optional fields: the sender's own words about a
// message, encrypted with it, so the server sees none of them.
type Fields struct {
	Subject string
	// InReplyTo is the msg_id of the message this one answers, as its
	// envelope carried it: never the id the server lists a message by.
	InReplyTo string
	// Supersedes is the msg_id of an earlier message of this box's that this
	// one replaces. The earlier one is not altered: the recipient decides.
	Supersedes string
}

func (f Fields) check() error {
	if !utf8.ValidString(f.Subject) {
		return errors.New("the subject is not UTF-8 text: JSON carries text only, and would replace the bad bytes")
	}
	for _, id := range []struct{ field, value string }{{"in_reply_to", f.InReplyTo}, {"supersedes", f.Supersedes}} {
		if id.value != "" && !protocol.IsMsgID(id.value) {
			return fmt.Errorf("%s is not a msg_id: it names a message by the 36-character msg_id in its envelope, "+
				"as recv prints it and sent/ keeps it, never by the 64-character id the server gives it", id.field)
		}
	}
	return nil
}

// Sent is a message the server took: the box it went to, the msg_id its
// envelope carries, and the server's receipt for it, checked against the
// ciphertext posted. Its ID is the server's id for the message, the SHA-256 of
// the ciphertext; MsgID names the message itself, on every re-encryption.
type Sent struct {
	To    protocol.Address
	MsgID string
	protocol.Receipt
	// ACLErr is why the box's ACL, changed since its server last took one,
	// was not sent ([Box.SyncACL]): the post went ahead, since the ACL the
	// server last took admits the recipient's reply. The next send or recv
	// sends it.
	ACLErr error
}

// Send sends one logical message with none of the optional fields: see
// [Box.SendWith].
func (b *Box) Send(ctx context.Context, to protocol.Address, body string) (*Sent, error) {
	return b.SendWith(ctx, to, body, Fields{})
}

// SendWith sends one logical message: its envelope is built once and kept in
// the outbox, then sealed for the post: dated at the post, signed for that
// peer only by this box's working key, and encrypted with that signature to
// the peer's verified prekey. On 409 stale_prekey it seals the SAME envelope
// to the newer prekey, once. If the post fails, the envelope stays in the outbox:
// retry with [Box.Flush], never by sending again, or the peer gets it twice.
// Once the server has it, the envelope and the server's receipt are kept in
// sent/.
//
// Writing to a peer allows it: its replies land in inbox/, and the box's
// server is sent the box's ACL, when it changed, before anything is posted
// ([Box.SyncACL]). One the server does not take holds the message in the
// outbox only when the ACL it last took does not admit the peer's reply,
// which it would refuse for good; otherwise the message is posted, and
// Sent.ACLErr says why the ACL was not taken (#180).
//
// Before anything is posted the server is asked what it holds about the
// peer: a revocation of its address, or of its certificates.
// What verifies is kept, and the send is checked against what the box then
// holds. With no answer nothing is posted, and the message stays in the
// outbox.
//
// The signature is inside the encryption, so the server is handed none: it
// knows the sender from the pass the post carries. Every message is padded,
// after the signature, so that the server sees its size only to within a
// block (protocol.PaddedSize).
//
// Nothing is written or sent when its reader would refuse the envelope for
// its form (PROTOCOL.md §3.3, §12.3 check 3): a noncharacter in the body or the
// subject is refused here, before the outbox.
//
// It holds the box's lock from start to end ([Box.hold]), as every command
// that writes the box does.
func (b *Box) SendWith(ctx context.Context, to protocol.Address, body string, f Fields) (*Sent, error) {
	return locked(ctx, b, func() (*Sent, error) {
		env, err := protocol.NewEnvelope(b.id.Address(), to, body, b.now())
		if err != nil {
			return nil, err
		}
		return b.sendWith(ctx, to, env, f)
	})
}

// SendJSON is [Box.SendWith] with a body that is a JSON value, given as one
// JSON text, where SendWith's is text: an object, say, arrives as that object
// and not as a string holding it. It is refused whole, with nothing written,
// when its reader would refuse it (protocol.NewJSONEnvelope has the rules),
// and sent compact, as written.
func (b *Box) SendJSON(ctx context.Context, to protocol.Address, body []byte, f Fields) (*Sent, error) {
	return locked(ctx, b, func() (*Sent, error) {
		env, err := protocol.NewJSONEnvelope(b.id.Address(), to, body, b.now())
		if err != nil {
			return nil, err
		}
		return b.sendWith(ctx, to, env, f)
	})
}

func (b *Box) sendWith(ctx context.Context, to protocol.Address, env *protocol.Envelope, f Fields) (*Sent, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	env.Subject, env.InReplyTo, env.Supersedes = f.Subject, f.InReplyTo, f.Supersedes
	// The envelope carries this box's identity document, so its recipient
	// can check a sender it has never met without asking the server.
	env.Identity = b.id.Document()
	p, err := env.Line()
	if err != nil {
		return nil, err
	}
	// Read back as its reader will read it, and as seal does, before anything
	// is kept: an envelope seal refuses would wait in the outbox for good.
	var bad *protocol.EnvelopeError
	if _, err := protocol.OpenEnvelopeRecord(p, b.id.Address(), to); errors.As(err, &bad) {
		return nil, refuse("nothing is written or sent, since its reader would refuse this message: %s", bad.Why)
	} else if err != nil {
		return nil, err
	}
	if _, err := b.addTo("allowed", to); err != nil {
		return nil, err
	}
	stem := b.path("outbox", to.String()+"."+env.MsgID)
	if err := writeFile(stem+".P", p); err != nil {
		return nil, err
	}
	step("outbox written")
	aclErr := b.syncACL(ctx)
	// Shown its own revocation at its ACL, the box can never deliver it.
	if gone := ownRevoked(aclErr); gone != nil {
		return nil, b.undelivered(stem, gone)
	}
	if err := b.replyWaits(to, aclErr); err != nil {
		return nil, fmt.Errorf("%w: nothing is posted, so that no reply is refused; kept in the outbox, irongall outbox flush sends it", err)
	}
	s, err := b.post(ctx, to, stem, newLookups())
	if s != nil {
		s.ACLErr = aclErr
	}
	return s, err
}

// replyWaits is why a message to peer waits in the outbox when the box's ACL
// was not taken (aclErr): the box's own lists cannot be read, which stops a
// post as it stops a drain, or the ACL the server last took, or the none it
// holds before one, does not admit the peer's reply, which it would refuse.
// It is nil when the reply is admitted, or the ACL was taken.
func (b *Box) replyWaits(peer protocol.Address, aclErr error) error {
	if aclErr == nil {
		return nil
	}
	if _, err := b.readSenders(); err != nil {
		return err
	}
	took, err := b.tookACL()
	if err != nil {
		return errors.Join(aclErr, err)
	}
	if !took.Admits(peer) {
		return aclErr
	}
	return nil
}

// Flush posts again every message still in the outbox, each sealed afresh
// to what the box holds now, as a send seals it: a seal is made for one post
// and never kept. A message the server took whose answer was lost is posted
// again as a new ciphertext, which the server stores and counts again and
// its reader drops by its msg_id (PROTOCOL.md §12.2). It tries every entry;
// one that fails never stops the others, and the error names each that
// failed. The server is asked about each recipient once, as a send asks
// ([Box.SendWith]).
func (b *Box) Flush(ctx context.Context) ([]*Sent, error) {
	return lockedFinished(ctx, b, func() ([]*Sent, error) { return b.flush(ctx) })
}

func (b *Box) flush(ctx context.Context) ([]*Sent, error) {
	names, err := filepath.Glob(b.path("outbox", "*.P"))
	if err != nil {
		return nil, err
	}
	// A box that holds its own revocation can never deliver what waits:
	// every reader that holds the revocation refuses its mail, whenever it was
	// signed. Each entry goes to outbox/failed/, with nothing asked or sent.
	if err := b.finished(); err != nil {
		var gone *RevokedError
		if !errors.As(err, &gone) {
			return nil, err
		}
		errs := []error{err}
		for _, n := range names {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(n), b.undelivered(strings.TrimSuffix(n, ".P"), err)))
		}
		return nil, errors.Join(errs...)
	}
	var aclErr error
	if len(names) > 0 {
		aclErr = b.syncACL(ctx)
	}
	var sent []*Sent
	var errs []error
	// The recipients this flush has asked the server about: one lookup each.
	asked := newLookups()
	for _, n := range names {
		stem := strings.TrimSuffix(n, ".P")
		to, msgID, _ := strings.Cut(filepath.Base(stem), ".")
		peer, err := protocol.ParseAddress(to)
		if err == nil && !protocol.IsMsgID(msgID) {
			err = errors.New("not a msg_id")
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: not an outbox entry", filepath.Base(n)))
			continue
		}
		// Once its ACL or an entry's post has shown the box its own
		// revocation, each later entry goes to outbox/failed/ with nothing
		// asked, as at the flush's start (#340), by the box's own ended
		// state, which the keep sets (keepRevocation): the one fact.
		if b.ended != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(stem), b.undelivered(stem, b.ended)))
			continue
		}
		if err := b.replyWaits(peer, aclErr); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w: nothing is posted, so that no reply is refused", filepath.Base(stem), err))
			continue
		}
		s, err := b.post(ctx, peer, stem, asked)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(stem), err))
			continue
		}
		s.ACLErr = aclErr
		sent = append(sent, s)
	}
	return sent, errors.Join(errs...)
}

// undeliverable are the answers that never change for this message: retrying
// it can only fail again. A box's ACL that does not admit this one is among
// them: only the recipient can change it, and a message it admits later is
// one this box sends again. A server saying a box is revoked is not among
// them: that is final only once this box holds the revocation
// ([Box.proved]), so no code of provedCodes' is
// (TestNoAnswerProvedIsUndeliverable).
var undeliverable = []protocol.Code{
	protocol.CodeBadAddress, protocol.CodeTooLarge, protocol.CodeConflict, protocol.CodeSenderNotAllowed,
}

// post seals the outbox entry stem and posts it. On failure the entry stays
// in the outbox for the next flush, unless it can never be delivered: the
// server refused it for good, its recipient is revoked, or it was written
// more than protocol.TTL ago. Then it moves to outbox/failed/. Each post is
// dated afresh, so the TTL an outbox posts an entry for is counted from the
// envelope it keeps, as written: a reader's replay set reaches back that far
// past a first post (protocol.SeenFor), so a retry of a message already
// delivered is dropped by its msg_id however late it comes.
//
// Each seal reads the recipient's box first, with what the server holds of
// its revocations ([Box.resolve]). The seal is made to what this box then holds:
// nothing goes to an address it holds a revocation of, and a prekey
// statement under a certificate since revoked, or ordered before one the box
// has recorded, is refused. A read that serves no box is not "none held":
// nothing is sealed or posted, and the entry stays.
func (b *Box) post(ctx context.Context, to protocol.Address, stem string, asked *lookups) (*Sent, error) {
	if b.expired(stem) {
		return nil, b.undelivered(stem, refuse("it was written more than %d days ago, and an outbox posts a message no longer than that", protocol.TTL/(24*time.Hour)))
	}
	r, posted, err := b.trySend(ctx, to, stem, asked)
	// A revocation that verified, the recipient's or this box's own, is
	// final (proved, in call): the entry goes to outbox/failed/. A box shown
	// its own since its command began, by an entry before this one or a pass
	// refused on the way, asks nothing for this one either (call; #340).
	var gone *RevokedError
	if errors.As(err, &gone) {
		return nil, b.undelivered(stem, err)
	}
	// A read of the box is never an answer about the message: whatever code
	// a failed one carries, the entry stays.
	var unread *lookupError
	if errors.As(err, &unread) {
		return nil, fmt.Errorf("the box %s could not be read, so nothing is posted: %w (kept in the outbox: retry with irongall outbox flush)", to, err)
	}
	if err != nil {
		// A server's "revoked" without the revocation in hand is a call that
		// failed. So is its word that this box's certificate is revoked: the
		// entry then waits for the renewal, as a seal under a certificate the
		// box holds revoked does.
		if !slices.Contains(undeliverable, code(err)) {
			return nil, fmt.Errorf("%w (kept in the outbox: retry with irongall outbox flush)", err)
		}
		return nil, b.undelivered(stem, err)
	}
	step("posted")
	// Recorded before the outbox entry goes: a crash in between seals and
	// posts it again, and its reader drops the copy by its msg_id.
	sent, err := b.recordSent(stem, posted, r)
	if err != nil {
		return nil, fmt.Errorf("sent, but not recorded in sent/ (still in the outbox: irongall outbox flush posts it again, and its reader drops the copy): %w", err)
	}
	step("sent kept")
	if err := removeIfExists(stem + ".P"); err != nil {
		return sent, err
	}
	return sent, nil
}

// recordSent keeps a sent message in sent/, named <address>.<msg_id> by the
// envelope posted: one line of JSON, {"envelope":…,"receipt":…}, the
// envelope as that post signed it (signed), as the recipient's recv
// delivers it, and the server's answer to that post. The envelope's members
// are only ever inside "envelope", so one it gains later never meets the
// record's own (#356). The client never deletes from sent/.
func (b *Box) recordSent(stem string, signed []byte, r *protocol.Receipt) (*Sent, error) {
	to, _, _ := strings.Cut(filepath.Base(stem), ".")
	peer, err := protocol.ParseAddress(to)
	if err != nil {
		return nil, errors.New("not an outbox entry")
	}
	// Read as its recipient reads it, but for its age, and written as its
	// recipient's recv writes it: the checked fields, without the identity
	// document.
	env, err := protocol.OpenEnvelopeRecord(signed, b.id.Address(), peer)
	if err != nil {
		return nil, errors.New("the posted envelope is not one this box made for that address")
	}
	env.Identity = nil
	p, err := env.Marshal()
	if err != nil {
		return nil, err
	}
	receipt, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	line := slices.Concat([]byte(`{"envelope":`), p, []byte(`,"receipt":`), receipt, []byte("}"))
	if !json.Valid(line) {
		return nil, errors.New("the outbox entry's envelope is not a JSON object")
	}
	if err := os.MkdirAll(b.path("sent"), 0o700); err != nil {
		return nil, err
	}
	// Named, and said, by the envelope posted, never by the outbox entry's
	// name, which nothing holds to it (#270).
	sent := &Sent{To: peer, MsgID: env.MsgID, Receipt: *r}
	return sent, writeFile(b.path("sent", peer.String()+"."+env.MsgID+".json"), escapeUnseen(line))
}

// undelivered moves an entry that can never be delivered to outbox/failed/,
// and returns why with that said.
func (b *Box) undelivered(stem string, why error) error {
	if err := b.moveToFailed(stem); err != nil {
		return errors.Join(why, err)
	}
	return fmt.Errorf("%w (it can never be delivered: moved to outbox/failed/)", why)
}

// trySend seals the entry and posts it, and on 409 stale_prekey seals the
// same envelope to the newer prekey and posts that, once. A seal is made for
// one post and never kept: what a message waited for in the outbox is its
// envelope, and what it is dated and sealed to is the post's. It returns the
// envelope's line as the post that was taken signed it.
func (b *Box) trySend(ctx context.Context, to protocol.Address, stem string, l *lookups) (*protocol.Receipt, []byte, error) {
	req, err := b.seal(ctx, to, stem, l)
	if err != nil {
		return nil, nil, err
	}
	r, err := b.postSealed(ctx, to, req)
	if code(err) == protocol.CodeStalePrekey {
		if req, err = b.seal(ctx, to, stem, l); err != nil {
			return nil, nil, err
		}
		r, err = b.postSealed(ctx, to, req)
	}
	return r, req.line, err
}

// expired reports whether an entry was written more than protocol.TTL ago,
// by its envelope as the outbox keeps it: the longest an outbox posts one.
func (b *Box) expired(stem string) bool {
	t, ok := b.sentAt(stem)
	return ok && t.Before(b.now().Add(-protocol.TTL))
}

// sentAt returns the sent_at of an outbox entry's envelope as the outbox
// keeps it: when the entry was written.
func (b *Box) sentAt(stem string) (time.Time, bool) {
	p, err := os.ReadFile(stem + ".P") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return time.Time{}, false
	}
	var e struct {
		SentAt string `json:"sent_at"`
	}
	if protocol.Unmarshal(p, &e) != nil {
		return time.Time{}, false
	}
	t, err := protocol.ParseTime(e.SentAt)
	return t, err == nil
}

// moveToFailed moves an outbox entry's files to outbox/failed/, where flush
// no longer sees them, and syncs both directories, the one it left and the
// one it is in. Delete them there to drop the message.
func (b *Box) moveToFailed(stem string) error {
	failed := b.path("outbox", "failed")
	if err := os.MkdirAll(failed, 0o700); err != nil {
		return err
	}
	err := os.Rename(stem+".P", filepath.Join(failed, filepath.Base(stem)+".P"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := syncDir(failed); err != nil {
		return err
	}
	return syncDir(filepath.Dir(stem))
}

// sealed is a seal made for one post: the ciphertext, the whole body of the
// send, the query that names the prekey it is encrypted to, and the
// envelope's line as it signed it, dated at the post.
type sealed struct {
	query      protocol.SendQuery
	ciphertext []byte
	line       []byte
}

func (b *Box) postSealed(ctx context.Context, to protocol.Address, s *sealed) (*protocol.Receipt, error) {
	// The post carries this box's pass: that is how the server knows the
	// sender.
	var r protocol.Receipt
	if _, err := b.owner(ctx, http.MethodPost, "/v1/"+to.String()+"/messages?"+s.query.Encode(), &ciphertext{bytes: s.ciphertext}, &r); err != nil {
		return nil, err
	}
	// A receipt names the ciphertext it is for, and this box knows which
	// that is: one that names another, or whose times are not times, is no
	// receipt, and the entry stays (PROTOCOL.md §11.10). So what send and
	// flush print of it is what this box computed.
	h := sha256.Sum256(s.ciphertext)
	_, rerr := protocol.ParseTime(r.ReceivedAt)
	_, eerr := protocol.ParseTime(r.ExpiresAt)
	if r.ID != hex.EncodeToString(h[:]) || rerr != nil || eerr != nil {
		return nil, refuse("the server's receipt does not name the ciphertext this box posted, or its times are not times")
	}
	return &r, nil
}

// seal dates the entry's envelope at this post, signs it for the peer only,
// with the working key in use, and encrypts the envelope, the signature and
// the padding to the peer's VERIFIED current prekey, and returns what to
// post. Nothing of it is written: the outbox keeps the envelope as written,
// and a seal is made again for every post.
//
// The dating sets the envelope's sent_at, and comes last, once the
// recipient's box is read: a post's sent_at is its sender's clock at that
// post, as a signed request's time is when it was signed, made anew for each
// attempt (PROTOCOL.md §9.1, §12.2), so the server keeps a message about as
// long as its reader takes it (protocol.Retention). The line is written again
// by the envelope's one writer (Envelope.Line), as sendWith wrote the entry:
// the outbox is this box's own, which no other client writes. It is read back
// as the envelope it was, dated at this post, before it is signed. The msg_id
// stays, and the reader drops a retry by it.
//
// The envelope is read as its recipient will read it, so one the recipient
// would refuse is never sealed. The padding is made here, for the prekey's
// type: an encryption after stale_prekey may be to a prekey of the other
// type. It is outside what is signed, so the signature is over the envelope
// as dated.
func (b *Box) seal(ctx context.Context, to protocol.Address, stem string, l *lookups) (*sealed, error) {
	written, err := os.ReadFile(stem + ".P") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return nil, err
	}
	env, err := protocol.OpenEnvelopeRecord(written, b.id.Address(), to)
	if err != nil || !bytes.Equal(env.Identity, b.id.Document()) || !bytes.HasSuffix(written, []byte("\n")) {
		return nil, refuse("the outbox entry is not an envelope this box made for that address")
	}
	worker, cert, err := b.currentWorker()
	if err != nil {
		return nil, err
	}
	// A certificate this box's own identity has revoked signs no mail: every
	// reader that holds the revocation refuses it, whatever this box's server
	// took. That is the remedy's window while its renewal waits (PROTOCOL.md
	// §12.6): the entry waits too. A kept revocation that does not verify is a
	// fault, never "nothing revoked".
	if held, err := b.revokedCerts(b.id.Address()); err != nil {
		return nil, err
	} else if held != nil && held.Revokes(cert.Serial()) {
		return nil, refuse("this box's identity has revoked the certificate it signs under, so mail signed now would be refused: irongall recv or irongall prekey renew publishes the new one first")
	}
	// Mail may wait 33 days to be read, and its certificate must still be
	// valid then.
	if !cert.SignsMail(b.now()) {
		return nil, refuse("this box's certificate ends within %d days, too soon to sign mail that may wait that long: irongall prekey renew makes a new one, as irongall recv does daily", protocol.TTL/(24*time.Hour))
	}
	pk, under, err := b.resolve(ctx, to, l)
	if err != nil {
		return nil, err
	}
	// Dated last, once the recipient's box is read: the sent_at a server
	// meets is this clock at the post, less only what the seal and the
	// second the dating truncates take (protocol.PostTime). And dated within
	// the outbox's TTL from when the entry was written, however long the
	// read took, however the clock moved meanwhile and however often a seal
	// is made again: never before it was written, and never more than a TTL
	// after. So every copy is dated within a TTL of every other, and the
	// line a reader keeps of the copy it delivered, protocol.SeenFor past its
	// sent_at, is there when any other comes. An entry written while the
	// clock read ahead of where it reads now waits in the outbox until the
	// clock passes that time (#334).
	wrote := env.SentAt
	env.SentAt = b.now().UTC().Truncate(time.Second)
	if env.SentAt.Before(wrote) {
		return nil, refuse("its envelope is dated %s, ahead of this machine's clock: it was written while the clock read ahead of where it reads now, and the outbox counts its 33 days from when it was written, so it is posted once the clock passes that time", wrote.Format(protocol.TimeLayout))
	}
	if env.SentAt.After(wrote.Add(protocol.TTL)) {
		return nil, refuse("it was written more than %d days ago, and an outbox posts a message no longer than that", protocol.TTL/(24*time.Hour))
	}
	line, err := env.Line()
	if err != nil {
		return nil, err
	}
	if dated, err := protocol.OpenEnvelopeRecord(line, b.id.Address(), to); err != nil || !sameEnvelope(dated, env) {
		return nil, refuse("the outbox entry does not read back as itself once dated at this post")
	}
	r, err := pk.Recipient()
	if err != nil {
		return nil, err
	}
	sig, err := worker.Signature(line, protocol.MessageNamespace(to))
	if err != nil {
		return nil, err
	}
	plaintext, size := protocol.Plaintext(line, sig, pk.Type())
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, r)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if ct.Len() != size {
		return nil, refuse("the encrypted message is %d bytes, where its padding was made for %d: it is not sent at a size that tells its length", ct.Len(), size)
	}
	// The prekey is named by both serials: its own, and that of the
	// certificate resolve verified it under. Never read back from what the
	// box recorded: that is the highest seen, which another statement may
	// have raised.
	return &sealed{query: protocol.SendQuery{PrekeySerial: pk.Serial, CertificateSerial: under.Serial()}, ciphertext: ct.Bytes(), line: line}, nil
}

// sameEnvelope reports whether two envelopes are one message, dated alike.
func sameEnvelope(a, b *protocol.Envelope) bool {
	return a.From == b.From && a.To == b.To && a.SentAt.Equal(b.SentAt) && a.MsgID == b.MsgID &&
		bytes.Equal(a.Body, b.Body) && a.Subject == b.Subject && a.InReplyTo == b.InReplyTo &&
		a.Supersedes == b.Supersedes && bytes.Equal(a.Identity, b.Identity)
}
