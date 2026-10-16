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
}

// Send sends one logical message with none of the optional fields: see
// [Box.SendWith].
func (b *Box) Send(ctx context.Context, to protocol.Address, body string) (*Sent, error) {
	return b.SendWith(ctx, to, body, Fields{})
}

// SendWith sends one logical message: its envelope is built once and kept in
// the outbox, signed for that peer only by this box's working key, encrypted
// with that signature to the peer's verified prekey, then posted. On 409
// stale_prekey it encrypts the SAME envelope to the newer prekey, once. If
// the post fails, the message stays in the outbox: retry with [Box.Flush],
// never by sending again, or the peer gets it twice. Once the server has it,
// the envelope and the server's receipt are kept in sent/.
//
// Writing to a peer allows it: its replies land in inbox/, and under
// "server allowed" the box's server is sent the box's ACL with it before
// anything is posted ([Box.SyncACL]), so that the reply is not refused.
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
// its form (PROTOCOL.md §0b, §5 check 3): a noncharacter in the body or the
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
	if err := b.syncACL(ctx); err != nil {
		return nil, fmt.Errorf("%w: nothing is posted, so that no reply is refused; kept in the outbox, irongall outbox flush sends it", err)
	}
	r, err := b.post(ctx, to, stem, newLookups())
	if err != nil {
		return nil, err
	}
	return &Sent{To: to, MsgID: env.MsgID, Receipt: *r}, nil
}

// Flush re-posts every message still in the outbox, unchanged: a retry of a
// message the server already holds gets its original receipt. It tries every
// entry; one that fails never stops the others, and the error names each
// that failed. The server is asked about each recipient once, as a send
// asks ([Box.SendWith]).
func (b *Box) Flush(ctx context.Context) ([]*Sent, error) {
	return locked(ctx, b, func() ([]*Sent, error) { return b.flush(ctx) })
}

func (b *Box) flush(ctx context.Context) ([]*Sent, error) {
	names, err := filepath.Glob(b.path("outbox", "*.P"))
	if err != nil {
		return nil, err
	}
	if len(names) > 0 {
		if err := b.syncACL(ctx); err != nil {
			return nil, fmt.Errorf("%w: nothing is posted, so that no reply is refused", err)
		}
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
		r, err := b.post(ctx, peer, stem, asked)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(stem), err))
			continue
		}
		sent = append(sent, &Sent{To: peer, MsgID: msgID, Receipt: *r})
	}
	return sent, errors.Join(errs...)
}

// undeliverable are the answers that never change for this message: retrying
// it can only fail again. A box's ACL that does not admit this one is among
// them: only the recipient can change it, and a message it admits later is
// one this box sends again. A server saying a box is revoked is not among
// them: that is final only once this box holds the revocation
// ([Box.proved]).
var undeliverable = []protocol.Code{
	protocol.CodeBadAddress, protocol.CodeTooLarge, protocol.CodeConflict, protocol.CodeSenderNotAllowed,
}

// post posts the outbox entry stem, sealing it first if it is not sealed. On
// failure the entry stays in the outbox for the next flush, unless it can
// never be delivered: the server refused it for good, its recipient is
// revoked, or its envelope is older than any recipient accepts. Then it
// moves to outbox/failed/. An entry already that old is never posted: the
// server would take it and give a receipt, and the recipient would refuse it.
//
// Before an entry is posted, sealed or not, the server is asked what it
// holds about the recipient (ask), and the entry is checked against what
// this box then holds: nothing goes to an address it holds a revocation of,
// and a seal made to a prekey under a certificate since revoked is made
// again (sealStands). No answer is not "none held": nothing is posted, and
// the entry stays.
func (b *Box) post(ctx context.Context, to protocol.Address, stem string, asked *lookups) (*protocol.Receipt, error) {
	if b.expired(stem) {
		return nil, b.undelivered(stem, refuse("its envelope is older than %d days, and every recipient refuses that", protocol.TTL/(24*time.Hour)))
	}
	// An envelope dated ahead of this machine's clock was written while the
	// clock read ahead of where it reads now. It is not posted, sealed or
	// not, until the clock passes that time: a reader takes a sent_at up to
	// MaxSkew ahead of its own clock, which is the room for two clocks a
	// server takes, and has none to spare for one that was wrong.
	if t, ok := b.sentAt(stem); ok && t.After(b.now()) {
		return nil, refuse("its envelope is dated %s, ahead of this machine's clock: it was written while the clock read ahead of where it reads now, and a recipient would refuse it. It is kept in the outbox, and irongall outbox flush sends it once the clock passes that time", t.Format(protocol.TimeLayout))
	}
	// The answer to this question is never read as an answer about the
	// message: whatever code a failed lookup carries, the entry stays.
	gone, err := b.ask(ctx, to, asked)
	if err != nil {
		return nil, fmt.Errorf("what the server holds about %s could not be asked, so nothing is posted: %w (kept in the outbox: retry with irongall outbox flush)", to, err)
	}
	if gone {
		return nil, b.undelivered(stem, &RevokedError{Address: to, Own: to == b.id.Address()})
	}
	r, err := b.trySend(ctx, to, stem)
	if err != nil {
		// A server's "revoked" is checked: with the revocation in hand it is
		// final, and without one it is a call that failed.
		err = b.proved(ctx, to, err, asked)
		var gone *RevokedError
		if !errors.As(err, &gone) && !slices.Contains(undeliverable, Code(err)) {
			return nil, fmt.Errorf("%w (kept in the outbox: retry with irongall outbox flush)", err)
		}
		return nil, b.undelivered(stem, err)
	}
	// Recorded before the outbox entry goes: a crash in between posts it
	// again, gets the original receipt, and records it again.
	if err := b.recordSent(stem, r); err != nil {
		return r, fmt.Errorf("sent, but not recorded in sent/ (still in the outbox: irongall outbox flush records it): %w", err)
	}
	for _, ext := range []string{".P", ".age", ".sig", ".json"} {
		if err := removeIfExists(stem + ext); err != nil {
			return r, err
		}
	}
	return r, nil
}

// recordSent keeps a sent message in sent/, under its outbox name,
// <address>.<msg_id>: its envelope as one line of JSON, as the recipient's
// recv delivers it, with one more member, "receipt", the server's answer.
// The client never deletes from sent/.
func (b *Box) recordSent(stem string, r *protocol.Receipt) error {
	signed, err := os.ReadFile(stem + ".P") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return err
	}
	to, _, _ := strings.Cut(filepath.Base(stem), ".")
	peer, err := protocol.ParseAddress(to)
	if err != nil {
		return errors.New("not an outbox entry")
	}
	// Read as its recipient reads it, but for its age, and written as its
	// recipient's recv writes it: the checked fields, without the identity
	// document.
	env, err := protocol.OpenEnvelopeRecord(signed, b.id.Address(), peer)
	if err != nil {
		return errors.New("the outbox entry's envelope is not one this box made for that address")
	}
	env.Identity = nil
	p, err := env.Marshal()
	if err != nil {
		return err
	}
	receipt, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// The receipt goes in as the last member.
	if !json.Valid(p) || !bytes.HasSuffix(p, []byte("}")) {
		return errors.New("the outbox entry's envelope is not a JSON object")
	}
	line := slices.Concat(p[:len(p)-1], []byte(`,"receipt":`), receipt, []byte("}"))
	if !json.Valid(line) {
		return errors.New("the outbox entry's envelope is not a JSON object")
	}
	if err := os.MkdirAll(b.path("sent"), 0o700); err != nil {
		return err
	}
	return writeFile(b.path("sent", filepath.Base(stem)+".json"), []byte(lineBreaks.Replace(string(line))))
}

// undelivered moves an entry that can never be delivered to outbox/failed/,
// and returns why with that said.
func (b *Box) undelivered(stem string, why error) error {
	if err := b.moveToFailed(stem); err != nil {
		return errors.Join(why, err)
	}
	return fmt.Errorf("%w (it can never be delivered: moved to outbox/failed/)", why)
}

func (b *Box) trySend(ctx context.Context, to protocol.Address, stem string) (*protocol.Receipt, error) {
	stands, err := b.sealStands(to, stem)
	if err != nil {
		return nil, err
	}
	if !stands {
		if err := b.seal(ctx, to, stem); err != nil {
			return nil, err
		}
	}
	r, err := b.postSealed(ctx, to, stem)
	if Code(err) == protocol.CodeStalePrekey {
		if err := b.seal(ctx, to, stem); err != nil {
			return nil, err
		}
		r, err = b.postSealed(ctx, to, stem)
	}
	return r, err
}

// sealStands reports whether the entry is sealed, to a prekey this box would
// still seal to by what it holds. An entry may wait in the outbox for days,
// and its recipient's identity may revoke, meanwhile, the certificate its
// prekey was signed under: that prekey may be one a thief of the working key
// published. Such a seal is not posted. It is made again, to a prekey whose
// statement passes every check now ([Box.Resolve]). So is one this client
// cannot read, or one that names no certificate.
func (b *Box) sealStands(to protocol.Address, stem string) (bool, error) {
	j, err := os.ReadFile(stem + ".json") //nolint:gosec // a path inside the box's own directory
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var req struct {
		CertificateSerial *uint64 `json:"certificate_serial"`
	}
	if protocol.Unmarshal(j, &req) != nil || req.CertificateSerial == nil {
		return false, nil
	}
	certs, err := b.revokedCerts(to)
	if err != nil {
		return false, err
	}
	return certs == nil || !certs.Revokes(*req.CertificateSerial), nil
}

// expired reports whether an entry's envelope is older than protocol.TTL, the
// most a recipient accepts: past that, every recipient refuses it as stale.
func (b *Box) expired(stem string) bool {
	t, ok := b.sentAt(stem)
	return ok && t.Before(b.now().Add(-protocol.TTL))
}

// sentAt returns the sent_at of an outbox entry's envelope.
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
// no longer sees them. Delete them there to drop the message.
func (b *Box) moveToFailed(stem string) error {
	failed := b.path("outbox", "failed")
	if err := os.MkdirAll(failed, 0o700); err != nil {
		return err
	}
	for _, ext := range []string{".P", ".age", ".sig", ".json"} {
		err := os.Rename(stem+ext, filepath.Join(failed, filepath.Base(stem)+ext))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return syncDir(failed)
}

func (b *Box) postSealed(ctx context.Context, to protocol.Address, stem string) (*protocol.Receipt, error) {
	j, err := os.ReadFile(stem + ".json") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return nil, err
	}
	var req protocol.SendRequest
	if err := protocol.Unmarshal(j, &req); err != nil {
		return nil, err
	}
	// The post carries this box's pass: that is how the server knows the
	// sender.
	var r protocol.Receipt
	if _, err := b.owner(ctx, http.MethodPost, "/v1/"+to.String(), req, nil, &r); err != nil {
		return nil, err
	}
	// A receipt names the ciphertext it is for, and this box knows which
	// that is: one that names another, or whose times are not times, is no
	// receipt, and the entry stays (PROTOCOL.md §4.5). So what send and
	// flush print of it is what this box computed.
	h := sha256.Sum256(req.Ciphertext)
	_, rerr := protocol.ParseTime(r.ReceivedAt)
	_, eerr := protocol.ParseTime(r.ExpiresAt)
	if r.ID != hex.EncodeToString(h[:]) || rerr != nil || eerr != nil {
		return nil, refuse("the server's receipt does not name the ciphertext this box posted, or its times are not times")
	}
	return &r, nil
}

// seal signs the entry's envelope for the peer only, with the working key
// in use, and encrypts the envelope, the signature and the padding to the
// peer's VERIFIED current prekey, then writes the request to post.
//
// The envelope is read as its recipient will read it, so one the recipient
// would refuse is never sealed. The padding is made here, for the prekey's
// type: an encryption after stale_prekey may be to a prekey of the other
// type. It is outside what is signed, so the signature is over the envelope
// as the outbox keeps it.
func (b *Box) seal(ctx context.Context, to protocol.Address, stem string) error {
	line, err := os.ReadFile(stem + ".P") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return err
	}
	env, err := protocol.OpenEnvelopeRecord(line, b.id.Address(), to)
	if err != nil || !bytes.Equal(env.Identity, b.id.Document()) || !bytes.HasSuffix(line, []byte("\n")) {
		return refuse("the outbox entry is not an envelope this box made for that address")
	}
	worker, cert, err := b.currentWorker()
	if err != nil {
		return err
	}
	// Mail may wait 33 days to be read, and its certificate must still be
	// valid then.
	if !cert.SignsMail(b.now()) {
		return refuse("this box's certificate ends within %d days, too soon to sign mail that may wait that long: irongall prekey renew makes a new one, as irongall recv does daily", protocol.TTL/(24*time.Hour))
	}
	pk, under, err := b.resolve(ctx, to)
	if err != nil {
		return err
	}
	r, err := pk.Recipient()
	if err != nil {
		return err
	}
	sig, err := protocol.Sign(worker, line, protocol.MessageNamespace(to))
	if err != nil {
		return err
	}
	plaintext, size := protocol.Plaintext(line, sig, pk.Type())
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, r)
	if err != nil {
		return err
	}
	if _, err := w.Write(plaintext); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if ct.Len() != size {
		return refuse("the encrypted message is %d bytes, where its padding was made for %d: it is not sent at a size that tells its length", ct.Len(), size)
	}
	// The prekey is named by both serials: its own, and that of the
	// certificate resolve verified it under. Never read back from what the
	// box recorded: that is the highest seen, which another statement may
	// have raised.
	serial, underSerial := pk.Serial, under.Serial()
	j, err := json.Marshal(protocol.SendRequest{PrekeySerial: &serial, CertificateSerial: &underSerial, Ciphertext: ct.Bytes()})
	if err != nil {
		return err
	}
	if err := writeFile(stem+".age", ct.Bytes()); err != nil {
		return err
	}
	if err := writeFile(stem+".sig", sig); err != nil {
		return err
	}
	return writeFile(stem+".json", j)
}
