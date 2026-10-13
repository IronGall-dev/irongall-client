package client

import (
	"bytes"
	"context"
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

// Send sends one logical message with none of the optional fields: see
// [Box.SendWith].
func (b *Box) Send(ctx context.Context, to protocol.Address, body string) (*protocol.Receipt, error) {
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
// The signature is inside the encryption, so the server is handed none: it
// knows the sender from the pass the post carries. Every message is padded,
// after the signature, so that the server sees its size only to within a
// block (protocol.PaddedSize).
func (b *Box) SendWith(ctx context.Context, to protocol.Address, body string, f Fields) (*protocol.Receipt, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	env, err := protocol.NewEnvelope(b.id.Address(), to, body, b.now())
	if err != nil {
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
	stem := b.path("outbox", to.String()+"."+env.MsgID)
	if err := writeFile(stem+".P", p); err != nil {
		return nil, err
	}
	return b.post(ctx, to, stem)
}

// Flush re-posts every message still in the outbox, unchanged: a retry of a
// message the server already holds gets its original receipt. It tries every
// entry; one that fails never stops the others, and the error names each
// that failed.
func (b *Box) Flush(ctx context.Context) ([]*protocol.Receipt, error) {
	names, err := filepath.Glob(b.path("outbox", "*.P"))
	if err != nil {
		return nil, err
	}
	var receipts []*protocol.Receipt
	var errs []error
	for _, n := range names {
		stem := strings.TrimSuffix(n, ".P")
		to, _, _ := strings.Cut(filepath.Base(stem), ".")
		peer, err := protocol.ParseAddress(to)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: not an outbox entry", filepath.Base(n)))
			continue
		}
		r, err := b.post(ctx, peer, stem)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(stem), err))
			continue
		}
		receipts = append(receipts, r)
	}
	return receipts, errors.Join(errs...)
}

// undeliverable are the answers that never change for this message: retrying
// it can only fail again.
var undeliverable = []protocol.Code{
	protocol.CodeRevoked, protocol.CodeSenderRevoked, protocol.CodeBadAddress, protocol.CodeTooLarge, protocol.CodeConflict,
}

// post posts the outbox entry stem, sealing it first if it is not sealed. On
// failure the entry stays in the outbox for the next flush, unless it can
// never be delivered: the server refused it for good, or its envelope is
// older than any recipient accepts. Then it moves to outbox/failed/. An entry
// already that old is never posted: the server would take it and give a
// receipt, and the recipient would refuse it.
func (b *Box) post(ctx context.Context, to protocol.Address, stem string) (*protocol.Receipt, error) {
	if b.expired(stem) {
		err := refuse("its envelope is older than %d days, and every recipient refuses that", protocol.TTL/(24*time.Hour))
		if merr := b.moveToFailed(stem); merr != nil {
			return nil, errors.Join(err, merr)
		}
		return nil, fmt.Errorf("%w (it can never be delivered: moved to outbox/failed/)", err)
	}
	// An envelope dated ahead of this machine's clock was written while the
	// clock read ahead of where it reads now. It is not posted, sealed or
	// not, until the clock passes that time: a reader takes a sent_at up to
	// MaxSkew ahead of its own clock, which is the room for two clocks a
	// server takes, and has none to spare for one that was wrong.
	if t, ok := b.sentAt(stem); ok && t.After(b.now()) {
		return nil, refuse("its envelope is dated %s, ahead of this machine's clock: it was written while the clock read ahead of where it reads now, and a recipient would refuse it. It is kept in the outbox, and irongall flush sends it once the clock passes that time", t.Format(protocol.TimeLayout))
	}
	r, err := b.trySend(ctx, to, stem)
	if err != nil {
		if !slices.Contains(undeliverable, Code(err)) {
			return nil, fmt.Errorf("%w (kept in the outbox: retry with irongall flush)", err)
		}
		if merr := b.moveToFailed(stem); merr != nil {
			return nil, errors.Join(err, merr)
		}
		return nil, fmt.Errorf("%w (it can never be delivered: moved to outbox/failed/)", err)
	}
	// Recorded before the outbox entry goes: a crash in between posts it
	// again, gets the original receipt, and records it again.
	if err := b.recordSent(stem, r); err != nil {
		return r, fmt.Errorf("sent, but not recorded in sent/ (still in the outbox: irongall flush records it): %w", err)
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

func (b *Box) trySend(ctx context.Context, to protocol.Address, stem string) (*protocol.Receipt, error) {
	if !exists(stem + ".json") {
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
	if json.Unmarshal(p, &e) != nil {
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
	if err := json.Unmarshal(j, &req); err != nil {
		return nil, err
	}
	// The post carries this box's pass: that is how the server knows the
	// sender.
	var r protocol.Receipt
	if _, err := b.owner(ctx, http.MethodPost, "/v1/"+to.String(), req, nil, &r); err != nil {
		return nil, err
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
		return refuse("this box's certificate ends within %d days, too soon to sign mail that may wait that long: irongall rekey makes a new one, as irongall recv does daily", protocol.TTL/(24*time.Hour))
	}
	pk, err := b.Resolve(ctx, to)
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
	serial := pk.Serial
	j, err := json.Marshal(protocol.SendRequest{PrekeySerial: &serial, Ciphertext: ct.Bytes()})
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
