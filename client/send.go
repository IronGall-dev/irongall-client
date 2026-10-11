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

// SendWith sends one logical message: its envelope is built once, kept in the
// outbox, encrypted to the peer's verified prekey and signed for that peer
// only, then posted. On 409 stale_prekey it re-encrypts the SAME envelope to
// the newer prekey, once. If the post fails, the message stays in the outbox:
// retry with [Box.Flush], never by sending again, or the peer gets it twice.
// Once the server has it, the envelope and the server's receipt are kept in
// sent/.
func (b *Box) SendWith(ctx context.Context, to protocol.Address, body string, f Fields) (*protocol.Receipt, error) {
	if err := f.check(); err != nil {
		return nil, err
	}
	env, err := protocol.NewEnvelope(b.id.Address(), to, body, b.now())
	if err != nil {
		return nil, err
	}
	env.Subject, env.InReplyTo, env.Supersedes = f.Subject, f.InReplyTo, f.Supersedes
	p, err := env.Marshal()
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
	p, err := os.ReadFile(stem + ".P") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return err
	}
	receipt, err := json.Marshal(r)
	if err != nil {
		return err
	}
	// The envelope is this box's own compact JSON object, so the receipt
	// goes in as its last member.
	p = bytes.TrimSpace(p)
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
	p, err := os.ReadFile(stem + ".P") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return false
	}
	var e struct {
		SentAt string `json:"sent_at"`
	}
	if json.Unmarshal(p, &e) != nil {
		return false
	}
	t, err := protocol.ParseTime(e.SentAt)
	return err == nil && t.Before(b.now().Add(-protocol.TTL))
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
	var r protocol.Receipt
	if _, err := b.call(ctx, http.MethodPost, "/v1/"+to.String(), req, nil, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// seal encrypts the entry's envelope to the peer's VERIFIED current prekey,
// signs the ciphertext for that peer only, and writes the request to post.
func (b *Box) seal(ctx context.Context, to protocol.Address, stem string) error {
	p, err := os.ReadFile(stem + ".P") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return err
	}
	pk, err := b.Resolve(ctx, to)
	if err != nil {
		return err
	}
	r, err := pk.Recipient()
	if err != nil {
		return err
	}
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, r)
	if err != nil {
		return err
	}
	if _, err := w.Write(p); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	sig, err := protocol.Sign(b.signer, ct.Bytes(), protocol.MessageNamespace(to))
	if err != nil {
		return err
	}
	serial := pk.Serial
	j, err := json.Marshal(protocol.SendRequest{
		From:         b.id.Address().String(),
		PrekeySerial: &serial,
		Ciphertext:   ct.Bytes(),
		Signature:    sig,
	})
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
