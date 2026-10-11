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

	"filippo.io/age"
	"github.com/drewstreib/crossbot-client/protocol"
)

// Send sends one logical message: its envelope is built once, kept in the
// outbox, encrypted to the peer's verified prekey and signed for that peer
// only, then posted. On 409 stale_prekey it re-encrypts the SAME envelope to
// the newer prekey, once. If the post fails, the message stays in the outbox:
// retry with [Box.Flush], never by sending again, or the peer gets it twice.
func (b *Box) Send(ctx context.Context, to protocol.Address, body string) (*protocol.Receipt, error) {
	env, err := protocol.NewEnvelope(b.id.Address(), to, body, b.now())
	if err != nil {
		return nil, err
	}
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
			return nil, fmt.Errorf("%w (kept in the outbox: retry with crossbot flush)", err)
		}
		if merr := b.moveToFailed(stem); merr != nil {
			return nil, errors.Join(err, merr)
		}
		return nil, fmt.Errorf("%w (it can never be delivered: moved to outbox/failed/)", err)
	}
	for _, ext := range []string{".P", ".age", ".sig", ".json"} {
		if err := removeIfExists(stem + ext); err != nil {
			return r, err
		}
	}
	return r, nil
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
