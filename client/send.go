package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

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
// message the server already holds gets its original receipt.
func (b *Box) Flush(ctx context.Context) ([]*protocol.Receipt, error) {
	names, err := filepath.Glob(b.path("outbox", "*.P"))
	if err != nil {
		return nil, err
	}
	var receipts []*protocol.Receipt
	for _, n := range names {
		stem := strings.TrimSuffix(n, ".P")
		to, _, _ := strings.Cut(filepath.Base(stem), ".")
		peer, err := protocol.ParseAddress(to)
		if err != nil {
			return receipts, fmt.Errorf("%s: not an outbox entry", n)
		}
		r, err := b.post(ctx, peer, stem)
		if err != nil {
			return receipts, err
		}
		receipts = append(receipts, r)
	}
	return receipts, nil
}

// post posts the outbox entry stem, sealing it first if it is not sealed.
func (b *Box) post(ctx context.Context, to protocol.Address, stem string) (*protocol.Receipt, error) {
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
	if err != nil {
		return nil, fmt.Errorf("%w (kept in the outbox: retry with crossbot flush)", err)
	}
	for _, ext := range []string{".P", ".age", ".sig", ".json"} {
		if err := removeIfExists(stem + ext); err != nil {
			return r, err
		}
	}
	return r, nil
}

func (b *Box) postSealed(ctx context.Context, to protocol.Address, stem string) (*protocol.Receipt, error) {
	j, err := os.ReadFile(stem + ".json")
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
	p, err := os.ReadFile(stem + ".P")
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
