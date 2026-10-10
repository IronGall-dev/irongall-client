package client

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/drewstreib/crossbot-client/protocol"
)

// Rekey publishes a NEW prekey at the next serial, of type kt, or of the
// current prekey's type if kt is empty. It needs no token, only the identity,
// so it also recovers a box that lost its prekeys or its token. The new token
// it returns, encrypted to the new prekey, replaces the old one, which dies.
// Run it at least monthly: a prekey is valid for at most 32 days.
func (b *Box) Rekey(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, error) {
	var ir protocol.IdentityResponse
	if _, err := b.call(ctx, http.MethodGet, b.boxPath("/identity"), nil, nil, &ir); err != nil {
		return nil, err
	}
	cur, err := protocol.VerifyPrekey(b.id, ir.Prekey, ir.PrekeySignature)
	if err != nil {
		return nil, refuse("this box's current prekey, as served: %v", err)
	}
	if kt == "" {
		kt = cur.Type()
	}
	next := cur.Serial + 1
	stem := b.path("prekeys", strconv.FormatUint(next, 10))
	// A statement left by an attempt that never published is remade, so its
	// not_after is counted from now. Its key, if any, is reused: it was
	// never published.
	for _, ext := range []string{".txt", ".txt.sig"} {
		if err := removeIfExists(stem + ext); err != nil {
			return nil, err
		}
	}
	p, err := b.makePrekey(next, kt)
	if err != nil {
		return nil, err
	}
	req := protocol.PrekeyRequest{Prekey: p.Statement()}
	if req.PrekeySignature, err = os.ReadFile(stem + ".txt.sig"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, err
	}
	var tr protocol.TokenResponse
	if _, err := b.call(ctx, http.MethodPut, b.boxPath("/prekey"), req, nil, &tr); err != nil {
		return nil, err
	}
	if err := b.storeToken(tr.Token); err != nil {
		return nil, err
	}
	return p, b.Prune()
}

// Prune deletes every retired prekey whose deletion time has come: its
// not_after plus the 8-day TTL. All mail encrypted to it arrived by its
// not_after and has expired by then; after this, that mail is unrecoverable
// from the box's keys. The newest prekey is never deleted.
func (b *Box) Prune() error {
	keys, err := filepath.Glob(b.path("prekeys", "*.agekey"))
	if err != nil {
		return err
	}
	var top uint64
	for _, k := range keys {
		if n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(k), ".agekey"), 10, 64); err == nil && n > top {
			top = n
		}
	}
	for _, k := range keys {
		n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(k), ".agekey"), 10, 64)
		if err != nil || n >= top {
			continue
		}
		st, err := os.ReadFile(b.path("prekeys", fmt.Sprintf("%d.txt", n)))
		if err != nil {
			continue
		}
		p, err := protocol.ParsePrekey(st)
		if err != nil {
			continue
		}
		if !b.now().Before(p.NotAfter.Add(protocol.TTL)) {
			if err := os.Remove(k); err != nil {
				return err
			}
		}
	}
	return nil
}
