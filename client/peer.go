package client

import (
	"context"
	"errors"
	"io/fs"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/drewstreib/crossbot-client/protocol"
)

// Resolve fetches a peer's identity and current prekey and verifies them. It
// returns the prekey only when every check passes; until then there is
// nothing to encrypt to.
//
//   - The identity is pinned at first contact, after checking it hashes to the
//     address, and a pin always wins over what the server sends later.
//   - The prekey statement must be signed by the pinned identity, in the peer's
//     prekey namespace, and name the peer.
//   - Its serial may not be lower than one already seen (rollback), and it may
//     not have expired.
func (b *Box) Resolve(ctx context.Context, peer protocol.Address) (*protocol.Prekey, error) {
	var ir protocol.IdentityResponse
	if _, err := b.call(ctx, http.MethodGet, "/v1/"+peer.String()+"/identity", nil, nil, &ir); err != nil {
		return nil, err
	}
	id, err := b.pin(peer, ir.Identity)
	if err != nil {
		return nil, err
	}
	p, err := protocol.VerifyPrekey(id, ir.Prekey, ir.PrekeySignature)
	if err != nil {
		return nil, refuse("%s's prekey: %v", peer, err)
	}
	seen, err := b.peerSerial(peer)
	if err != nil {
		return nil, err
	}
	if p.Serial < seen {
		return nil, refuse("rollback: %s's prekey serial %d is below %d, already seen", peer, p.Serial, seen)
	}
	if p.Expired(b.now()) {
		return nil, refuse("%s's prekey has expired: its owner must publish a new one", peer)
	}
	// Recorded only after every check passed.
	d := b.path("peers", peer.String())
	if err := writeFile(d+"/serial", []byte(strconv.FormatUint(p.Serial, 10)+"\n")); err != nil {
		return nil, err
	}
	if err := writeFile(d+"/prekey.txt", ir.Prekey); err != nil {
		return nil, err
	}
	return p, writeFile(d+"/prekey.sig", ir.PrekeySignature)
}

// pin returns the peer's pinned identity. At first contact the served
// document must hash to the address and parse; it is pinned only then.
func (b *Box) pin(peer protocol.Address, served []byte) (*protocol.Identity, error) {
	d := b.path("peers", peer.String())
	doc, err := os.ReadFile(d + "/identity.doc") //nolint:gosec // a path inside the box's own directory
	switch {
	case err == nil:
		// A pin always wins.
	case errors.Is(err, fs.ErrNotExist):
		doc = served // pinned below, only if it hashes to the address
	default:
		return nil, err
	}
	id, err := protocol.ParseIdentity(doc)
	if err != nil {
		return nil, refuse("%s's identity: %v", peer, err)
	}
	if id.Address() != peer {
		return nil, refuse("the identity for %s does not hash to it", peer)
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return nil, err
	}
	if !exists(d + "/identity.doc") {
		if err := writeFile(d+"/identity.doc", doc); err != nil {
			return nil, err
		}
	}
	return id, nil
}

// peerSerial returns the highest prekey serial seen for peer, or 0.
func (b *Box) peerSerial(peer protocol.Address) (uint64, error) {
	s, err := os.ReadFile(b.path("peers", peer.String(), "serial"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(s)), 10, 64)
	if err != nil {
		return 0, refuse("the serial recorded for %s is unreadable", peer)
	}
	return n, nil
}
