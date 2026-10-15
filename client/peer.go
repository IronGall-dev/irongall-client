package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Resolve fetches a peer's identity and current prekey and verifies them. It
// returns the prekey only when every check passes; until then there is
// nothing to encrypt to.
//
//   - The identity is the pinned one, or at first contact the served one,
//     which must hash to the address. A pin always wins over what the server
//     sends later.
//   - The prekey statement must be signed by a working key that identity
//     certified, under a certificate valid now, in the peer's prekey
//     namespace, and name the peer.
//   - It may not be ordered before one already seen (rollback): under an
//     earlier certificate, or under the same one with a lower serial. A later
//     certificate outranks any serial under an earlier one, so a box that
//     moved to a new certificate is followed whatever serial it publishes.
//   - Its certificate may not be one the peer's identity has revoked, by the
//     revocation this box holds, and it may not have expired.
//   - A peer this box holds a revocation of is refused before anything is
//     asked: a [RevokedError], whatever the server now serves for it.
//
// The identity is pinned, and the serials recorded, only after every check
// passed: nothing is kept of a peer whose statement did not verify.
func (b *Box) Resolve(ctx context.Context, peer protocol.Address) (*protocol.Prekey, error) {
	if held, err := b.revoked(peer); err != nil {
		return nil, err
	} else if held {
		return nil, &RevokedError{Address: peer}
	}
	var ir protocol.IdentityResponse
	if _, err := b.lookup(ctx, peer, "/identity", &ir); err != nil {
		return nil, err
	}
	id, err := b.identityOf(peer, ir.Identity)
	if err != nil {
		return nil, err
	}
	p, cert, err := protocol.VerifyPrekey(id, ir.Prekey, ir.PrekeySignature, b.now())
	if errors.Is(err, protocol.ErrCertificateNotBegun) {
		return nil, refuse("%s's prekey: %v, by this machine's clock: a certificate starts an hour before it is made, so check the clock", peer, err)
	}
	if err != nil {
		return nil, refuse("%s's prekey: %v", peer, err)
	}
	seen, err := b.peerSerial(peer, "serial")
	if err != nil {
		return nil, err
	}
	seenCert, err := b.peerSerial(peer, "cert-serial")
	if err != nil {
		return nil, err
	}
	// Ordered by certificate first, then by the prekey's own serial.
	if cert.Serial() < seenCert {
		return nil, refuse("rollback: %s's prekey is signed under certificate %d, below %d, already seen", peer, cert.Serial(), seenCert)
	}
	if cert.Serial() == seenCert && p.Serial < seen {
		return nil, refuse("rollback: %s's prekey serial %d is below %d, already seen", peer, p.Serial, seen)
	}
	certs, err := b.revokedCerts(peer)
	if err != nil {
		return nil, err
	}
	if certs != nil && certs.Revokes(cert.Serial()) {
		return nil, refuse("%s's prekey is signed under a certificate its identity has revoked: its owner must publish a new one", peer)
	}
	if p.Expired(b.now()) {
		return nil, refuse("%s's prekey has expired: its owner must publish a new one", peer)
	}
	// Whether the peer can verify this box is the one thing here that
	// nothing signs: the server says what the peer declared. A server that
	// misstates it can only stop a message, as it can without it.
	if !protocol.AcceptsSender(ir.SenderKeyTypes, b.id.Type()) {
		return nil, refuse("%s's client does not verify identities of this box's key type, %s, so it would refuse this box's mail: nothing is sent", peer, b.id.Type())
	}
	if err := b.pin(id); err != nil {
		return nil, err
	}
	d := b.path("peers", peer.String())
	if err := writeFile(d+"/serial", []byte(strconv.FormatUint(p.Serial, 10)+"\n")); err != nil {
		return nil, err
	}
	if err := writeFile(d+"/cert-serial", []byte(strconv.FormatUint(cert.Serial(), 10)+"\n")); err != nil {
		return nil, err
	}
	if err := writeFile(d+"/prekey.txt", ir.Prekey); err != nil {
		return nil, err
	}
	return p, writeFile(d+"/prekey.sig", ir.PrekeySignature)
}

// identityOf returns the peer's identity: the pinned one, or, for a peer not
// met before, the one served, held in memory. A served document must hash to
// the address before anything else is read from it. Nothing is written:
// [Box.pin] does that, once something the identity signed has verified.
func (b *Box) identityOf(peer protocol.Address, served []byte) (*protocol.Identity, error) {
	doc, err := os.ReadFile(b.path("peers", peer.String(), "identity.doc"))
	switch {
	case err == nil:
		// A pin always wins.
	case errors.Is(err, fs.ErrNotExist):
		doc = served
	default:
		return nil, err
	}
	if len(doc) == 0 {
		return nil, refuse("the server has no identity for %s", peer)
	}
	if protocol.Address(sha256.Sum256(doc)) != peer {
		return nil, refuse("the identity for %s does not hash to it", peer)
	}
	id, err := protocol.ParseIdentity(doc)
	switch {
	case errors.Is(err, protocol.ErrIdentityType):
		return nil, refuse("%s's identity is of a key type this client does not verify, so nothing it signs can be checked here and nothing is sent", peer)
	case err != nil:
		return nil, refuse("%s's identity: %v", peer, err)
	}
	return id, nil
}

// pin keeps a peer's identity document, unless it is kept already. It is
// called only for an identity that has signed something this box verified: a
// prekey statement it will encrypt to, mail it delivers, a revocation of its
// address or of its certificates. So peers/<a>/ exists only
// for a peer that has signed something.
func (b *Box) pin(id *protocol.Identity) error {
	d := b.path("peers", id.Address().String())
	if exists(d + "/identity.doc") {
		return nil
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	return writeFile(d+"/identity.doc", id.Document())
}

// peerSerial returns the highest serial seen for peer and kept in file:
// "serial" for its prekey's, "cert-serial" for its certificate's. It is 0
// when none is kept.
func (b *Box) peerSerial(peer protocol.Address, file string) (uint64, error) {
	s, err := os.ReadFile(b.path("peers", peer.String(), file))
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
