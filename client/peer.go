package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/dromas-dev/dromas-client/protocol"
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
//     namespace, and name the peer. One whose key is an age recipient of a
//     type this client cannot encrypt to is refused with its own code,
//     RefusedPrekeyType.
//   - It may not be ordered before one already seen (rollback): under an
//     earlier certificate, or under the same one with a lower serial. A later
//     certificate outranks any serial under an earlier one, so a mailbox that
//     moved to a new certificate is followed whatever serial it publishes.
//   - Its certificate may not be one the peer's identity has revoked, by the
//     revocation this mailbox holds, and it may not have expired.
//   - A peer this mailbox holds a revocation of is refused before anything is
//     asked: a [RevokedError], whatever the server now serves for it.
//
// The identity is pinned, and the serials recorded, only after every check
// passed: nothing is kept of a peer whose statement did not verify. It holds
// the mailbox's lock ([Mailbox.hold]).
func (b *Mailbox) Resolve(ctx context.Context, peer protocol.Address) (*protocol.Prekey, error) {
	return locked(ctx, b, func() (*protocol.Prekey, error) {
		p, _, err := b.resolve(ctx, peer, nil)
		return p, err
	})
}

// resolve is Resolve with the lock held. It also returns the certificate the
// prekey statement verified under. It reads the peer's mailbox once (readMailbox),
// and keeps what verifies of the revocations it carries before it checks the
// statement against them. With l, a send's lookups, the read is marked as
// answered in the command.
//
// A read that serves no mailbox is a [lookupError]: there is nothing to seal to,
// and what the server answered is never an answer about a message.
func (b *Mailbox) resolve(ctx context.Context, peer protocol.Address, l *lookups) (*protocol.Prekey, *protocol.Certificate, error) {
	if held, err := b.revoked(peer); err != nil {
		return nil, nil, err
	} else if held {
		return nil, nil, &RevokedError{Address: peer, Own: peer == b.id.Address()}
	}
	ir, gone, err := b.readMailbox(ctx, peer, l)
	if gone {
		return nil, nil, &RevokedError{Address: peer, Own: peer == b.id.Address()}
	}
	if err != nil {
		if code(err) == protocol.CodeRevoked {
			err = fmt.Errorf("%w; it showed no revocation of %s that verifies, so this mailbox does not take that address as revoked", err, peer)
		}
		return nil, nil, &lookupError{err}
	}
	id, err := b.identityOf(peer, ir.Identity)
	if err != nil {
		return nil, nil, err
	}
	p, cert, err := protocol.VerifyPrekey(id, ir.Prekey, ir.PrekeySignature, b.now())
	if errors.Is(err, protocol.ErrCertificateNotBegun) {
		return nil, nil, refuse("%s's prekey: %v, by this machine's clock: a certificate starts an hour before it is made, so check the clock", peer, err)
	}
	// A well-formed recipient of a type this client lacks is a statement good
	// in every other way, and is held to every other rule here before it is
	// refused with its own code, never as one that does not verify (#167).
	typeErr := errors.Is(err, protocol.ErrPrekeyType)
	if err != nil && !typeErr {
		return nil, nil, refuse("%s's prekey: %v", peer, err)
	}
	var seen, seenCert uint64
	if err := b.view(func(s store) error {
		kept, err := b.peerOf(s, peer)
		if kept != nil {
			seen, seenCert = kept.Serial, kept.CertificateSerial
		}
		return err
	}); err != nil {
		return nil, nil, err
	}
	// Ordered by certificate first, then by the prekey's own serial.
	if before(cert.Serial(), p.Serial, seenCert, seen) {
		if cert.Serial() < seenCert {
			return nil, nil, refuse("rollback: %s's prekey is signed under certificate %d, below %d, already seen", peer, cert.Serial(), seenCert)
		}
		return nil, nil, refuse("rollback: %s's prekey serial %d is below %d, already seen", peer, p.Serial, seen)
	}
	certs, err := b.revokedCerts(peer)
	if err != nil {
		return nil, nil, err
	}
	if certs != nil && certs.Revokes(cert.Serial()) {
		return nil, nil, refuse("%s's prekey is signed under a certificate its identity has revoked: its owner must publish a new one", peer)
	}
	if p.Expired(b.now()) {
		return nil, nil, refuse("%s's prekey has expired: its owner must publish a new one", peer)
	}
	if typeErr {
		return nil, nil, &RefusedError{Code: RefusedPrekeyType, Reason: fmt.Sprintf("%s's prekey is an age recipient of a type this client cannot encrypt to, so nothing is sent", peer)}
	}
	// Whether the peer can verify this mailbox is the one thing here that
	// nothing signs: the server says what the peer declared. A server that
	// misstates it can only stop a message, as it can without it.
	if !protocol.AcceptsSender(ir.SenderKeyTypes, b.id.Type()) {
		return nil, nil, refuse("%s's client does not verify identities of this mailbox's key type, %s, so it would refuse this mailbox's messages: nothing is sent", peer, b.id.Type())
	}
	// The pin, the pair of serials and the statement they came from, in one
	// value, written together (#68).
	return p, cert, b.update(func(s store) error {
		kept, err := b.pinned(s, id)
		if err != nil {
			return err
		}
		kept.Serial, kept.CertificateSerial, kept.Prekey, kept.PrekeySignature = p.Serial, cert.Serial(), ir.Prekey, ir.PrekeySignature
		return b.keepPeer(s, peer, kept)
	})
}

// identityOf returns the peer's identity: the pinned one, or, for a peer not
// met before, the one served, held in memory. A served document must hash to
// the address before anything else is read from it. Nothing is kept:
// [Mailbox.pin] does that, once something the identity signed has verified.
func (b *Mailbox) identityOf(peer protocol.Address, served []byte) (*protocol.Identity, error) {
	doc := served
	if err := b.view(func(s store) error {
		kept, err := b.peerOf(s, peer)
		if kept != nil {
			doc = kept.Identity // a pin always wins
		}
		return err
	}); err != nil {
		return nil, err
	}
	if len(doc) == 0 {
		return nil, refuse("the server has no identity for %s", peer)
	}
	if protocol.AddressOf(doc) != peer {
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

// peerRecord is what this mailbox keeps of a peer, one value of the peers
// bucket by its address: the identity document it pinned, the highest prekey
// serial and certificate serial it has seen, with the statement they came
// from, and the revocation of the address and of its certificates, once
// either has verified. One value, so what goes together is never left half
// written (#68).
type peerRecord struct {
	Identity                     protocol.Bytes `json:"identity"`
	Serial                       uint64         `json:"serial,omitempty"`
	CertificateSerial            uint64         `json:"certificate_serial,omitempty"`
	Prekey                       protocol.Bytes `json:"prekey,omitempty"`
	PrekeySignature              protocol.Bytes `json:"prekey_signature,omitempty"`
	Revocation                   protocol.Bytes `json:"revocation_signature,omitempty"`
	RevokedCertificates          protocol.Bytes `json:"revoked_certificates,omitempty"`
	RevokedCertificatesSignature protocol.Bytes `json:"revoked_certificates_signature,omitempty"`
}

// peerOf is what this mailbox keeps of peer a, or nil for a peer it has pinned
// nothing of.
func (b *Mailbox) peerOf(s store, a protocol.Address) (*peerRecord, error) {
	raw := s.get(bucketPeers, a.String())
	if raw == nil {
		return nil, nil
	}
	var p peerRecord
	if err := protocol.Unmarshal(raw, &p); err != nil || protocol.AddressOf(p.Identity) != a {
		return nil, fmt.Errorf("what the mailbox's state file keeps of %s is not a peer's record", a)
	}
	return &p, nil
}

// keepPeer keeps p as what this mailbox holds of peer a.
func (b *Mailbox) keepPeer(s store, a protocol.Address, p *peerRecord) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return s.put(bucketPeers, a.String(), raw)
}

// pin keeps a peer's identity document, unless it is kept already. It is
// called only for an identity that has signed something this mailbox verified: a
// prekey statement it will encrypt to, a message it delivers, a revocation of its
// address or of its certificates. So the mailbox keeps a record only of a peer
// that has signed something.
func (b *Mailbox) pin(id *protocol.Identity) error {
	return b.update(func(s store) error {
		p, err := b.pinned(s, id)
		if err != nil {
			return err
		}
		return b.keepPeer(s, id.Address(), p)
	})
}

// pinned is what this mailbox keeps of the peer whose identity id is, with id
// pinned if nothing was: a record to add to and keep.
func (b *Mailbox) pinned(s store, id *protocol.Identity) (*peerRecord, error) {
	p, err := b.peerOf(s, id.Address())
	if err != nil || p != nil {
		return p, err
	}
	return &peerRecord{Identity: id.Document()}, nil
}
