package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// RefusedRevoked is why mail from a revoked address is refused: this box
// holds a revocation of the sender that verifies.
const RefusedRevoked = "revoked"

// RevokedError is an address this box holds a revocation of. The revocation
// verified here, so it is not the server's word: nothing is sent to that
// address or taken from it again, and nothing a server says later undoes it.
type RevokedError struct {
	Address protocol.Address
	// Own is true when the address is this box's.
	Own bool
}

func (e *RevokedError) Error() string {
	if e.Own {
		return "REVOKED: this box's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new box (irongall init) and give its address to those who write to this one"
	}
	return "REVOKED: " + e.Address.String() + " is revoked, for good, and the revocation verifies: ask its owner for their new address"
}

// Revocation returns this box's revocation: its identity document and the
// identity's signature over the fixed statement. It publishes nothing. The
// record is what [Revoke] sends, and it can be made long before it is needed
// and kept somewhere other than the box.
func (b *Box) Revocation() (*protocol.Revocations, error) {
	sig, err := protocol.SignRevocation(b.signer, b.id.Address())
	if err != nil {
		return nil, err
	}
	return &protocol.Revocations{Identity: b.id.Document(), Revocation: sig}, nil
}

// Revoke publishes a revocation to the server opt names: the address the
// record is for is revoked there, for good. It needs no box and no key, only
// the record, so a box that is lost can still be revoked with a record made
// in advance. The record is checked here first.
func Revoke(ctx context.Context, opt Options, rec *protocol.Revocations) (protocol.Address, error) {
	a := protocol.Address(sha256.Sum256(rec.Identity))
	if _, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation); err != nil {
		return a, refuse("the record is not a revocation: %v", err)
	}
	_, err := newBox("", opt).call(ctx, http.MethodPut, "/v1/"+a.String()+"/revocations", rec, nil, nil)
	return a, err
}

// KeepRevocation takes a revocation someone handed over, of this box's own
// address or of anyone's, checks it, and keeps it. It is the answer to a
// server that hides one: the record proves itself wherever it came from.
func (b *Box) KeepRevocation(rec *protocol.Revocations) (protocol.Address, error) {
	a := protocol.Address(sha256.Sum256(rec.Identity))
	id, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	if errors.Is(err, protocol.ErrIdentityType) {
		return a, refuse("the record's identity is of a key type this client does not verify, so its revocation cannot be checked here")
	}
	if err != nil {
		return a, refuse("the record is not a revocation: %v", err)
	}
	return a, b.keepRevocation(id, rec.Revocation)
}

// revocationFile is where a verified revocation of a is kept: for a peer,
// beside its pinned identity; for this box, at its root.
func (b *Box) revocationFile(a protocol.Address) string {
	if a == b.id.Address() {
		return b.path("revoked.sig")
	}
	return b.path("peers", a.String(), "revoke.sig")
}

// keepRevocation records a revocation that has verified under id. It is never
// removed: a revoked address stays revoked.
func (b *Box) keepRevocation(id *protocol.Identity, sig []byte) error {
	a := id.Address()
	if a != b.id.Address() {
		if err := b.pin(id); err != nil {
			return err
		}
	}
	return writeFile(b.revocationFile(a), sig)
}

// revoked reports whether this box holds a revocation of a. The kept
// signature is checked again each time, against the identity kept with it: a
// file that no longer verifies is an error, never a quiet "not revoked".
func (b *Box) revoked(a protocol.Address) (bool, error) {
	sig, err := os.ReadFile(b.revocationFile(a))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	doc := b.id.Document()
	if a != b.id.Address() {
		if doc, err = os.ReadFile(b.path("peers", a.String(), "identity.doc")); err != nil {
			return false, err
		}
	}
	if _, err := protocol.VerifyRevocation(a, doc, sig); err != nil {
		return false, fmt.Errorf("the revocation kept for %s no longer verifies: %w", a, err)
	}
	return true, nil
}

// lookupRevocation asks the server what it holds about a, and keeps a
// revocation that verifies. It reports whether this box now holds one.
//
// The three answers are kept apart. A revocation that verifies is final. A
// server that says it holds none (not_revoked, or no such box) has answered,
// and the caller goes on. Anything else is no answer: an error, which the
// caller stops on. What a server sends that does not verify counts as holding
// none: only a statement the identity signed can revoke an address.
func (b *Box) lookupRevocation(ctx context.Context, a protocol.Address) (bool, error) {
	if held, err := b.revoked(a); held || err != nil {
		return held, err
	}
	var rec protocol.Revocations
	_, err := b.call(ctx, http.MethodGet, "/v1/"+a.String()+"/revocations", nil, nil, &rec)
	switch Code(err) {
	case protocol.CodeNotRevoked, protocol.CodeNoSuchMailbox:
		return false, nil
	}
	if err != nil {
		return false, err
	}
	id, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	if err != nil {
		return false, nil
	}
	return true, b.keepRevocation(id, rec.Revocation)
}

// proved turns a server's "revoked" into something this box has checked. who
// is the box a call named. If err is the server saying who is revoked, or
// that this box is, the server is asked for the revocation: one that verifies
// makes it a [RevokedError], which is final. With none, the error says so and
// stays what it was, a call that failed: a server's word revokes nothing.
func (b *Box) proved(ctx context.Context, who protocol.Address, err error) error {
	switch Code(err) {
	case protocol.CodeRevoked:
	case protocol.CodeSenderRevoked:
		who = b.id.Address()
	default:
		return err
	}
	held, lerr := b.lookupRevocation(ctx, who)
	if lerr != nil {
		return fmt.Errorf("%w; asking for the revocation failed: %w", err, lerr)
	}
	if !held {
		return fmt.Errorf("%w; it showed no revocation of %s that verifies, so this box does not take that address as revoked", err, who)
	}
	return &RevokedError{Address: who, Own: who == b.id.Address()}
}
