package client

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// RefusedRevoked is why mail from a revoked address is refused: this box
// holds a revocation of the sender that verifies. RefusedCertificate is why
// mail under a revoked certificate is: its sender's address goes on, and the
// identity has revoked the certificate the mail was signed under.
const (
	RefusedRevoked     = "revoked"
	RefusedCertificate = "certificate_revoked"
)

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
	// A list of revoked certificates rides in the same record. It is taken
	// or not on its own: the address may well go on.
	if err := b.keepRevokedCerts(a, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
		return false, err
	}
	id, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	if err != nil {
		return false, nil
	}
	return true, b.keepRevocation(id, rec.Revocation)
}

// revokedCertsFile is where the list of a's revoked certificates is kept:
// for a peer, beside its pinned identity; for this box, at its root. It is
// one file, the record that carries the list (PROTOCOL.md §6.3): the
// identity document, the list and its signature, as one line of JSON. A list
// and its signature in two files could be left one new and one old, a pair
// that verifies never again.
func (b *Box) revokedCertsFile(a protocol.Address) string {
	if a == b.id.Address() {
		return b.path("revoked-certs.json")
	}
	return b.path("peers", a.String(), "revoked-certs.json")
}

// revokedCerts returns the list of a's revoked certificates this box holds,
// or nil. Like a kept revocation it is checked again each time it is read: a
// file that no longer verifies is an error, never a quiet "nothing revoked".
func (b *Box) revokedCerts(a protocol.Address) (*protocol.RevokedCertificates, error) {
	raw, err := os.ReadFile(b.revokedCertsFile(a)) //nolint:gosec // a path inside the box's own directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec protocol.Revocations
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("the list of revoked certificates kept for %s is not a record: %w", a, err)
	}
	// Checked under the identity this box holds for the address, whatever
	// document the file carries.
	doc := b.id.Document()
	if a != b.id.Address() {
		if doc, err = os.ReadFile(b.path("peers", a.String(), "identity.doc")); err != nil {
			return nil, err
		}
	}
	list, err := protocol.VerifyRevokedCertificates(a, doc, rec.RevokedCertificates, rec.RevokedCertificatesSignature)
	if err != nil {
		return nil, fmt.Errorf("the list of revoked certificates kept for %s no longer verifies: %w", a, err)
	}
	return list, nil
}

// keepRevokedCerts keeps a list of a's revoked certificates if it verifies
// and its version is above the one this box holds. One that does not verify,
// or is no newer, changes nothing: only the identity's own signature revokes
// a certificate, and an older list never replaces a newer one.
func (b *Box) keepRevokedCerts(a protocol.Address, doc, statement, sig []byte) error {
	if len(statement) == 0 {
		return nil
	}
	list, err := protocol.VerifyRevokedCertificates(a, doc, statement, sig)
	if err != nil {
		return nil //nolint:nilerr // what does not verify counts as nothing shown
	}
	held, err := b.revokedCerts(a)
	if err != nil || (held != nil && held.Version >= list.Version) {
		return err
	}
	if a != b.id.Address() {
		id, err := protocol.ParseIdentity(doc)
		if err != nil {
			return nil //nolint:nilerr // VerifyRevokedCertificates parsed it
		}
		if err := b.pin(id); err != nil {
			return err
		}
	}
	// One file, moved into place whole: the list is never kept without the
	// signature that goes with it.
	line, err := json.Marshal(protocol.Revocations{Identity: doc, RevokedCertificates: statement, RevokedCertificatesSignature: sig})
	if err != nil {
		return err
	}
	return writeFile(b.revokedCertsFile(a), append(line, '\n'))
}

// RevokeEarlier revokes every certificate this box's identity made before
// the one in use: it signs a list naming them, publishes it, and keeps it.
// It is for a box whose working key may have been taken: [Box.Rekey] first,
// which makes a new working key under a new certificate, then this, which
// ends what the old key could still sign. The address goes on.
//
// It returns the list, or nil when the box has made no earlier certificate.
// Mail this box sent under those certificates, and that its reader has not
// read yet, is refused too: nobody can tell it from a thief's.
func (b *Box) RevokeEarlier(ctx context.Context) (*protocol.RevokedCertificates, error) {
	current, err := b.publishedSerial()
	if err != nil || current <= 1 {
		return nil, err
	}
	ranges, version := []protocol.SerialRange{{First: 1, Last: current - 1}}, uint64(1)
	held, err := b.revokedCerts(b.id.Address())
	if err != nil {
		return nil, err
	}
	if held != nil {
		ranges, version = append(ranges, held.Ranges...), held.Version+1
	}
	list, err := protocol.NewRevokedCertificates(b.id.Address(), version, ranges)
	if err != nil {
		return nil, err
	}
	sig, err := protocol.SignRevokedCertificates(b.signer, list)
	if err != nil {
		return nil, err
	}
	rec := &protocol.Revocations{Identity: b.id.Document(), RevokedCertificates: list.Statement(), RevokedCertificatesSignature: sig}
	if _, err := b.call(ctx, http.MethodPut, b.boxPath("/revocations"), rec, nil, nil); err != nil {
		return nil, err
	}
	return list, b.keepRevokedCerts(b.id.Address(), rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature)
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
