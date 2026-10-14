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

// Revoke publishes a revocation to the server opt names, and to each
// revocation server it lists: the address the record is for is revoked
// there, for good. It needs no box and no key, only the record, so a box
// that is lost can still be revoked with a record made in advance. The
// record is checked here first. It is [Publish], of a record that must
// carry a revocation of the address.
func Revoke(ctx context.Context, opt Options, rec *protocol.Revocations) (protocol.Address, error) {
	return newBox("", opt).Revoke(ctx, rec)
}

// Revoke is [Revoke] as this box: to its own server and to the revocation
// servers it lists.
func (b *Box) Revoke(ctx context.Context, rec *protocol.Revocations) (protocol.Address, error) {
	a := protocol.Address(sha256.Sum256(rec.Identity))
	if _, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation); err != nil {
		return a, refuse("the record is not a revocation: %v", err)
	}
	return b.Publish(ctx, rec)
}

// Held is what a box holds about an address: what that address's identity
// signed about it, verified here, and kept. It is what a send to the address
// and a read of its mail are checked against, with no call to anyone.
type Held struct {
	// Revoked is true when the box holds a revocation of the address: it is
	// ended, for good.
	Revoked bool
	// Certificates is the newest list of the address's revoked certificates
	// the box holds, or nil. The address goes on.
	Certificates *protocol.RevokedCertificates
}

// held returns what this box holds about a, each part checked again as it is
// read.
func (b *Box) held(a protocol.Address) (*Held, error) {
	gone, err := b.revoked(a)
	if err != nil {
		return nil, err
	}
	list, err := b.revokedCerts(a)
	if err != nil {
		return nil, err
	}
	return &Held{Revoked: gone, Certificates: list}, nil
}

// KeepRevocation takes a record someone handed over, of this box's own
// address or of anyone's: a revocation of the address, a list of its revoked
// certificates, or both. Each part is checked, and what verifies is kept. It
// is the answer to a server that hides one: the record proves itself
// wherever it came from. A record with a part that does not verify is
// refused whole, and nothing of it is kept: whoever handed it over is told,
// where a server's answer that does not verify counts as nothing shown.
//
// It returns the address and what this box then holds about it. A list no
// newer than the one held changes nothing.
func (b *Box) KeepRevocation(rec *protocol.Revocations) (protocol.Address, *Held, error) {
	a := protocol.Address(sha256.Sum256(rec.Identity))
	if len(rec.Revocation) == 0 && len(rec.RevokedCertificates) == 0 {
		return a, nil, refuse("the record holds no revocation and no list of revoked certificates")
	}
	var id *protocol.Identity
	if len(rec.Revocation) > 0 {
		var err error
		id, err = protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
		if errors.Is(err, protocol.ErrIdentityType) {
			return a, nil, refuse("the record's identity is of a key type this client does not verify, so its revocation cannot be checked here")
		}
		if err != nil {
			return a, nil, refuse("the record is not a revocation: %v", err)
		}
	}
	if len(rec.RevokedCertificates) > 0 {
		_, err := protocol.VerifyRevokedCertificates(a, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature)
		if errors.Is(err, protocol.ErrIdentityType) {
			return a, nil, refuse("the record's identity is of a key type this client does not verify, so its list of revoked certificates cannot be checked here")
		}
		if err != nil {
			return a, nil, refuse("the record's list: %v", err)
		}
		if err := b.keepRevokedCerts(a, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
			return a, nil, err
		}
	}
	if id != nil {
		if err := b.keepRevocation(id, rec.Revocation); err != nil {
			return a, nil, err
		}
	}
	h, err := b.held(a)
	return a, h, err
}

// Ask asks this box's server what it holds about a, and each revocation
// server the box lists ([Box.RevocationServers]), keeps what verifies, and
// returns what the box then holds: a box may ask at any time, and whatever
// it has verified about an address it keeps. A send asks by itself
// ([Box.SendWith]), and so does a drain, of each sender ([Box.Receive]).
//
// A server that answers that it holds nothing has answered, and that is its
// word: it can keep a record back, and nothing here tells. What the box
// holds already stands whatever a server answers. No answer from the box's
// own server is an error; none from a revocation server changes nothing.
func (b *Box) Ask(ctx context.Context, a protocol.Address) (*Held, error) {
	if _, err := b.lookupRevocation(ctx, a, newLookups()); err != nil {
		return nil, err
	}
	return b.held(a)
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

// lookupRevocation asks what is held about a, of this box's own server and
// then of each revocation server the box lists, and keeps what verifies. It
// reports whether this box now holds a revocation of a.
//
// The own server's three answers are kept apart. A revocation that verifies
// is final. A server that says it holds none (not_revoked, or no such box)
// has answered, and the caller goes on. Anything else is no answer: an error,
// which the caller stops on. What a server sends that does not verify counts
// as holding none: only a statement the identity signed can revoke an
// address.
//
// A revocation server is asked once the box's own has answered, and can only
// add (askRevocationServers): its record is kept as any is, and neither its
// "none held" nor its silence changes what the caller does.
func (b *Box) lookupRevocation(ctx context.Context, a protocol.Address, l *lookups) (bool, error) {
	if held, err := b.revoked(a); held || err != nil {
		return held, err
	}
	var rec protocol.Revocations
	_, err := b.call(ctx, http.MethodGet, "/v1/"+a.String()+"/revocations", nil, nil, &rec)
	switch Code(err) {
	case protocol.CodeNotRevoked, protocol.CodeNoSuchMailbox:
		err, rec = nil, protocol.Revocations{}
	}
	if err != nil {
		return false, err
	}
	if gone, err := b.take(a, &rec); gone || err != nil {
		return gone, err
	}
	return b.askRevocationServers(ctx, a, l)
}

// ask asks what is held about a recipient before a message is posted to it,
// once for each recipient in a flush, keeps what verifies, and reports
// whether this box holds a revocation of it. l holds the recipients a flush
// has an answer about: for those the box reads what it holds, with no call.
func (b *Box) ask(ctx context.Context, to protocol.Address, l *lookups) (bool, error) {
	if l.answered[to] {
		return b.revoked(to)
	}
	gone, err := b.lookupRevocation(ctx, to, l)
	if err == nil {
		l.answered[to] = true
	}
	return gone, err
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
// The list is every serial below the one in use. A box numbers a certificate
// by its clock ([protocol.SerialAt]), so that range names every certificate
// made before this one on any machine, whether this box knows of it or not:
// one a lost machine made and never published is in it.
//
// It returns the list, or nil when the certificate in use has serial 1, which
// nothing is below.
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
	// To this box's server and to each revocation server it lists. Once any
	// of them has taken the list it is out, at that version, and this box
	// keeps it: the next one it signs is numbered above it.
	perr := b.publishRecord(ctx, b.id.Address(), rec)
	var part *NotPublishedError
	if perr != nil && (!errors.As(perr, &part) || len(part.Took) == 0) {
		return nil, perr
	}
	if err := b.keepRevokedCerts(b.id.Address(), rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
		return nil, err
	}
	return list, perr
}

// proved turns a server's "revoked" into something this box has checked. who
// is the box a call named. If err is the server saying who is revoked, or
// that this box is, the server is asked for the revocation: one that verifies
// makes it a [RevokedError], which is final. With none, the error says so and
// stays what it was, a call that failed: a server's word revokes nothing.
func (b *Box) proved(ctx context.Context, who protocol.Address, err error, l *lookups) error {
	switch Code(err) {
	case protocol.CodeRevoked:
	case protocol.CodeSenderRevoked:
		who = b.id.Address()
	default:
		return err
	}
	held, lerr := b.lookupRevocation(ctx, who, l)
	if lerr != nil {
		return fmt.Errorf("%w; asking for the revocation failed: %w", err, lerr)
	}
	if !held {
		return fmt.Errorf("%w; it showed no revocation of %s that verifies, so this box does not take that address as revoked", err, who)
	}
	return &RevokedError{Address: who, Own: who == b.id.Address()}
}
