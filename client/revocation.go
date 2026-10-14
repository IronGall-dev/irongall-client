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
	// Certificates is the highest revocation of the address's certificates
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
	certs, err := b.revokedCerts(a)
	if err != nil {
		return nil, err
	}
	return &Held{Revoked: gone, Certificates: certs}, nil
}

// KeepRevocation takes a record someone handed over, of this box's own
// address or of anyone's: a revocation of the address, a revocation of its
// certificates, or both. Each part is checked, and what verifies is kept. It
// is the answer to a server that hides one: the record proves itself
// wherever it came from. A record with a part that does not verify is
// refused whole, and nothing of it is kept: whoever handed it over is told,
// where a server's answer that does not verify counts as nothing shown.
//
// It returns the address and what this box then holds about it. A revocation
// of certificates through no higher a serial than the one held changes
// nothing.
func (b *Box) KeepRevocation(rec *protocol.Revocations) (protocol.Address, *Held, error) {
	a := protocol.Address(sha256.Sum256(rec.Identity))
	if len(rec.Revocation) == 0 && len(rec.RevokedCertificates) == 0 {
		return a, nil, refuse("the record holds no revocation of the address and none of its certificates")
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
			return a, nil, refuse("the record's identity is of a key type this client does not verify, so its revocation of certificates cannot be checked here")
		}
		if err != nil {
			return a, nil, refuse("the record's revocation of certificates: %v", err)
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

// revokedCertsFile is where the revocation of a's certificates is kept: for
// a peer, beside its pinned identity; for this box, at its root. It is one
// file, the record that carries it (PROTOCOL.md §6.3): the identity
// document, the statement and its signature, as one line of JSON. A
// statement and its signature in two files could be left one new and one
// old, a pair that verifies never again.
func (b *Box) revokedCertsFile(a protocol.Address) string {
	if a == b.id.Address() {
		return b.path("revoked-certs.json")
	}
	return b.path("peers", a.String(), "revoked-certs.json")
}

// revokedCerts returns the revocation of a's certificates this box holds, or
// nil. Like a kept revocation of an address it is checked again each time it
// is read: a file that no longer verifies is an error, never a quiet
// "nothing revoked".
func (b *Box) revokedCerts(a protocol.Address) (*protocol.RevokedCertificates, error) {
	raw, err := os.ReadFile(b.revokedCertsFile(a)) //nolint:gosec // a path inside the box's own directory
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var rec protocol.Revocations
	if err := protocol.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("the revocation of certificates kept for %s is not a record: %w", a, err)
	}
	// Checked under the identity this box holds for the address, whatever
	// document the file carries.
	doc := b.id.Document()
	if a != b.id.Address() {
		if doc, err = os.ReadFile(b.path("peers", a.String(), "identity.doc")); err != nil {
			return nil, err
		}
	}
	certs, err := protocol.VerifyRevokedCertificates(a, doc, rec.RevokedCertificates, rec.RevokedCertificatesSignature)
	if err != nil {
		return nil, fmt.Errorf("the revocation of certificates kept for %s no longer verifies: %w", a, err)
	}
	return certs, nil
}

// keepRevokedCerts keeps a revocation of a's certificates if it verifies and
// runs through a higher serial than the one this box holds. One that does not
// verify, or runs no higher, changes nothing: only the identity's own
// signature revokes a certificate, and a certificate once revoked stays so.
func (b *Box) keepRevokedCerts(a protocol.Address, doc, statement, sig []byte) error {
	if len(statement) == 0 {
		return nil
	}
	certs, err := protocol.VerifyRevokedCertificates(a, doc, statement, sig)
	if err != nil {
		return nil //nolint:nilerr // what does not verify counts as nothing shown
	}
	held, err := b.revokedCerts(a)
	if err != nil || (held != nil && held.Through >= certs.Through) {
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
	// One file, moved into place whole: the statement is never kept without
	// the signature that goes with it.
	line, err := json.Marshal(protocol.Revocations{Identity: doc, RevokedCertificates: statement, RevokedCertificatesSignature: sig})
	if err != nil {
		return err
	}
	return writeFile(b.revokedCertsFile(a), append(line, '\n'))
}

// RevokeEarlier revokes every certificate this box's identity made before
// the one in use: it signs a revocation of them, publishes it, and keeps it.
// [Box.RenewAndRevoke] is the whole remedy for a box whose working key may
// have been taken, and is what "irongall rekey --revoke-earlier" runs; this
// is its second half alone, for a box that has renewed already.
//
// It revokes through the serial below the one in use. A box numbers a
// certificate by its clock ([protocol.SerialAt]), so that covers every
// certificate made before this one on any machine, whether this box knows of
// it or not: one a lost machine made and never published is among them.
//
// It returns the revocation, or nil when the certificate in use has serial
// 1, which nothing is below.
// Mail this box sent under those certificates, and that its reader has not
// read yet, is refused too: nobody can tell it from a thief's.
func (b *Box) RevokeEarlier(ctx context.Context) (*protocol.RevokedCertificates, error) {
	current, err := b.publishedSerial()
	if err != nil {
		return nil, err
	}
	return b.revokeBelow(ctx, current)
}

// A Remedy is what [Box.RenewAndRevoke] did.
type Remedy struct {
	// Below is the serial of the certificate this call made. Every
	// certificate below it is revoked.
	Below uint64
	// Prekey is the new prekey, if the server took it.
	Prekey *protocol.Prekey
	// NotRenewed is why the server did not take it, or nil.
	NotRenewed error
	// Revoked is the revocation of those certificates, if a server took it.
	Revoked *protocol.RevokedCertificates
}

// RenewAndRevoke is the remedy for a box whose working key may have been
// taken, with the address kept: a new prekey under a new working key and a
// new certificate, and a revocation, signed by the identity, of every
// certificate before that one.
//
// It asks first what is held of the box's own revocation of its
// certificates, and numbers the new certificate above it. It sends nothing
// an earlier renewal left: whoever copied the box while one waited holds its
// working key too.
//
// The revocation is published when the server took the new prekey, and also
// when it refused it for the box's renewals of the day (rate_limited). A
// holder of the working key can spend those, so a remedy that waited on the
// renewal would wait on the taker. The certificate the box is using is then
// among those revoked: the server takes nothing more under it, mail to the
// box is refused until its new prekey is taken, and [Box.Receive] and
// [Box.Rekey] send that one again. For any other failure of the renewal
// nothing is revoked, and the Remedy says why: a server reaches its count of
// renewals only after it has taken this box's new certificate and its pass
// as timely, so that refusal is the one that shows the box's clock within
// what the server allows, and a revocation numbered by a clock that reads
// ahead would cover certificates not yet made.
//
// The error is why the revocation is not at every server, or why there is
// none.
func (b *Box) RenewAndRevoke(ctx context.Context, kt protocol.KeyType) (*Remedy, error) {
	l, err := b.lockWait(ctx, rekeyLockWait)
	if err != nil {
		return nil, err
	}
	r, err := b.renewAndRevoke(ctx, kt)
	if e := l.release(); err == nil {
		err = e
	}
	return r, err
}

func (b *Box) renewAndRevoke(ctx context.Context, kt protocol.KeyType) (*Remedy, error) {
	// What is held of this box's own revocation, first: the new certificate
	// is numbered above it (rekey), or it would be revoked as it was made.
	if err := b.askOwn(ctx); err != nil {
		return nil, err
	}
	p, made, rerr := b.rekey(ctx, kt, true)
	if made == 0 {
		return nil, rerr // it made no new certificate: nothing is named
	}
	r := &Remedy{Below: made, Prekey: p, NotRenewed: rerr}
	if rerr != nil && Code(rerr) != protocol.CodeRateLimited {
		return r, rerr
	}
	certs, err := b.revokeBelow(ctx, made)
	r.Revoked = certs
	return r, err
}

// ownRevokes reports whether this box holds a revocation of its own
// certificates that covers certificate n. One it cannot read covers nothing
// here: whoever reads it to apply it says so.
func (b *Box) ownRevokes(n uint64) bool {
	certs, err := b.revokedCerts(b.id.Address())
	return err == nil && certs != nil && certs.Revokes(n)
}

// askOwn asks what is held of this box's own revocation of its certificates,
// of its server and of each revocation server it lists, and keeps what
// verifies: the one this box signs next then runs through at least the
// highest serial it has been shown. A box restored from its identity holds
// none of its own, and neither does one whose revocation was taken with the
// answer lost. No answer from the box's own server stops nothing here: the
// revocation still goes to whoever takes it.
func (b *Box) askOwn(ctx context.Context) error {
	own := b.id.Address()
	var rec protocol.Revocations
	if _, err := b.call(ctx, http.MethodGet, "/v1/"+own.String()+"/revocations", nil, nil, &rec); err == nil {
		if _, err := b.take(own, &rec); err != nil {
			return err
		}
	} else if ctx.Err() != nil {
		return ctx.Err()
	}
	_, err := b.askRevocationServers(ctx, own, newLookups())
	return err
}

// revokeBelow signs, publishes and keeps the revocation of every
// certificate of this box's identity below serial. It returns nil when
// nothing is below.
//
// It asks first what is held ([Box.askOwn]). A revocation through a higher
// serial than that stands already, and the box signs and publishes that one
// again: every holder would refuse a lower one, and one that lacks it takes
// it. A server that holds a higher one it did not show answers conflict: the
// box asks once more and signs again.
func (b *Box) revokeBelow(ctx context.Context, serial uint64) (*protocol.RevokedCertificates, error) {
	if serial <= 1 {
		return nil, nil
	}
	own := b.id.Address()
	for try := 0; ; try++ {
		if err := b.askOwn(ctx); err != nil {
			return nil, err
		}
		through := serial - 1
		held, err := b.revokedCerts(own)
		if err != nil {
			return nil, err
		}
		if held != nil {
			through = max(through, held.Through)
		}
		certs, err := protocol.NewRevokedCertificates(own, through)
		if err != nil {
			return nil, err
		}
		sig, err := protocol.SignRevokedCertificates(b.signer, certs)
		if err != nil {
			return nil, err
		}
		rec := &protocol.Revocations{Identity: b.id.Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
		// To this box's server and to each revocation server it lists. Once
		// any of them has taken it, it is out, and this box keeps it: the
		// next one it signs runs at least as high.
		perr := b.publishRecord(ctx, own, rec)
		var part *NotPublishedError
		if perr != nil && (!errors.As(perr, &part) || len(part.Took) == 0) {
			if try == 0 && conflicted(perr) {
				continue
			}
			return nil, perr
		}
		if err := b.keepRevokedCerts(own, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
			return nil, err
		}
		return certs, perr
	}
}

// conflicted reports whether a server refused a record as no newer than the
// one it holds: a revocation of certificates through a lower serial.
func conflicted(err error) bool {
	if Code(err) == protocol.CodeConflict {
		return true
	}
	var part *NotPublishedError
	if errors.As(err, &part) {
		for _, f := range part.Failed {
			if Code(f.Err) == protocol.CodeConflict {
				return true
			}
		}
	}
	return false
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
