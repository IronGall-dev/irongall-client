package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/dromas-dev/dromas-client/client/internal/sign"
	"github.com/dromas-dev/dromas-client/protocol"
)

// RefusedRevoked is why a message from a revoked address is refused: this mailbox
// holds a revocation of the sender that verifies. RefusedCertificate is why
// a message under a revoked certificate is: its sender's address goes on, and the
// identity has revoked the certificate the message was signed under.
const (
	RefusedRevoked     = "revoked"
	RefusedCertificate = "certificate_revoked"
)

// RevokedError is an address this mailbox holds a revocation of. The revocation
// verified here, so it is not the server's word: nothing is sent to that
// address or taken from it again, and nothing a server says later undoes it.
type RevokedError struct {
	Address protocol.Address
	// Own is true when the address is this mailbox's.
	Own bool
}

func (e *RevokedError) Error() string {
	if e.Own {
		return "REVOKED: this mailbox's own address is revoked, for good, and the revocation verifies. It can send and receive nothing more: make a new mailbox (dromas init) and give its address to those who write to this one"
	}
	return "REVOKED: " + e.Address.String() + " is revoked, for good, and the revocation verifies: ask its owner for their new address"
}

// Revocation returns this mailbox's revocation: its identity document and the
// identity's signature over the fixed statement. It publishes nothing. The
// record is what [Revoke] sends, and it can be made long before it is needed
// and kept somewhere other than the mailbox. A mailbox that holds its own
// revocation returns the one it holds, and signs nothing (sign).
func (b *Mailbox) Revocation(ctx context.Context) (*protocol.Revocations, error) {
	return reading(ctx, b, b.revocation)
}

// revocation is Revocation inside a command or a reading.
func (b *Mailbox) revocation() (*protocol.Revocations, error) {
	if gone, err := b.revoked(b.id.Address()); err != nil {
		return nil, err
	} else if gone {
		var sig []byte
		if err := b.view(func(s store) error { sig = s.get(bucketMailbox, "revoked"); return nil }); err != nil {
			return nil, err
		}
		return &protocol.Revocations{Identity: b.id.Document(), Revocation: sig}, nil
	}
	sig, err := b.certifier.Revocation(b.id.Address())
	if err != nil {
		return nil, err
	}
	return &protocol.Revocations{Identity: b.id.Document(), Revocation: sig}, nil
}

// Revoke publishes a revocation to the server opt names: the address the
// record is for is revoked there, for good. It needs no mailbox and no key, only the record, so a mailbox
// that is lost can still be revoked with a record made in advance. The
// record is checked here first. It is [Publish], of a record that must
// carry a revocation of the address.
func Revoke(ctx context.Context, opt Options, rec *protocol.Revocations) (protocol.Address, error) {
	b, err := newMailbox("", opt)
	if err != nil {
		return protocol.Address{}, err
	}
	return b.Revoke(ctx, rec)
}

// Revoke is [Revoke] as this mailbox: to its own server.
func (b *Mailbox) Revoke(ctx context.Context, rec *protocol.Revocations) (protocol.Address, error) {
	a := protocol.AddressOf(rec.Identity)
	if _, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation); err != nil {
		return a, refuse("the record is not a revocation: %v", err)
	}
	return b.Publish(ctx, rec)
}

// Held is what a mailbox holds about an address: what that address's identity
// signed about it, verified here, and kept. It is what a send to the address
// and a read of its messages are checked against, with no call to anyone.
type Held struct {
	// Revoked is true when the mailbox holds a revocation of the address: it is
	// ended, for good.
	Revoked bool
	// Certificates is the highest revocation of the address's certificates
	// the mailbox holds, or nil. The address goes on.
	Certificates *protocol.RevokedCertificates
}

// held returns what this mailbox holds about a, each part checked again as it is
// read.
func (b *Mailbox) held(a protocol.Address) (*Held, error) {
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

// KeepRevocation takes a record someone handed over, of this mailbox's own
// address or of anyone's: a revocation of the address, a revocation of its
// certificates, or both. Each part is checked, and what verifies is kept. It
// is the answer to a server that hides one: the record proves itself
// wherever it came from. A record with a part that does not verify is
// refused whole, and nothing of it is kept: whoever handed it over is told,
// where a server's answer that does not verify counts as nothing shown.
//
// It returns the address and what this mailbox then holds about it. A revocation
// of certificates through no higher a serial than the one held changes
// nothing.
func (b *Mailbox) KeepRevocation(ctx context.Context, rec *protocol.Revocations) (a protocol.Address, h *Held, err error) {
	_, err = lockedFinished(ctx, b, func() (struct{}, error) {
		a, h, err = b.keepRevocationRecord(rec)
		return struct{}{}, err
	})
	if err != nil && a == (protocol.Address{}) {
		a = protocol.AddressOf(rec.Identity)
	}
	return a, h, err
}

func (b *Mailbox) keepRevocationRecord(rec *protocol.Revocations) (protocol.Address, *Held, error) {
	a := protocol.AddressOf(rec.Identity)
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

// Ask asks this mailbox's server what it holds about a, keeps what verifies, and
// returns what the mailbox then holds: a mailbox may ask at any time, and whatever
// it has verified about an address it keeps. A send asks by itself
// ([Mailbox.SendWith]), and so does a drain, of each sender ([Mailbox.Receive]).
//
// A server that answers that it holds nothing has answered, and that is its
// word: it can keep a record back, and nothing here tells. What the mailbox
// holds already stands whatever a server answers. No answer is an error.
func (b *Mailbox) Ask(ctx context.Context, a protocol.Address) (*Held, error) {
	return lockedFinished(ctx, b, func() (*Held, error) {
		if _, err := b.lookupRevocation(ctx, a, newLookups()); err != nil {
			return nil, err
		}
		return b.held(a)
	})
}

// keepRevocation records a revocation that has verified under id. It is never
// removed: a revoked address stays revoked.
func (b *Mailbox) keepRevocation(id *protocol.Identity, sig []byte) error {
	a := id.Address()
	if a != b.id.Address() {
		return b.update(func(s store) error {
			p, err := b.pinned(s, id)
			if err != nil {
				return err
			}
			p.Revocation = sig
			return b.keepPeer(s, a, p)
		})
	}
	// The mailbox's own: the pass it kept is a signature already made, which
	// nothing may use now, and a renewal that failed, or the read of its
	// server's ACL a renewal owed (aclAt), is one nothing tries again. Kept
	// by a command that began with none, it is the event that ends the
	// command: it asks nothing more (call), and says that alone (locked).
	learned := false
	if err := b.update(func(s store) error {
		learned = s.get(bucketMailbox, "revoked") == nil
		if err := s.put(bucketMailbox, "revoked", sig); err != nil {
			return err
		}
		for _, k := range []struct{ bucket, key string }{{bucketMailbox, "renew-failed"}, {bucketIntent, "acl-read"}} {
			if err := s.del(k.bucket, k.key); err != nil {
				return err
			}
		}
		return s.del(bucketMailbox, "pass")
	}); err != nil {
		return err
	}
	if learned {
		b.ended = &RevokedError{Address: a, Own: true}
	}
	return nil
}

// finished is this mailbox's own revocation of its address, as an error. A mailbox
// that holds one that verifies signs nothing more as that address, no pass,
// no message and no certificate, whatever any server answers: a server that
// never saw the revocation would take it all (PROTOCOL.md §12.5). It still
// asks, keeps and publishes the record, which carry no pass. A kept one that
// no longer verifies is a fault, and stops the same.
func (b *Mailbox) finished() error {
	gone, err := b.revoked(b.id.Address())
	if err != nil {
		return err
	}
	if gone {
		return &RevokedError{Address: b.id.Address(), Own: true}
	}
	return nil
}

// ownRevoked is the first of errs that is this mailbox's own revocation, which
// ends a command whatever else it goes on past (keepRevocation), or nil.
func ownRevoked(errs ...error) *RevokedError {
	for _, err := range errs {
		var gone *RevokedError
		if errors.As(err, &gone) && gone.Own {
			return gone
		}
	}
	return nil
}

// revoked reports whether this mailbox holds a revocation of a. The kept
// signature is checked again each time, against the identity kept with it: a
// record that no longer verifies is an error, never a quiet "not revoked".
func (b *Mailbox) revoked(a protocol.Address) (bool, error) {
	doc, sig, _, _, err := b.heldRecord(a)
	if err != nil || sig == nil {
		return false, err
	}
	if _, err := protocol.VerifyRevocation(a, doc, sig); err != nil {
		return false, fmt.Errorf("the revocation this mailbox keeps for %s no longer verifies: %w", a, err)
	}
	return true, nil
}

// heldRecord is what this mailbox keeps that a's identity signed about a: the
// identity document it holds for a (its own, or the one pinned), the
// revocation of the address, and the revocation of its certificates with
// its signature, each nil when the mailbox keeps none.
func (b *Mailbox) heldRecord(a protocol.Address) (doc, revocation, certs, certsSig []byte, err error) {
	err = b.view(func(s store) error {
		if a == b.id.Address() {
			doc, revocation = b.id.Document(), s.get(bucketMailbox, "revoked")
			if raw := s.get(bucketMailbox, "revoked-certs"); raw != nil {
				var rec protocol.Revocations
				if err := protocol.Unmarshal(raw, &rec); err != nil {
					return fmt.Errorf("the revocation of certificates this mailbox keeps for itself is not a record: %w", err)
				}
				certs, certsSig = rec.RevokedCertificates, rec.RevokedCertificatesSignature
			}
			return nil
		}
		p, err := b.peerOf(s, a)
		if err != nil || p == nil {
			return err
		}
		doc, revocation, certs, certsSig = p.Identity, p.Revocation, p.RevokedCertificates, p.RevokedCertificatesSignature
		return nil
	})
	return doc, revocation, certs, certsSig, err
}

// readMailbox reads mailbox a from this mailbox's server (GET /v1/<a>, PROTOCOL.md
// §11.8), keeps what verifies of the revocations it carries, and with l marks
// a as answered in the command. It returns the mailbox served, and whether this
// mailbox now holds a revocation of a.
//
// A served mailbox carries the revocation of its certificates the server holds,
// and a revoked address is answered 410 revoked with its record (proved, in
// call): either is kept once it verifies, and what does not verify counts as
// nothing shown, since only a statement the identity signed can revoke an
// address or a certificate. No such mailbox, and "revoked" with nothing that
// verifies, are answers that serve no mailbox: they come back as the server's
// error, which a caller reads as none held (lookupRevocation) or as nothing
// to seal to (resolve). This mailbox's own revocation, which ends its command, is
// the error, and anything else is no answer.
func (b *Mailbox) readMailbox(ctx context.Context, a protocol.Address, l *lookups) (*protocol.MailboxResponse, bool, error) {
	var br protocol.MailboxResponse
	_, err := b.lookup(ctx, a, &br)
	var gone *RevokedError
	switch {
	case errors.As(err, &gone) && gone.Address == a:
		return nil, true, nil
	case err == nil:
		if rec := br.Record(); rec != nil {
			if gone, err := b.take(a, rec); gone || err != nil {
				return nil, gone, err
			}
		}
	case code(err) != protocol.CodeRevoked && code(err) != protocol.CodeNoSuchMailbox:
		return nil, false, err
	}
	// The mailbox's own server has answered, whatever it served: with l, a is
	// marked answered in the command, whichever read it here (resolve, at
	// each post of a send; lookupRevocation, in a drain or a question).
	if l != nil {
		l.answered[a] = true
	}
	if err != nil {
		return nil, false, err
	}
	return &br, false, nil
}

// recordOf is the revocation record a server's 410 revoked carries, or nil.
func recordOf(err error) *protocol.Revocations {
	var e *APIError
	if errors.As(err, &e) && e.Problem.Code == protocol.CodeRevoked {
		return e.Problem.Record
	}
	return nil
}

// lookupRevocation asks what this mailbox's server holds about a (readMailbox), and
// keeps what verifies. It reports whether this mailbox now holds a revocation of a. A
// server that serves no mailbox, because it holds none or says "revoked" and
// shows nothing that verifies, has answered that it holds no revocation,
// and the caller goes on. No answer is an error, which the caller stops on.
//
// Of this mailbox's own address it reads what its server holds of it (known):
// its revocations too where the server holds no mailbox. Any call there not
// answered is an error.
func (b *Mailbox) lookupRevocation(ctx context.Context, a protocol.Address, l *lookups) (bool, error) {
	if held, err := b.revoked(a); held || err != nil {
		return held, err
	}
	if a == b.id.Address() {
		o, err := b.known(ctx)
		var gone *RevokedError
		switch {
		case errors.As(err, &gone):
		case err != nil:
			return false, err
		case o.err != nil && o.at != atRevoked:
			return false, o.err
		}
		// An answer, a 410 among them, whether or not what it showed
		// verified.
		if l != nil {
			l.answered[a] = true
		}
		return gone != nil, nil
	}
	_, gone, err := b.readMailbox(ctx, a, l)
	switch code(err) {
	case protocol.CodeRevoked:
		err = nil
	case protocol.CodeNoSuchMailbox:
		// Every server keeps an address's revocations, with a mailbox there or
		// none (PROTOCOL.md §11.15): a sender forgotten here may have
		// revoked its address, or made its trip.
		gone, err = b.readRevocations(ctx, a)
	}
	return gone, err
}

// readRevocations reads what this mailbox's server keeps of a's
// revocations, GET …/revocations, where it holds no mailbox for a, and keeps
// what verifies. It reports whether this mailbox now holds a revocation of a.
// not_revoked is the answer of none held; anything else not answered is an
// error.
func (b *Mailbox) readRevocations(ctx context.Context, a protocol.Address) (bool, error) {
	var held protocol.Revocations
	_, err := b.call(ctx, http.MethodGet, "/v1/"+a.String()+"/revocations", nil, nil, &held)
	var gone *RevokedError
	switch {
	case errors.As(err, &gone) && gone.Address == a:
		return true, nil
	case err == nil:
		return b.take(a, &held)
	case code(err) == protocol.CodeNotRevoked, code(err) == protocol.CodeRevoked:
		return false, nil
	}
	return false, err
}

// revokedCerts returns the revocation of a's certificates this mailbox holds, or
// nil. Like a kept revocation of an address it is checked again each time it
// is read, under the identity this mailbox holds for the address: one that no
// longer verifies is an error, never a quiet "nothing revoked".
func (b *Mailbox) revokedCerts(a protocol.Address) (*protocol.RevokedCertificates, error) {
	doc, _, statement, sig, err := b.heldRecord(a)
	if err != nil || statement == nil {
		return nil, err
	}
	certs, err := protocol.VerifyRevokedCertificates(a, doc, statement, sig)
	if err != nil {
		return nil, fmt.Errorf("the revocation of certificates this mailbox keeps for %s no longer verifies: %w", a, err)
	}
	return certs, nil
}

// CertificatesRecord is the record of this mailbox's own revocation of its
// certificates that it keeps, the one it published or was shown, or nil: what
// dromas cert publish-revoked sends again.
func (b *Mailbox) CertificatesRecord(ctx context.Context) (*protocol.Revocations, error) {
	return reading(ctx, b, b.certificatesRecord)
}

// certificatesRecord is CertificatesRecord inside a command or a reading.
func (b *Mailbox) certificatesRecord() (*protocol.Revocations, error) {
	_, _, statement, sig, err := b.heldRecord(b.id.Address())
	if err != nil || statement == nil {
		return nil, err
	}
	return &protocol.Revocations{Identity: b.id.Document(), RevokedCertificates: statement, RevokedCertificatesSignature: sig}, nil
}

// keepRevokedCerts keeps a revocation of a's certificates if it verifies and
// runs through a higher serial than the one this mailbox holds. One that does not
// verify, or runs no higher, changes nothing: only the identity's own
// signature revokes a certificate, and a certificate once revoked stays so.
// The statement is kept in one value with its signature, never without it.
func (b *Mailbox) keepRevokedCerts(a protocol.Address, doc, statement, sig []byte) error {
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
	if a == b.id.Address() {
		line, err := json.Marshal(protocol.Revocations{Identity: doc, RevokedCertificates: statement, RevokedCertificatesSignature: sig})
		if err != nil {
			return err
		}
		// The first is the trip (mode.go). A mailbox that has published
		// nothing, a restore or an init, takes one a server served or its
		// owner handed over as its mode, and records it as its own trip with
		// it; one that has published a statement of its own and recorded no
		// trip did not make it.
		published, err := b.publishedSerial()
		if err != nil {
			return err
		}
		return b.update(func(s store) error {
			if held == nil && published == 0 && s.get(bucketIntent, "trip") == nil {
				if err := s.put(bucketIntent, "trip", fmt.Appendf(nil, "%d", certs.Through)); err != nil {
					return err
				}
			}
			return s.put(bucketMailbox, "revoked-certs", line)
		})
	}
	id, err := protocol.ParseIdentity(doc)
	if err != nil {
		return nil //nolint:nilerr // VerifyRevokedCertificates parsed it
	}
	return b.update(func(s store) error {
		p, err := b.pinned(s, id)
		if err != nil {
			return err
		}
		p.RevokedCertificates, p.RevokedCertificatesSignature = statement, sig
		return b.keepPeer(s, a, p)
	})
}

// RevokeEarlier revokes every certificate this mailbox's identity made before
// the one in use: it signs a revocation of them, publishes it, and keeps it.
// [Mailbox.RenewAndRevoke] is the whole remedy for a mailbox whose working key may
// have been taken, and is what "dromas cert revoke-earlier" runs; this
// is its second half alone, for a mailbox that has renewed already.
//
// It revokes through the serial below the one in use, as the mailbox holds it
// once it has read itself at its server (known), which records a renewal the
// server took whose answer the mailbox never had. A mailbox numbers a certificate by
// its clock ([protocol.SerialAt]), so that covers every certificate made
// before this one on any machine, whether this mailbox knows of it or not: one a
// lost machine made and never published is among them, unless that machine's
// clock read ahead of this one's (PROTOCOL.md §5); a later run covers that
// one.
//
// It returns the revocation, or nil when the certificate in use has serial
// 1, which nothing is below. A revocation with an error is one the server
// took, and a fault of this mailbox after that: the mailbox keeps it at its next
// read of itself (#383).
// A message this mailbox sent under those certificates, and that its reader has not
// read yet, is refused too: nobody can tell it from a thief's.
func (b *Mailbox) RevokeEarlier(ctx context.Context) (*protocol.RevokedCertificates, error) {
	return locked(ctx, b, func() (*protocol.RevokedCertificates, error) {
		// What its server holds of the mailbox's own revocations, kept where it
		// verifies, and of its renewals (noteServed): an answer it cannot use
		// stops nothing.
		if _, err := b.known(ctx); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := b.certificatesOwn(); err != nil {
			return nil, err
		}
		current, err := b.publishedSerial()
		if err != nil {
			return nil, err
		}
		return b.revokeBelow(ctx, current)
	})
}

// A Remedy is what [Mailbox.RenewAndRevoke] did.
type Remedy struct {
	// Below is the serial of the certificate this call made, numbered once
	// the revocation was final. Every certificate below it is revoked where
	// the revocation was taken.
	Below uint64
	// Prekey is the new prekey, if the server took it.
	Prekey *protocol.Prekey
	// NotRenewed is why the server did not take it, or nil.
	NotRenewed error
	// Revoked is the revocation of those certificates, if a server took it,
	// whether or not this mailbox kept it: one it did not keep is the call's
	// error, a fault of this mailbox after the server took it (#383).
	Revoked *protocol.RevokedCertificates
	// NotRevoked is why the mailbox's server did not take the revocation, or
	// nil. One it holds higher, shown and verified, is taken: Revoked is that
	// one.
	NotRevoked error
	// Unread is why the mailbox's own server's read of it could not be used (no
	// answer, a statement that does not verify, or one ordered before what
	// the mailbox published), or nil. The remedy went on: the certificate was
	// numbered from what the mailbox knows.
	Unread error
}

// RenewAndRevoke is the remedy for a mailbox whose working key may have been
// taken, with the address kept: a revocation, signed by the identity, of
// every certificate before a new one, then a new prekey under a new working
// key and that new certificate.
//
// It reads the mailbox once at its server, for what is held of the mailbox's own
// revocation of its certificates. An answer it cannot use stops nothing: the
// revocation still goes to the server (PROTOCOL.md §12.6). It sends nothing an earlier renewal left: whoever
// copied the mailbox while one waited holds its working key too.
//
// The revocation is published first, once, through the serial below the
// number this machine's clock gives, or through the highest one held if that
// is higher. A server that holds a higher one it did not show answers
// conflict: the mailbox reads itself once more, keeps that one once it verifies,
// and goes on above it, or stops there with nothing renewed when it shows
// none that covers what this one would have. Only then is the new
// certificate numbered, one above the revocation, so it is never revoked as
// it is made, and the renewal is sent, once. Once a server has taken the
// revocation it takes nothing under the certificates it revokes, the one the
// mailbox was using among them: whoever holds that working key can no longer
// spend the mailbox's calls, and the renewal that follows spends none of the
// mailbox's counts, the calls a taker spent before the revocation among them
// (PROTOCOL.md §10.2, §11.9; dromas-dev/dromas-server#84). While the
// mailbox's server holds the revocation and not the renewal, the mailbox takes no
// messages there and signs none, and [Mailbox.Receive] and [Mailbox.Rekey] send the
// renewal again.
//
// It returns no Remedy where it stopped before it published anything, a mailbox
// shown its own revocation on the way among them, which is its [RevokedError]
// alone; otherwise the Remedy says what each publish met, and an error beside
// it is a fault of this mailbox after a server took the revocation or the
// renewal, or the mailbox's own revocation, shown at the renewal.
//
// A mailbox in identity mode, by what it keeps once it has read itself, has
// no certificates to revoke, and is refused before anything is signed
// (certificatesOwn).
func (b *Mailbox) RenewAndRevoke(ctx context.Context) (*Remedy, error) {
	return locked(ctx, b, func() (*Remedy, error) { return b.renewAndRevoke(ctx) })
}

// certificatesOwn is the refusal of a revocation of a mailbox's earlier
// certificates in identity mode, where it has none: its identity signs, and
// only revoking the address answers a copy of it (PROTOCOL.md §12.6). A trip
// it did not make is its own error.
func (b *Mailbox) certificatesOwn() error {
	m, err := b.mode()
	if err != nil {
		return err
	}
	if m == sign.IdentityMode {
		return refuse("this mailbox is in identity mode, where its identity signs and it has no certificates to revoke: a copy of its directory holds the identity, so revoke the address (dromas revocation publish, with the address in full)")
	}
	return nil
}

func (b *Mailbox) renewAndRevoke(ctx context.Context) (*Remedy, error) {
	own := b.id.Address()
	st, err := b.readOwn(ctx, true, true)
	if err != nil {
		return nil, err
	}
	if err := b.certificatesOwn(); err != nil {
		return nil, err
	}
	below, _, err := b.nextNumber(st, true)
	if err != nil {
		return nil, err
	}
	r := &Remedy{Below: below, Unread: st.unread}
	// A revocation the server took that this mailbox did not keep is taken: the
	// fault is the call's error, beside whatever the renewal meets, as a
	// renewal's is (#110, #383).
	var notKept error
	if r.Revoked, r.NotRevoked = b.revokeBelow(ctx, below); r.Revoked != nil {
		notKept, r.NotRevoked = r.NotRevoked, nil
	}
	done := func(err error) (*Remedy, error) {
		if notKept != nil {
			err = errors.Join(notKept, err)
		}
		return r, err
	}
	// A mailbox shown its own revocation on the way, a 410 to its publish or at
	// the read after a conflict, has nothing more to remedy, and says that
	// alone: no server took anything from it there (#326).
	if gone := ownRevoked(r.NotRevoked); gone != nil {
		return nil, gone
	}
	// A conflict that showed no revocation covering what this one would have
	// stops here: a server that holds a higher one would refuse a renewal under
	// it, and nothing here tells how high it runs.
	if code(r.NotRevoked) == protocol.CodeConflict {
		r.NotRenewed = refuse("the server holds a revocation of this mailbox's certificates higher than the one it signed, and showed none that verifies: nothing is renewed above it. dromas revocation ask <this mailbox's address> reads it again, and dromas cert revoke-earlier tries again")
		return done(nil)
	}
	// Numbered once the revocation is final: above whatever a server showed
	// on the way, kept or not (#406 item 1).
	held, err := b.revokedCerts(own)
	if err != nil {
		r.NotRenewed = err
		return done(nil)
	}
	if r.Revoked != nil && (held == nil || held.Through < r.Revoked.Through) {
		held = r.Revoked
	}
	if held != nil && held.Through >= r.Below {
		if r.NotRenewed = noneAbove(held.Through); r.NotRenewed != nil {
			return done(nil)
		}
		r.Below = held.Through + 1
	}
	p, req, err := b.makeRenewal(ctx, st, r.Below, nil)
	if err != nil {
		r.NotRenewed = err
		return done(nil)
	}
	at, err := b.sendRenewal(ctx, req, r.Below)
	took, err := b.tookRenewal(r.Below, at, err)
	if !took {
		r.NotRenewed = err
		return done(nil)
	}
	// Taken: a fault of this mailbox after that is the call's error, and the
	// renewal stands (#110).
	r.Prekey = p
	if err != nil {
		return done(err)
	}
	// By the reading the server took the renewal at (PROTOCOL.md §12.4).
	return done(b.prune(at))
}

// ownRevokes reports whether this mailbox holds a revocation of its own
// certificates that covers a signer of rank n: a certificate at or below it,
// or the identity, rank 0, once it holds one at all. One it cannot read covers nothing
// here: whoever reads it to apply it says so.
func (b *Mailbox) ownRevokes(n uint64) bool {
	certs, err := b.revokedCerts(b.id.Address())
	return err == nil && certs != nil && certs.Revokes(n)
}

// revokeBelow signs, publishes and keeps the revocation of every
// certificate of this mailbox's identity below serial, or through the highest
// serial it holds revoked if that is higher: every holder would refuse a
// lower one, and one that lacks it takes it. It returns nil when nothing is
// below. It signs from what the mailbox holds, which its caller has read.
//
// It publishes once. A server that holds a higher one it did not show answers
// conflict, and the mailbox reads itself once more (known), which keeps that one
// once it verifies: it is the revocation, with no error, when it covers every
// certificate below serial, as the mailbox's would have; otherwise the conflict
// is the error (PROTOCOL.md §12.6). The revocation with an error is one the
// server took or holds, and a fault of this mailbox at its keep after that.
func (b *Mailbox) revokeBelow(ctx context.Context, serial uint64) (*protocol.RevokedCertificates, error) {
	if serial <= 1 {
		return nil, nil
	}
	own := b.id.Address()
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
	sig, err := b.certifier.RevokedCertificates(certs)
	if err != nil {
		return nil, err
	}
	rec := &protocol.Revocations{Identity: b.id.Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
	// Once the server has taken it, it is out, and this mailbox keeps it: the
	// next one it signs runs at least as high.
	perr := b.publishRecord(ctx, own, rec)
	if perr == nil {
		step("revocation published")
		if err := b.keepRevokedCerts(own, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
			return certs, err
		}
		step("revocation kept")
		return certs, nil
	}
	if code(perr) != protocol.CodeConflict {
		return nil, perr
	}
	o, err := b.known(ctx)
	if err != nil {
		// One the read showed, verified, that covers what this one would
		// have is the revocation whether or not this mailbox kept it: the fault
		// comes beside it, as at a keep after the publish (#406 item 1).
		if o.certs != nil && o.certs.Through >= serial-1 && ownRevoked(err) == nil {
			return o.certs, err
		}
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if held, err = b.revokedCerts(own); err != nil {
		return nil, err
	}
	if held != nil && held.Through >= serial-1 {
		return held, nil
	}
	return nil, fmt.Errorf("%w; it showed no revocation of this mailbox's certificates that verifies and covers every one below %d", perr, serial)
}

// provedCodes are the answers about a revocation that proved checks and
// never believes: each is final only once this mailbox holds a revocation that
// verifies, so none is ever one of undeliverable's, whose answers end a
// message for good (TestNoAnswerProvedIsUndeliverable).
var provedCodes = []protocol.Code{protocol.CodeRevoked, protocol.CodeSenderRevoked, protocol.CodeCertificateRevoked}

// proved turns what a server answered about a revocation into what this mailbox
// has checked, by what the answer names (PROTOCOL.md §12.5). Every
// answer of every call passes it (call; a request made outside the mailbox's
// lock, provedLocked), and nothing else proves one:
//
//   - 410 revoked names the mailbox the call's path names. The record it carries
//     is taken as a read's is (take); without one that verifies, that mailbox is
//     read for one (lookupRevocation), unless the call was itself a read of
//     it or of its revocations, whose answer is that read (#353).
//   - 403 sender_revoked names this mailbox, which reads itself.
//   - 401 certificate_revoked names the signer this mailbox signs with: it
//     reads itself (known), which keeps a revocation of its certificates once
//     it verifies. One that covers the signer in use is a refusal in this
//     client's words, and in identity mode a trip it did not make, its
//     [ForeignTripError] (PROTOCOL.md §12.5). The renewal that mends it stays
//     the drain's and the send's to make (mendable, seal), since it signs.
//
// A revocation that verifies is a [RevokedError], which is final; of this
// mailbox's own address it is kept, the event that ends its command
// (keepRevocation). Without one the error stays the call's, saying so: a
// server's word revokes nothing. A read is proved by what it carries alone,
// so a proof's own reads are not proved again. With no mailbox ([Publish]),
// nothing is kept.
func (b *Mailbox) proved(ctx context.Context, method, path string, err error) error {
	c := code(err)
	if !slices.Contains(provedCodes, c) {
		return err
	}
	who, read, ok := named(method, path)
	if !ok {
		return err
	}
	if b.id == nil {
		if c != protocol.CodeRevoked {
			return err
		}
		if revokes(who, recordOf(err)) {
			return &RevokedError{Address: who}
		}
		if !read {
			var gone *RevokedError
			if _, rerr := b.call(ctx, http.MethodGet, "/v1/"+who.String(), nil, nil, nil); errors.As(rerr, &gone) {
				return rerr
			}
		}
		return err
	}
	own := b.id.Address()
	if rec := recordOf(err); rec != nil {
		gone, terr := b.take(who, rec)
		if terr != nil {
			return fmt.Errorf("%w; keeping the revocation it carried failed: %v", err, terr)
		}
		if gone {
			return &RevokedError{Address: who, Own: who == own}
		}
	}
	if read {
		return err
	}
	switch c {
	case protocol.CodeSenderRevoked:
		who = own
	case protocol.CodeCertificateRevoked:
		o, kerr := b.known(ctx)
		var gone *RevokedError
		if errors.As(kerr, &gone) {
			return kerr // the read showed the mailbox its own revocation, kept (#335)
		}
		if kerr == nil {
			kerr = o.err
		}
		if kerr != nil {
			return fmt.Errorf("%w; reading this mailbox's revocations failed: %v", err, kerr)
		}
		if _, merr := b.mode(); merr != nil {
			return merr
		}
		if !b.usesRevoked() {
			return fmt.Errorf("%w; it showed no revocation of this mailbox's certificates that verifies and covers the signer it uses", err)
		}
		return refuse("this mailbox's identity has revoked the signer it signs with, as its server shows, so it is taken nowhere that holds the revocation: dromas recv or dromas prekey renew publishes a statement under a new certificate")
	}
	held, lerr := b.lookupRevocation(ctx, who, nil)
	if lerr != nil {
		// The call's error alone is wrapped: its code is what a caller reads,
		// whichever comes first.
		return fmt.Errorf("%w; asking for the revocation failed: %v", err, lerr)
	}
	if !held {
		return fmt.Errorf("%w; it showed no revocation of %s that verifies, so this mailbox does not take that address as revoked", err, who)
	}
	return &RevokedError{Address: who, Own: who == own}
}

// provedLocked is proved for the answer to a request made outside the mailbox's
// lock (Hold's): proving reads and keeps the mailbox's state, so it takes the
// lock, as a command does (locked), and only for an answer it has to prove.
func (b *Mailbox) provedLocked(ctx context.Context, method, path string, err error) error {
	if !slices.Contains(provedCodes, code(err)) {
		return err
	}
	return b.lockedDo(ctx, func() error { return b.proved(ctx, method, path, err) })
}

// named is the address a call's path names, /v1/<address>, and whether the
// call is a read of that mailbox or of its revocations, which carries no pass.
func named(method, path string) (a protocol.Address, read, ok bool) {
	rest, found := strings.CutPrefix(path, "/v1/")
	if !found {
		return a, false, false
	}
	rest, _, _ = strings.Cut(rest, "?")
	addr, sub, _ := strings.Cut(rest, "/")
	a, err := protocol.ParseAddress(addr)
	if err != nil {
		return a, false, false
	}
	return a, method == http.MethodGet && (sub == "" || sub == "revocations"), true
}

// lookups is what one command has asked as it went: one send, one flush,
// one drain, or one question.
type lookups struct {
	// answered are the addresses this command has its server's answer
	// about, each marked as resolve or lookupRevocation reads it. Only
	// judge reads the marks, and a drain asks nothing more about them; a
	// send's resolve reads the mailbox at each post whatever is marked.
	answered map[protocol.Address]bool
	// reread are the senders judge has read once more, before refusing a
	// certificate's signature from one with no revocation of its
	// certificates held: once each in a drain.
	reread map[protocol.Address]bool
}

func newLookups() *lookups {
	return &lookups{answered: map[protocol.Address]bool{}, reread: map[protocol.Address]bool{}}
}

// take keeps what verifies of a record a server showed for a: a revocation of
// its certificates, of the address, or both. It reports
// whether the mailbox now holds a revocation of a. What does not verify counts
// as nothing shown: only the identity's own signature revokes.
func (b *Mailbox) take(a protocol.Address, rec *protocol.Revocations) (bool, error) {
	// A revocation of certificates is taken or not on its own: the address may
	// well go on.
	if err := b.keepRevokedCerts(a, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
		return false, err
	}
	id, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	if err != nil {
		return false, nil //nolint:nilerr // what does not verify counts as nothing shown
	}
	return true, b.keepRevocation(id, rec.Revocation)
}

// Publish publishes a record to the server opt names: a revocation of an
// address, a revocation of its certificates, or both. It needs no mailbox and no
// key, only the record, so a mailbox that is lost can still be revoked with a
// record made in advance ([Mailbox.Revocation]). Each part is checked here
// first, and a record with a part that does not verify goes nowhere.
func Publish(ctx context.Context, opt Options, rec *protocol.Revocations) (protocol.Address, error) {
	b, err := newMailbox("", opt)
	if err != nil {
		return protocol.Address{}, err
	}
	return b.Publish(ctx, rec)
}

// Publish is [Publish] as this mailbox: to its own server, under its lock. It
// keeps nothing of the record (see [Mailbox.KeepRevocation]), but what the server
// shows when it answers that it holds as much already, once that verifies, as
// of every answer (proved).
func (b *Mailbox) Publish(ctx context.Context, rec *protocol.Revocations) (protocol.Address, error) {
	a := protocol.AddressOf(rec.Identity)
	if len(rec.Revocation) == 0 && len(rec.RevokedCertificates) == 0 {
		return a, refuse("the record holds no revocation of the address and none of its certificates")
	}
	if len(rec.Revocation) > 0 {
		if _, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation); err != nil {
			return a, refuse("the record is not a revocation: %v", err)
		}
	}
	if len(rec.RevokedCertificates) > 0 {
		if _, err := protocol.VerifyRevokedCertificates(a, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
			return a, refuse("the record's revocation of certificates: %v", err)
		}
	}
	if b.id == nil {
		return a, served(a, b.publishRecord(ctx, a, rec))
	}
	// As this mailbox, under its lock: what the server then shows of a
	// revocation is kept once it verifies (proved). A revocation of its
	// certificates below the one the server holds is answered conflict: the
	// mailbox reads itself and keeps that one once it verifies, which covers this
	// one, and the record has nothing left to do.
	return a, b.lockedFinishedDo(ctx, func() error {
		err := b.publishRecord(ctx, a, rec)
		if code(err) != protocol.CodeConflict || a != b.id.Address() || len(rec.RevokedCertificates) == 0 {
			return served(a, err)
		}
		mine, perr := protocol.ParseRevokedCertificates(rec.RevokedCertificates)
		if perr != nil {
			return err
		}
		if _, kerr := b.known(ctx); kerr != nil {
			return served(a, kerr)
		}
		if held, herr := b.revokedCerts(a); herr != nil || held == nil || held.Through < mine.Through {
			return errors.Join(err, herr)
		}
		return nil
	})
}

// served is a publish's error, but none where its server showed a's
// revocation, verified (proved): the address is ended there already, which
// covers whatever the record revokes.
func served(a protocol.Address, err error) error {
	var gone *RevokedError
	if errors.As(err, &gone) && gone.Address == a {
		return nil
	}
	return err
}

// publishRecord sends a checked record to this mailbox's server. A server answers
// a record sent for an address it holds revoked with revoked, without
// checking the record (PROTOCOL.md §11.15): taken only once what it shows
// verifies (proved).
func (b *Mailbox) publishRecord(ctx context.Context, a protocol.Address, rec *protocol.Revocations) error {
	_, err := b.call(ctx, http.MethodPut, "/v1/"+a.String()+"/revocations", rec, nil, nil)
	return err
}

// revokes reports whether rec holds a revocation of address a that verifies.
func revokes(a protocol.Address, rec *protocol.Revocations) bool {
	if rec == nil || len(rec.Revocation) == 0 {
		return false
	}
	_, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	return err == nil
}
