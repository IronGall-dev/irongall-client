package client

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

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
// and kept somewhere other than the box. A box that holds its own
// revocation returns the one it holds, and signs nothing (sign).
func (b *Box) Revocation() (*protocol.Revocations, error) {
	if gone, err := b.revoked(b.id.Address()); err != nil {
		return nil, err
	} else if gone {
		var sig []byte
		if err := b.view(func(s store) error { sig = s.get(bucketBox, "revoked"); return nil }); err != nil {
			return nil, err
		}
		return &protocol.Revocations{Identity: b.id.Document(), Revocation: sig}, nil
	}
	sig, err := b.identity.Revocation(b.id.Address())
	if err != nil {
		return nil, err
	}
	return &protocol.Revocations{Identity: b.id.Document(), Revocation: sig}, nil
}

// Revoke publishes a revocation to the server opt names: the address the
// record is for is revoked there, for good. It needs no box and no key, only the record, so a box
// that is lost can still be revoked with a record made in advance. The
// record is checked here first. It is [Publish], of a record that must
// carry a revocation of the address.
func Revoke(ctx context.Context, opt Options, rec *protocol.Revocations) (protocol.Address, error) {
	b, err := newBox("", opt)
	if err != nil {
		return protocol.Address{}, err
	}
	return b.Revoke(ctx, rec)
}

// Revoke is [Revoke] as this box: to its own server.
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
func (b *Box) KeepRevocation(rec *protocol.Revocations) (a protocol.Address, h *Held, err error) {
	_, err = lockedFinished(context.Background(), b, func() (struct{}, error) {
		a, h, err = b.keepRevocationRecord(rec)
		return struct{}{}, err
	})
	if err != nil && a == (protocol.Address{}) {
		a = protocol.Address(sha256.Sum256(rec.Identity))
	}
	return a, h, err
}

func (b *Box) keepRevocationRecord(rec *protocol.Revocations) (protocol.Address, *Held, error) {
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

// Ask asks this box's server what it holds about a, keeps what verifies, and
// returns what the box then holds: a box may ask at any time, and whatever
// it has verified about an address it keeps. A send asks by itself
// ([Box.SendWith]), and so does a drain, of each sender ([Box.Receive]).
//
// A server that answers that it holds nothing has answered, and that is its
// word: it can keep a record back, and nothing here tells. What the box
// holds already stands whatever a server answers. No answer is an error.
func (b *Box) Ask(ctx context.Context, a protocol.Address) (*Held, error) {
	return lockedFinished(ctx, b, func() (*Held, error) {
		if _, err := b.lookupRevocation(ctx, a, newLookups()); err != nil {
			return nil, err
		}
		return b.held(a)
	})
}

// keepRevocation records a revocation that has verified under id. It is never
// removed: a revoked address stays revoked.
func (b *Box) keepRevocation(id *protocol.Identity, sig []byte) error {
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
	// The box's own: the pass it kept is a signature already made, which
	// nothing may use now.
	return b.update(func(s store) error {
		if err := s.put(bucketBox, "revoked", sig); err != nil {
			return err
		}
		return s.del(bucketBox, "pass")
	})
}

// finished is this box's own revocation of its address, as an error. A box
// that holds one that verifies signs nothing more as that address, no pass,
// no mail and no certificate, whatever any server answers: a server that
// never saw the revocation would take it all (PROTOCOL.md §6.3). It still
// asks, keeps and publishes the record, which carry no pass. A kept one that
// no longer verifies is a fault, and stops the same.
func (b *Box) finished() error {
	gone, err := b.revoked(b.id.Address())
	if err != nil {
		return err
	}
	if gone {
		return &RevokedError{Address: b.id.Address(), Own: true}
	}
	return nil
}

// revoked reports whether this box holds a revocation of a. The kept
// signature is checked again each time, against the identity kept with it: a
// record that no longer verifies is an error, never a quiet "not revoked".
func (b *Box) revoked(a protocol.Address) (bool, error) {
	doc, sig, _, _, err := b.heldRecord(a)
	if err != nil || sig == nil {
		return false, err
	}
	if _, err := protocol.VerifyRevocation(a, doc, sig); err != nil {
		return false, fmt.Errorf("the revocation this box keeps for %s no longer verifies: %w", a, err)
	}
	return true, nil
}

// heldRecord is what this box keeps that a's identity signed about a: the
// identity document it holds for a (its own, or the one pinned), the
// revocation of the address, and the revocation of its certificates with
// its signature, each nil when the box keeps none.
func (b *Box) heldRecord(a protocol.Address) (doc, revocation, certs, certsSig []byte, err error) {
	err = b.view(func(s store) error {
		if a == b.id.Address() {
			doc, revocation = b.id.Document(), s.get(bucketBox, "revoked")
			if raw := s.get(bucketBox, "revoked-certs"); raw != nil {
				var rec protocol.Revocations
				if err := protocol.Unmarshal(raw, &rec); err != nil {
					return fmt.Errorf("the revocation of certificates this box keeps for itself is not a record: %w", err)
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

// readBox reads box a from this box's server (GET /v1/<a>, PROTOCOL.md
// §4.1), keeps what verifies of the revocations it carries, and with l marks
// a as answered in the command. It returns the box served, and whether this
// box now holds a revocation of a.
//
// A served box carries the revocation of its certificates the server holds,
// and a revoked address is answered 410 revoked with its record: either is
// kept once it verifies, and what does not verify counts as nothing shown,
// since only a statement the identity signed can revoke an address or a
// certificate. No such box, and "revoked" with nothing that verifies, are
// answers that serve no box: they come back as the server's error, which a
// caller reads as none held (lookupRevocation) or as nothing to seal to
// (resolve). Anything else is no answer.
func (b *Box) readBox(ctx context.Context, a protocol.Address, l *lookups) (*protocol.BoxResponse, bool, error) {
	var br protocol.BoxResponse
	_, err := b.lookup(ctx, a, &br)
	rec := br.Record()
	switch {
	case err == nil:
	case code(err) == protocol.CodeRevoked:
		rec = recordOf(err)
	case code(err) != protocol.CodeNoSuchMailbox:
		return nil, false, err
	}
	if rec != nil {
		if gone, err := b.take(a, rec); gone || err != nil {
			return nil, gone, err
		}
	}
	// The box's own server has answered, whatever it served and whoever
	// reads the box: a send at each post, a drain, a post's refusal checked.
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

// lookupRevocation asks what this box's server holds about a (readBox), and
// keeps what verifies. It reports whether this box now holds a revocation of a. A
// server that serves no box, because it holds none or says "revoked" and
// shows nothing that verifies, has answered that it holds no revocation,
// and the caller goes on. No answer is an error, which the caller stops on.
//
// Of this box's own address it reads what its server holds of it (known):
// its revocations too where the server holds no box. Any call there not
// answered is an error.
func (b *Box) lookupRevocation(ctx context.Context, a protocol.Address, l *lookups) (bool, error) {
	if held, err := b.revoked(a); held || err != nil {
		return held, err
	}
	if a == b.id.Address() {
		o, err := b.known(ctx)
		if err != nil {
			return false, err
		}
		if o.at == atRevoked {
			// An answer, whether or not what it showed verified.
			if l != nil {
				l.answered[a] = true
			}
			return b.revoked(a)
		}
		if o.err != nil {
			return false, o.err
		}
		if l != nil {
			l.answered[a] = true
		}
		return false, nil
	}
	_, gone, err := b.readBox(ctx, a, l)
	switch code(err) {
	case protocol.CodeRevoked, protocol.CodeNoSuchMailbox:
		err = nil
	}
	return gone, err
}

// revokedCerts returns the revocation of a's certificates this box holds, or
// nil. Like a kept revocation of an address it is checked again each time it
// is read, under the identity this box holds for the address: one that no
// longer verifies is an error, never a quiet "nothing revoked".
func (b *Box) revokedCerts(a protocol.Address) (*protocol.RevokedCertificates, error) {
	doc, _, statement, sig, err := b.heldRecord(a)
	if err != nil || statement == nil {
		return nil, err
	}
	certs, err := protocol.VerifyRevokedCertificates(a, doc, statement, sig)
	if err != nil {
		return nil, fmt.Errorf("the revocation of certificates this box keeps for %s no longer verifies: %w", a, err)
	}
	return certs, nil
}

// CertificatesRecord is the record of this box's own revocation of its
// certificates that it keeps, the one it published or was shown, or nil: what
// irongall cert publish-revoked sends again.
func (b *Box) CertificatesRecord() (*protocol.Revocations, error) {
	_, _, statement, sig, err := b.heldRecord(b.id.Address())
	if err != nil || statement == nil {
		return nil, err
	}
	return &protocol.Revocations{Identity: b.id.Document(), RevokedCertificates: statement, RevokedCertificatesSignature: sig}, nil
}

// keepRevokedCerts keeps a revocation of a's certificates if it verifies and
// runs through a higher serial than the one this box holds. One that does not
// verify, or runs no higher, changes nothing: only the identity's own
// signature revokes a certificate, and a certificate once revoked stays so.
// The statement is kept in one value with its signature, never without it.
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
	if a == b.id.Address() {
		line, err := json.Marshal(protocol.Revocations{Identity: doc, RevokedCertificates: statement, RevokedCertificatesSignature: sig})
		if err != nil {
			return err
		}
		return b.update(func(s store) error { return s.put(bucketBox, "revoked-certs", line) })
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

// RevokeEarlier revokes every certificate this box's identity made before
// the one in use: it signs a revocation of them, publishes it, and keeps it.
// [Box.RenewAndRevoke] is the whole remedy for a box whose working key may
// have been taken, and is what "irongall cert revoke-earlier" runs; this
// is its second half alone, for a box that has renewed already.
//
// It revokes through the serial below the one in use. A box numbers a
// certificate by its clock ([protocol.SerialAt]), so that covers every
// certificate made before this one on any machine, whether this box knows of
// it or not: one a lost machine made and never published is among them,
// unless that machine's clock read ahead of this one's (PROTOCOL.md §2b); a
// later run covers that one.
//
// It returns the revocation, or nil when the certificate in use has serial
// 1, which nothing is below.
// Mail this box sent under those certificates, and that its reader has not
// read yet, is refused too: nobody can tell it from a thief's.
func (b *Box) RevokeEarlier(ctx context.Context) (*protocol.RevokedCertificates, error) {
	return locked(ctx, b, func() (*protocol.RevokedCertificates, error) {
		current, err := b.publishedSerial()
		if err != nil {
			return nil, err
		}
		// What its server holds of the box's own revocations, kept where it
		// verifies: an answer it cannot use stops nothing.
		if _, err := b.known(ctx); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return b.revokeBelow(ctx, current)
	})
}

// A Remedy is what [Box.RenewAndRevoke] did.
type Remedy struct {
	// Below is the serial of the certificate this call made, numbered once
	// the revocation was final. Every certificate below it is revoked where
	// the revocation was taken.
	Below uint64
	// Prekey is the new prekey, if the server took it.
	Prekey *protocol.Prekey
	// NotRenewed is why the server did not take it, or nil.
	NotRenewed error
	// Revoked is the revocation of those certificates, if a server took it.
	Revoked *protocol.RevokedCertificates
	// NotRevoked is why the box's server did not take the revocation, or
	// nil.
	NotRevoked error
	// Unread is why the box's own server's read of it could not be used (no
	// answer, a statement that does not verify, or one ordered before what
	// the box published), or nil. The remedy went on: the certificate was
	// numbered from what the box knows.
	Unread error
}

// remedyWait is the longest Retry-After the remedy waits out before it sends
// its renewal once more. Once the revocation is taken, nothing under the
// certificates it revokes is: whoever spent the box's calls with a taken
// working key can spend no more, and a server's own pacing of the renewal
// ends within a refill.
const remedyWait = time.Minute

// RenewAndRevoke is the remedy for a box whose working key may have been
// taken, with the address kept: a revocation, signed by the identity, of
// every certificate before a new one, then a new prekey under a new working
// key and that new certificate.
//
// It reads the box once at its server, for what is held of the box's own
// revocation of its certificates. An answer it cannot use stops nothing: the
// revocation still goes to the server (PROTOCOL.md §6.3a). It sends nothing an earlier renewal left: whoever
// copied the box while one waited holds its working key too.
//
// The revocation is published first, through the serial below the number
// this machine's clock gives, or through the highest one held if that is
// higher. A server that holds a higher one it did not show answers conflict:
// the box asks again and signs that one. Only then is the new certificate
// numbered, one above the revocation, so it is never revoked as it is made,
// and the renewal is sent. Once a server has taken the revocation it takes
// nothing under the certificates it revokes, the one the box was using among
// them: whoever holds that working key can no longer spend the box's calls,
// and the renewal that follows is not counted against the identity's
// certificates for the day (PROTOCOL.md §6.3a). If the server refuses the
// renewal with a Retry-After of at most a minute, it is sent again once after
// it. While the box's server holds the revocation and not the renewal, the
// box takes no mail there and signs none, and [Box.Receive] and [Box.Rekey]
// send the renewal again.
//
// It returns no Remedy when it published nothing, and an error with one
// only for a fault after the renewal was taken.
func (b *Box) RenewAndRevoke(ctx context.Context, kt protocol.KeyType) (*Remedy, error) {
	return locked(ctx, b, func() (*Remedy, error) { return b.renewAndRevoke(ctx, kt) })
}

func (b *Box) renewAndRevoke(ctx context.Context, kt protocol.KeyType) (*Remedy, error) {
	own := b.id.Address()
	l := newLookups()
	st, err := b.readOwn(ctx, kt, true)
	if err != nil {
		return nil, err
	}
	// A box whose read showed it its own revocation has nothing to remedy:
	// the remedy's answer, not its guard, which is sign's.
	if err := b.finished(); err != nil {
		return nil, err
	}
	below, _, err := b.nextNumber(st, true)
	if err != nil {
		return nil, err
	}
	r := &Remedy{Below: below, Unread: st.unread}
	r.Revoked, r.NotRevoked = b.revokeBelow(ctx, below)
	// Numbered once the revocation is final: above whatever a server showed
	// on the way.
	held, err := b.revokedCerts(own)
	if err != nil {
		r.NotRenewed = err
		return r, nil
	}
	if held != nil && held.Through >= r.Below {
		if held.Through >= protocol.MaxSerial {
			r.NotRenewed = refuse("this box's identity has revoked its certificates through the highest serial there is, so no later certificate can be made: the address cannot renew")
			return r, nil
		}
		r.Below = held.Through + 1
	}
	p, req, err := b.makeRenewal(st, r.Below, nil)
	if err != nil {
		r.NotRenewed = err
		return r, nil
	}
	at, err := b.sendRenewal(ctx, req, r.Below)
	var api *APIError
	if at.at.IsZero() && errors.As(err, &api) && api.Status == http.StatusTooManyRequests && api.RetryAfter > 0 && api.RetryAfter <= remedyWait {
		select {
		case <-ctx.Done():
			r.NotRenewed = err
			return r, nil
		case <-time.After(api.RetryAfter):
		}
		at, err = b.sendRenewal(ctx, req, r.Below)
	}
	if at.at.IsZero() {
		r.NotRenewed = b.proved(ctx, own, err, l)
		return r, nil
	}
	// Taken: a fault of this box after that is the call's error, and the
	// renewal stands (#110).
	r.Prekey = p
	if err != nil {
		return r, err
	}
	// By the reading the server took the renewal at (PROTOCOL.md §0).
	return r, b.prune(at)
}

// ownRevokes reports whether this box holds a revocation of its own
// certificates that covers certificate n. One it cannot read covers nothing
// here: whoever reads it to apply it says so.
func (b *Box) ownRevokes(n uint64) bool {
	certs, err := b.revokedCerts(b.id.Address())
	return err == nil && certs != nil && certs.Revokes(n)
}

// revokeBelow signs, publishes and keeps the revocation of every
// certificate of this box's identity below serial, or through the highest
// serial it holds revoked if that is higher: every holder would refuse a
// lower one, and one that lacks it takes it. It returns nil when nothing is
// below. It signs from what the box holds, which its caller has asked.
//
// A server that holds a higher one it did not show answers conflict. The box
// then asks once more and signs again. What the server took is kept.
func (b *Box) revokeBelow(ctx context.Context, serial uint64) (*protocol.RevokedCertificates, error) {
	if serial <= 1 {
		return nil, nil
	}
	own := b.id.Address()
	var took *protocol.RevokedCertificates
	for try := 0; ; try++ {
		through := serial - 1
		held, err := b.revokedCerts(own)
		if err != nil {
			return took, err
		}
		if held != nil {
			through = max(through, held.Through)
		}
		certs, err := protocol.NewRevokedCertificates(own, through)
		if err != nil {
			return took, err
		}
		sig, err := b.identity.RevokedCertificates(certs)
		if err != nil {
			return took, err
		}
		rec := &protocol.Revocations{Identity: b.id.Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
		// Once the server has taken it, it is out, and this box keeps it: the
		// next one it signs runs at least as high.
		perr := b.publishRecord(ctx, own, rec)
		if perr == nil {
			if err := b.keepRevokedCerts(own, rec.Identity, rec.RevokedCertificates, rec.RevokedCertificatesSignature); err != nil {
				return took, err
			}
			took = certs
		}
		if try == 0 && code(perr) == protocol.CodeConflict {
			if _, err := b.known(ctx); err != nil {
				return took, err
			}
			if err := ctx.Err(); err != nil {
				return took, err
			}
			continue
		}
		if took == nil {
			return nil, perr
		}
		return took, perr
	}
}

// proved turns a server's "revoked" into something this box has checked. who
// is the box a call named. If err is the server saying who is revoked, or
// that this box is, the server is asked for the revocation: one that verifies
// makes it a [RevokedError], which is final. With none, the error says so and
// stays what it was, a call that failed: a server's word revokes nothing.
func (b *Box) proved(ctx context.Context, who protocol.Address, err error, l *lookups) error {
	switch code(err) {
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

// lookups is what one command has asked as it went: one send, one flush,
// one drain, or one question.
type lookups struct {
	// answered are the addresses this command has its server's answer
	// about: a drain asks nothing more about them, and a send reads their
	// box at each post.
	answered map[protocol.Address]bool
}

func newLookups() *lookups {
	return &lookups{answered: map[protocol.Address]bool{}}
}

// take keeps what verifies of a record a server showed for a: a revocation of
// its certificates, of the address, or both. It reports
// whether the box now holds a revocation of a. What does not verify counts
// as nothing shown: only the identity's own signature revokes.
func (b *Box) take(a protocol.Address, rec *protocol.Revocations) (bool, error) {
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
// address, a revocation of its certificates, or both. It needs no box and no
// key, only the record, so a box that is lost can still be revoked with a
// record made in advance ([Box.Revocation]). Each part is checked here
// first, and a record with a part that does not verify goes nowhere.
func Publish(ctx context.Context, opt Options, rec *protocol.Revocations) (protocol.Address, error) {
	b, err := newBox("", opt)
	if err != nil {
		return protocol.Address{}, err
	}
	return b.Publish(ctx, rec)
}

// Publish is [Publish] as this box: to its own server, under its lock. It
// keeps nothing of the record: see [Box.KeepRevocation].
func (b *Box) Publish(ctx context.Context, rec *protocol.Revocations) (protocol.Address, error) {
	a := protocol.Address(sha256.Sum256(rec.Identity))
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
		return a, b.publishRecord(ctx, a, rec)
	}
	// As this box, under its lock: of its own address, what the server then
	// serves is kept (servesRevocation).
	return a, b.lockedFinishedDo(ctx, func() error { return b.publishRecord(ctx, a, rec) })
}

// publishRecord sends a checked record to this box's server.
func (b *Box) publishRecord(ctx context.Context, a protocol.Address, rec *protocol.Revocations) error {
	_, err := b.call(ctx, http.MethodPut, "/v1/"+a.String()+"/revocations", rec, nil, nil)
	if code(err) == protocol.CodeRevoked {
		served, serr := b.servesRevocation(ctx, a)
		if serr != nil {
			return serr
		}
		if served {
			return nil // the address is ended there already, which covers whatever the record revokes
		}
	}
	return err
}

// servesRevocation reports whether this box's server shows a revocation of
// address a that verifies. A server answers a record sent for an address it
// holds revoked with revoked, without checking the record (PROTOCOL.md
// §6.3); that answer is taken only once what it serves is checked. Of this
// box's own address, what verifies is kept (known), as all a box verifies
// of itself is; of another's, nothing is, and a publish with no box
// ([Publish]) keeps nothing.
func (b *Box) servesRevocation(ctx context.Context, a protocol.Address) (bool, error) {
	if b.id != nil && a == b.id.Address() {
		if _, err := b.known(ctx); err != nil {
			return false, err
		}
		return b.revoked(a)
	}
	_, err := b.call(ctx, http.MethodGet, "/v1/"+a.String(), nil, nil, nil)
	rec := recordOf(err)
	if rec == nil || len(rec.Revocation) == 0 {
		return false, nil
	}
	_, err = protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	return err == nil, nil
}
