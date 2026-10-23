package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Rekey publishes a NEW prekey, of type kt, or of the current prekey's type
// if kt is empty (post-quantum, init's default, when there is none to read),
// signed by a NEW working key under a new certificate. The three share one
// number, which this machine's clock gives
// ([protocol.SerialAt]). If an earlier Rekey signed one and the server did
// not take it, that one is sent again, unchanged, until it can no longer be
// sent (PROTOCOL.md §6.4): it has expired or does not verify by this clock,
// its certificate began less than an hour before the clock or is at or below
// a serial the identity revoked, it was made for longer than the box's
// lifetime now allows or has no record of when it was made, this box no
// longer holds its key or its working key, or another type is asked for. A
// key is signed once, so no key is encrypted to for longer than its
// lifetime, at most 33 days or the box's shorter one, whatever the server
// does with what it was sent. It needs only the identity, so it also
// recovers a box that lost its prekeys or its working key, and such a box
// needs no record of the numbers the lost machine used; one that lost its
// allowed, blocked and policy files too takes them from the ACL its server
// holds (adoptPending). The upload carries a pass under the new
// certificate, and the server then takes no pass under an older one.
// [Box.Receive] renews the prekey once it is more than a day old, so a box
// received at least monthly never lapses; Rekey is for a new key type, for
// recovery, and for boxes that are only ever sent from.
//
// It holds the box's lock, so two runs never make the same serial's key at
// once, and it refuses a served serial below the highest this box has
// published (a rollback), whose next serial's key was already published. A
// prekey with an error is one the server took, and a fault of this box after
// that.
func (b *Box) Rekey(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, error) {
	return locked(ctx, b, func() (*protocol.Prekey, error) { return b.rekeyAdopting(ctx, kt) })
}

// rekeyAdopting is rekey, after which a restore adopts the ACL its server
// holds once its renewal is taken (adoptPending; #366): Rekey and Init's
// restore from an identity alone. Receive's renewal adopts it where it reads
// the server's ACL (checkACL).
func (b *Box) rekeyAdopting(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, error) {
	p, err := b.rekey(ctx, kt)
	if p == nil || err != nil {
		return p, err
	}
	_, err = b.adoptPending(ctx)
	return p, err
}

// rekey is Rekey with the lock held. It returns the prekey once the server
// took it: an error beside it is a fault of this box after that.
func (b *Box) rekey(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, error) {
	p, at, err := b.renew(ctx, kt)
	if err != nil {
		return p, err
	}
	// By the reading the server took the renewal at (PROTOCOL.md §0).
	return p, b.prune(at)
}

// renew reads the box at its server, numbers and makes the renewal, and
// sends it. It returns the prekey and the reading the server took it at once
// it is taken, with an error beside them only for a fault of this box after
// that (#110).
func (b *Box) renew(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, taken, error) {
	st, err := b.readOwn(ctx, kt, false)
	if err != nil {
		return nil, taken{}, err
	}
	return b.renewFrom(ctx, st)
}

// renewFrom is renew from what the box knows of itself at its server, st.
func (b *Box) renewFrom(ctx context.Context, st *ownRead) (*protocol.Prekey, taken, error) {
	next, signed, err := b.nextNumber(st, false)
	if err != nil {
		return nil, taken{}, err
	}
	p, req, err := b.makeRenewal(st, next, signed)
	if err != nil {
		return nil, taken{}, err
	}
	// From here a statement at next exists, signed, whatever the server
	// makes of it.
	at, err := b.sendRenewal(ctx, req, next)
	if at.None() {
		return nil, taken{}, err
	}
	return p, at, err
}

// renewal is a renewal made and signed, ready to send.
type renewal struct {
	req protocol.PrekeyRequest
	// forgotten is set when the box's server holds no box at its address: it
	// forgot it, past its record's expiry. The renewal then goes as a
	// registration, which is how such a box comes back (PROTOCOL.md §3, §7).
	forgotten bool
}

// sendRenewal publishes renewal r of statement n: as a new prekey, or to a
// server that forgot the box, as its registration. A server that holds no
// box holds no ACL of it, and a box registered anew has none there, so what
// this box kept of the last one the server took goes before the registration
// is sent: whatever becomes of the answer, a fault after it or a process
// ended before it is recorded, the next send or recv sends the ACL again
// (#324). So does a restore's adoption of it, which has nothing to adopt
// (#366). It returns the reading the server took, as publish does.
func (b *Box) sendRenewal(ctx context.Context, r renewal, n uint64) (taken, error) {
	if !r.forgotten {
		return b.publish(ctx, b.boxPath("/prekey"), r.req, n)
	}
	if err := b.update(func(s store) error {
		if err := s.del(bucketBox, "acl"); err != nil {
			return err
		}
		return s.del(bucketIntent, "adopt-acl")
	}); err != nil {
		return taken{}, err
	}
	reg := protocol.RegisterRequest{Identity: b.id.Document(), Prekey: r.req.Prekey, PrekeySignature: r.req.PrekeySignature, SenderKeyTypes: r.req.SenderKeyTypes}
	return b.publish(ctx, b.boxPath(""), reg, n)
}

// ownRead is what a renewal learned from its read of its own box.
type ownRead struct {
	// forgotten is set when the box's server holds no box at its address.
	forgotten bool
	// known is the highest certificate serial this box knows it has used:
	// what it published, and the served certificate's when the read could be
	// used.
	known uint64
	// kt is the key type the renewal makes: the one asked for, or the one this
	// box published last, by its own record, never a served statement's
	// (#61), or else post-quantum.
	kt protocol.KeyType
	// unread is why the remedy went on without its server's answer, or nil.
	unread error
}

// readOwn reads this box at its server (known), as a renewal does before
// it numbers anything, keeping what verifies of the box's own revocations.
// Every renewal asks, so the certificate it makes next is numbered above the
// highest serial it has been shown revoked, and is never revoked as it is
// made (PROTOCOL.md §2b), on a box restored from its identity too. A read
// that showed the box its own revocation is known's error, which ends the
// renewal here, in those words: such a box signs nothing more (§6.3; #339).
//
// A server that holds no box at this address shows nothing to number above
// or to hold to its order: the renewal is numbered above what this box knows
// of its own, and goes as a registration.
//
// With unused set, for the remedy, an answer it cannot use stops nothing: no
// answer, a served statement that does not verify, or one ordered before
// what this box published. The renewal is numbered from what the box knows,
// and the revocation still goes to the server (PROTOCOL.md §6.3a). A plain
// renewal stops there: the refusal is the check.
func (b *Box) readOwn(ctx context.Context, kt protocol.KeyType, unused bool) (*ownRead, error) {
	out := &ownRead{kt: kt}
	o, err := b.known(ctx)
	if err != nil {
		return nil, err
	}
	out.forgotten = o.at == atNone
	// A restore from the identity alone adopts its server's ACL once a
	// renewal is taken: marked before anything is signed (#366). A server
	// that holds no box holds no ACL of it, so a registration adopts none.
	if !out.forgotten {
		if err := b.beginAdoption(); err != nil {
			return nil, err
		}
	}
	if o.err != nil {
		if !unused || ctx.Err() != nil {
			return nil, o.err
		}
		out.unread = o.err
	}
	published, err := b.publishedSerial()
	if err != nil {
		return nil, err
	}
	out.known = published
	if o.at == atServed {
		var err error
		switch {
		case o.bad != nil:
			err = refuse("this box's current prekey, as served: %v", o.bad)
		// A box's statements are ordered by certificate first, then by
		// serial, and this box gives a renewal's certificate and prekey one
		// number. So what it published is (published, published), and the
		// server may serve nothing ordered before it.
		case before(o.cert.Serial(), o.statement.Serial, published, published):
			err = refuse("rollback: the server serves this box's prekey serial %d under certificate %d, before serial %d, which this box published", o.statement.Serial, o.cert.Serial(), published)
		default:
			out.known = max(o.cert.Serial(), published)
		}
		if err != nil {
			if !unused {
				return nil, err
			}
			out.unread = err
		}
	}
	if out.kt == "" {
		out.kt = b.publishedType(published)
	}
	if out.kt == "" {
		// Nothing published: a new box, or one restored from its identity
		// alone. It takes init's default, whatever a server serves in its name.
		out.kt = protocol.PostQuantum
	}
	return out, nil
}

// nextNumber is the serial a renewal takes. It returns, too, the statement
// an earlier attempt signed at that serial when that one is sent again.
//
// A serial is signed once. A statement an earlier attempt signed, and
// never saw published, is sent again exactly as it is: signed again, its
// not_after counted from now, it would hand a server that fails every
// renewal and keeps what it was sent the same key for 33 more days at
// each retry, without end. Once such a statement can no longer be sent
// (it expired, or a key of another type is wanted), a new number is
// taken, above it: its key stays, as a retired one, for mail it may yet
// decrypt. Nothing at or below the highest serial this box signed is
// signed anew, and that one's files are never pruned, so a serial is
// never used twice.
//
// With unused set it takes nothing an earlier attempt left: not a statement
// signed before this call, and not a key or working key made for one. It is
// for a box whose working key may have been taken ([Box.RenewAndRevoke]):
// whoever copied the box while a renewal waited holds that renewal's working
// key too, so sent again it would hand them the box's next certificate.
func (b *Box) nextNumber(st *ownRead, unused bool) (uint64, *protocol.Prekey, error) {
	// The number must be above the served CERTIFICATE's serial, not the
	// served prekey's: the new statement is under a new certificate, which
	// outranks any prekey serial under the one before. So a prekey published
	// in this box's name at the highest serial there is, by whoever took its
	// working key, holds nothing: the next certificate passes it.
	// And above every serial this box's identity has revoked: a certificate
	// numbered there would be revoked as it was made, and the box could not
	// renew until its identity revoked fewer, which it never does. So a
	// waiting statement at or below one is passed over too.
	known := st.known
	own, err := b.revokedCerts(b.id.Address())
	if err != nil {
		return 0, nil, err
	}
	if own != nil {
		known = max(known, own.Through)
	}
	// A number an earlier attempt took, and that nothing has passed since,
	// is kept: its statement is the one sent again, and a key made for it
	// and never signed is used. Any other renewal takes a new number, from
	// this machine's clock (protocol.SerialAt): a box restored from its
	// identity knows only what the server shows it, and the clock puts its
	// certificate above every one made before, on whatever machine.
	begun, err := b.highestBegun()
	if err != nil {
		return 0, nil, err
	}
	switch {
	case begun > known && unused:
		// Whatever an earlier attempt left is passed over, as a spent
		// statement is: its key stays, as a retired one.
		known = begun
	case begun > known:
		signed, spent, err := b.signedPrekey(begun, st.kt)
		if err != nil {
			return 0, nil, err
		}
		if !spent {
			return begun, signed, nil
		}
		known = begun // the new number is above the spent one too
	}
	if err := noneAbove(known); err != nil {
		return 0, nil, err
	}
	return protocol.SerialAt(b.now(), known), nil, nil
}

// noneAbove is the refusal of a renewal numbered above n, the highest serial
// this box knows of its own or holds revoked, when n is the highest serial
// there is (protocol.MaxSerial): no later certificate can be made.
func noneAbove(n uint64) error {
	if n < protocol.MaxSerial {
		return nil
	}
	return refuse("this box's certificates run through the highest serial there is, its own or revoked by its identity, so no later certificate can be made: the address cannot renew")
}

// before reports whether a statement at prekey serial n under certificate
// cert stands before one at (seenN, seenCert) in its box's order: by
// certificate first, then by the prekey's own serial (PROTOCOL.md §2b;
// decided on #48). A later certificate passes any serial under an earlier one.
func before(cert, n, seenCert, seenN uint64) bool {
	return cert < seenCert || cert == seenCert && n < seenN
}

// makeRenewal makes and signs renewal next, of st's key type, or takes p,
// the statement an earlier attempt signed at next, and reads what it sends.
func (b *Box) makeRenewal(st *ownRead, next uint64, p *protocol.Prekey) (*protocol.Prekey, renewal, error) {
	out := renewal{forgotten: st.forgotten}
	req := &out.req
	if p == nil {
		var err error
		if p, err = b.makePrekey(next, st.kt); err != nil {
			return nil, out, err
		}
	}
	rec, err := b.prekeyOf(next)
	if err != nil {
		return nil, out, err
	}
	if rec == nil {
		return nil, out, fmt.Errorf("the box's state file keeps no statement of prekey %d", next)
	}
	req.SenderKeyTypes, req.Prekey, req.PrekeySignature = b.senderKeyTypes, rec.Statement, rec.Signature
	return p, out, nil
}

// publishedType is the key type of statement n, which this box published, or
// "", the client's default, when it holds no statement n to read.
func (b *Box) publishedType(n uint64) protocol.KeyType {
	p, err := b.prekeyStatement(n)
	if err != nil {
		return ""
	}
	return p.Type()
}

// signedPrekey looks at what an earlier attempt left for a serial. If it
// signed a statement that can still be sent, that statement is returned: the
// box's own, for this serial and the key it holds, of type kt, not expired,
// made for no longer than the box's lifetime now allows, under a certificate
// that is valid now, began at least protocol.MaxSkew before now (so was not
// made while the clock read ahead of where it reads now: a reader whose clock
// a server takes may not have reached its start), and whose working key the
// box holds. If it signed one that cannot be, the serial is spent. If it
// signed nothing, neither: a key it made and never signed is free to use.
func (b *Box) signedPrekey(serial uint64, kt protocol.KeyType) (p *protocol.Prekey, spent bool, err error) {
	rec, err := b.prekeyOf(serial)
	if err != nil || rec == nil {
		return nil, false, err
	}
	p, _, err = protocol.VerifyPrekey(b.id, rec.Statement, rec.Signature, b.now())
	if err != nil || p.Serial != serial || p.Type() != kt || p.Expired(b.now()) {
		return nil, true, nil //nolint:nilerr // a statement that does not verify is one this box will not send
	}
	if began, err := protocol.CertificateBegan(rec.Signature); err != nil || began.After(b.now().Add(-protocol.MaxSkew)) {
		return nil, true, nil //nolint:nilerr // under a certificate made while the clock read ahead
	}
	if _, _, err := b.worker(serial); err != nil {
		return nil, true, nil //nolint:nilerr // a statement whose working key this box cannot sign a pass with
	}
	if held, err := ageRecipient(b.path("prekeys", strconv.FormatUint(serial, 10)+".agekey")); err != nil || held != p.Key {
		return nil, true, nil //nolint:nilerr // a statement for a key this box does not hold
	}
	// Made for longer than the box's lifetime now allows, or with no record
	// of when: spent, as an expired one is, so a lifetime set lower holds
	// from the next renewal whatever waited (PROTOCOL.md §6.4).
	lifetime, err := b.PrekeyLifetime()
	if err != nil {
		return nil, false, err
	}
	if made, err := b.made(serial); err != nil || p.NotAfter.Sub(made) > lifetime {
		return nil, true, nil //nolint:nilerr // a statement made for longer than this box now signs one for
	}
	return p, false, nil
}

// highestBegun returns the highest serial this box has begun a prekey at: the
// renewal under way, or the highest statement it signed, published or not. It
// is 0 when the box has begun none.
func (b *Box) highestBegun() (top uint64, err error) {
	err = b.view(func(s store) error {
		n, err := decimal(s.get(bucketIntent, "renewal"), "renewal")
		top = n
		return err
	})
	if err != nil {
		return 0, err
	}
	signed, err := b.prekeys()
	if len(signed) > 0 {
		top = max(top, signed[len(signed)-1])
	}
	return top, err
}

// publishedSerial returns the highest prekey serial this box has published,
// or 0 if none is recorded.
func (b *Box) publishedSerial() (n uint64, err error) {
	err = b.view(func(s store) error {
		n, err = decimal(s.get(bucketBox, "serial"), "serial")
		return err
	})
	return n, err
}

// recordPublished records serial as published, unless a higher one is.
func (b *Box) recordPublished(s store, serial uint64) error {
	cur, err := decimal(s.get(bucketBox, "serial"), "serial")
	if err != nil || serial <= cur {
		return err
	}
	return s.put(bucketBox, "serial", strconv.AppendUint(nil, serial, 10))
}

// decimal is a number the box's state keeps in decimal digits, or 0 when it
// keeps none: one of anything else is an error, never 0.
func decimal(v []byte, name string) (uint64, error) {
	if v == nil {
		return 0, nil
	}
	n, err := strconv.ParseUint(string(v), 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != string(v) {
		return 0, fmt.Errorf("the box's state file holds a %s that is no number", name)
	}
	return n, nil
}

// renewAfter is how old the current prekey may get before Receive renews
// it: a day, so a box received at least monthly never lapses, and a busy
// box renews at most daily.
const renewAfter = 24 * time.Hour

// renewTime is the room a renewal leaves for its own calls, beside
// protocol.MaxSkew: from the start of the Receive that renews to the server
// taking the new prekey, the read of the box's own box and the upload.
const renewTime = time.Hour

// MinPrekeyLifetime is the shortest a box's prekeys may be valid for: the
// day Receive waits to renew one (renewAfter), an hour of slip for when recv
// runs, renewTime, and protocol.MaxSkew for clocks, the hour a sender's may
// read ahead of the box's (PROTOCOL.md §0, §6.4). At it, an hourly recv
// renews in time.
const MinPrekeyLifetime = renewAfter + time.Hour + renewTime + protocol.MaxSkew

// RecvWithin is how often a box must run Receive for a prekey of the given
// lifetime to be renewed while every sender whose clock a server takes still
// takes it: Receive renews one once it is a day old, and the prekey then has
// renewTime and protocol.MaxSkew left, the room whoever makes a time-limited
// thing leaves (PROTOCOL.md §0).
func RecvWithin(lifetime time.Duration) time.Duration {
	return lifetime - renewAfter - renewTime - protocol.MaxSkew
}

// lifetimeGrammar is what a box's prekey-lifetime file holds: a number of
// seconds, alone on its line. Both clients hold the file to it.
var lifetimeGrammar = regexp.MustCompile(`\A[1-9][0-9]{0,9}\n?\z`)

// PrekeyLifetime is how long each new prekey of this box is valid for: the
// seconds its prekey-lifetime file names, or protocol.PrekeyLifetime when it
// has none. A file that names anything but a lifetime from
// MinPrekeyLifetime to protocol.PrekeyLifetime is an error, never read as the
// default: the box renews no prekey until it is put right.
func (b *Box) PrekeyLifetime() (time.Duration, error) {
	raw, err := os.ReadFile(b.path("prekey-lifetime"))
	if errors.Is(err, fs.ErrNotExist) {
		return protocol.PrekeyLifetime, nil
	}
	if err != nil {
		return 0, err
	}
	if lifetimeGrammar.Match(raw) {
		n, err := strconv.ParseInt(strings.TrimSuffix(string(raw), "\n"), 10, 64)
		if d := time.Duration(n) * time.Second; err == nil && d >= MinPrekeyLifetime && d <= protocol.PrekeyLifetime {
			return d, nil
		}
	}
	return 0, fmt.Errorf("this box's prekey-lifetime file names no lifetime: %s", lifetimeRule)
}

// lifetimeRule is what a prekey lifetime is, as a box's owner is told it.
var lifetimeRule = fmt.Sprintf("one is a number of seconds, alone on its line, from %d (a day and three hours) to %d (33 days)", int64(MinPrekeyLifetime/time.Second), int64(protocol.PrekeyLifetime/time.Second))

// SetPrekeyLifetime writes the box's prekey-lifetime file: each prekey made
// from now on is valid for d, a whole number of seconds from
// MinPrekeyLifetime to protocol.PrekeyLifetime. The prekey in use keeps its
// own; Receive renews it at once if it was made for longer.
func (b *Box) SetPrekeyLifetime(ctx context.Context, d time.Duration) error {
	if d < MinPrekeyLifetime || d > protocol.PrekeyLifetime || d%time.Second != 0 {
		return fmt.Errorf("%v is no prekey lifetime: %s", d, lifetimeRule)
	}
	return b.lockedFinishedDo(ctx, func() error {
		return writeFile(b.path("prekey-lifetime"), []byte(strconv.FormatInt(int64(d/time.Second), 10)+"\n"))
	})
}

// retiredGrace is how long after a renewal a drain must begin before it may
// delete prekeys: room for a send the server took as the renewal landed.
const retiredGrace = time.Hour

// renewRetry is how long Receive waits to try a failed renewal again, so a
// refused one (a rate limit, a server that is down) is not tried every poll.
const renewRetry = time.Hour

// current returns the serial of the prekey this box published last.
func (b *Box) current() (uint64, error) {
	n, err := b.publishedSerial()
	if err == nil && n == 0 {
		err = errors.New("this box has published no prekey")
	}
	return n, err
}

// made returns when prekey n was signed, as the box keeps it with the
// statement. Nothing is inferred from the statement, whose lifetime is the
// box's to set.
func (b *Box) made(n uint64) (time.Time, error) {
	rec, err := b.prekeyOf(n)
	if err != nil {
		return time.Time{}, err
	}
	if rec == nil {
		return time.Time{}, fmt.Errorf("this box keeps no statement of prekey %d", n)
	}
	return protocol.ParseTime(rec.Made)
}

// prekeyStatement returns prekey n's statement, as this box signed it.
func (b *Box) prekeyStatement(n uint64) (*protocol.Prekey, error) {
	rec, err := b.prekeyOf(n)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, fmt.Errorf("this box keeps no statement of prekey %d", n)
	}
	return protocol.ParsePrekey(rec.Statement)
}

// renewFailure is a renewal Receive tried that did not go through, as the box
// keeps it: when, by this machine's clock, and why, in this client's words.
// It is one the server did not take, or one it took that did not mend the
// drain it was made for.
type renewFailure struct {
	At    string `json:"at"`
	Error string `json:"error"`
}

// renewIfDue publishes a new prekey, of the current type, when renewDue
// says so. The caller holds the lock. A failure is kept, and tried again only
// renewRetry after it, by whichever process runs then (#10); until then each
// Receive says why the last one failed, so recv says the box needs a look
// until a renewal is taken. A failure dated after the clock's reading holds
// nothing back: the clock has gone back since (#201).
func (b *Box) renewIfDue(ctx context.Context) (*protocol.Prekey, error) {
	if !b.renewDue() {
		return nil, nil
	}
	return b.renewNow(ctx)
}

// renewNow is renewIfDue's renewal, held to the same hour after a failure.
func (b *Box) renewNow(ctx context.Context) (*protocol.Prekey, error) {
	var last renewFailure
	if err := b.view(func(s store) error {
		if raw := s.get(bucketBox, "renew-failed"); raw != nil {
			return protocol.Unmarshal(raw, &last)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("the box's state file keeps a failed renewal it cannot read: %w", err)
	}
	if at, err := protocol.ParseTime(last.At); err == nil {
		if since := b.now().Sub(at); since >= 0 && since < renewRetry {
			return nil, fmt.Errorf("the renewal at %s did not go through, and recv tries it again from %s: %s", last.At, at.Add(renewRetry).Format(protocol.TimeLayout), last.Error)
		}
	}
	p, err := b.rekey(ctx, "")
	if p == nil && err != nil {
		// A box that holds its own revocation renews nothing again: there
		// is nothing to try in an hour.
		var gone *RevokedError
		if errors.As(err, &gone) {
			return nil, err
		}
		return nil, errors.Join(err, b.holdRenewal(err))
	}
	return p, err
}

// holdRenewal keeps why a renewal did not go through, so renewNow tries the
// next one only renewRetry after it.
func (b *Box) holdRenewal(why error) error {
	failed, err := json.Marshal(renewFailure{At: b.now().UTC().Format(protocol.TimeLayout), Error: why.Error()})
	if err != nil {
		return err
	}
	return b.update(func(s store) error { return s.put(bucketBox, "renew-failed", failed) })
}

// renewDue reports whether the current prekey is to be renewed: once it is
// more than renewAfter old; when it, or the record of when it was made,
// cannot be read; when it was made for longer than the box's prekey
// lifetime now allows, so a lifetime set lower holds from the next recv; when
// that lifetime cannot be read, so that the renewal fails and says why; and
// when this box's own identity has revoked the certificate it is using: such
// a box takes no mail until it publishes under a new one, and
// [Box.RenewAndRevoke] leaves it so when the server refused its renewal.
func (b *Box) renewDue() bool {
	n, err := b.current()
	if err != nil || b.ownRevokes(n) {
		return true
	}
	made, err := b.made(n)
	if err != nil || b.now().Sub(made) > renewAfter {
		return true
	}
	p, err := b.prekeyStatement(n)
	lifetime, lerr := b.PrekeyLifetime()
	return err != nil || lerr != nil || p.NotAfter.Sub(made) > lifetime
}

// dropRetired deletes every retired prekey but the newest, after a drain
// that emptied the box and whose list the server took at a reading more than
// retiredGrace after the newest retired prekey was made: every older one was
// retired by then. A send must
// name the recipient's current prekey serial, so mail encrypted to a retired
// prekey reached the server before the renewal that retired it, or with a
// send already in progress: such a drain collected all of it. The newest
// retired prekey is kept regardless. After this, mail encrypted to a deleted
// prekey is unrecoverable from the box's keys. irongall.sh does not do this;
// it keeps every retired prekey until prune's deletion time.
func (b *Box) dropRetired(at taken) error {
	cur, err := b.publishedSerial()
	if err != nil {
		return err
	}
	signed, err := b.prekeys()
	if err != nil {
		return err
	}
	var retired []uint64
	for _, n := range signed {
		if n < cur {
			retired = append(retired, n)
		}
	}
	if len(retired) < 2 {
		return nil
	}
	newest := retired[len(retired)-1]
	if made, err := b.made(newest); err != nil || at.At().Sub(made) <= retiredGrace {
		return nil //nolint:nilerr // a newest retired prekey that cannot be read keeps every key
	}
	for _, n := range retired[:len(retired)-1] {
		if err := b.removePrekey(n); err != nil {
			return err
		}
	}
	return nil
}

// removePrekey deletes a prekey's key and its statement, and the working key
// made with it, if a renewal the server never took left one: the files
// first, then the record, so a crash in between leaves a record of a key
// gone, which the next prune deletes again, and never a key no record names.
func (b *Box) removePrekey(n uint64) error {
	if err := removeIfExists(b.path("prekeys", strconv.FormatUint(n, 10)+".agekey")); err != nil {
		return err
	}
	for _, ext := range []string{"", ".pub", "-cert.pub"} {
		if err := removeIfExists(b.workStem(n) + ext); err != nil {
			return err
		}
	}
	return b.update(func(s store) error { return s.del(bucketPrekeys, serialKey(n)) })
}

// prune deletes every prekey but the newest this box holds whose deletion
// time has come by the reading at, one a server took: its not_after plus
// protocol.TTL. All mail encrypted to it arrived by its not_after and has
// expired by then; after this, that mail is unrecoverable from the box's
// keys. A drain's list taken, and a renewal taken, each run it, by the date
// of the pass that call carried: a clock far ahead is stopped at that pass,
// and one that moves while the call is in flight deletes nothing by where it
// went.
func (b *Box) prune(at taken) error {
	signed, err := b.prekeys()
	if err != nil || len(signed) == 0 {
		return err
	}
	for _, n := range signed[:len(signed)-1] {
		p, err := b.prekeyStatement(n)
		if err != nil {
			continue
		}
		if !at.At().Before(p.NotAfter.Add(protocol.TTL)) {
			if err := b.removePrekey(n); err != nil {
				return err
			}
		}
	}
	return nil
}
