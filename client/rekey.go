package client

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
// needs no record of the numbers the lost machine used. The upload carries a
// pass under the new certificate, and the server then takes no pass under an
// older one.
// [Box.Receive] renews the prekey once it is more than a day old, so a box
// received at least monthly never lapses; Rekey is for a new key type, for
// recovery, and for boxes that are only ever sent from.
//
// It holds the box's lock, so two runs never make the same serial's key at
// once, and it refuses a served serial below the highest this box has
// published (a rollback), whose next serial's key was already published.
func (b *Box) Rekey(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, error) {
	return locked(ctx, b, func() (*protocol.Prekey, error) {
		p, err := b.rekey(ctx, kt)
		return p, b.proved(ctx, b.id.Address(), err, newLookups())
	})
}

// rekey is Rekey with the lock held. It returns the prekey once the server
// took it.
func (b *Box) rekey(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, error) {
	p, at, err := b.renew(ctx, kt)
	if err != nil {
		return nil, err
	}
	// By the reading the server took the renewal at (PROTOCOL.md §0).
	return p, b.prune(at)
}

func (b *Box) renew(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, taken, error) {
	st, err := b.readOwn(ctx, kt, false)
	if err != nil {
		return nil, taken{}, err
	}
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
	if err != nil {
		return nil, taken{}, err
	}
	return p, at, nil
}

// renewal is a renewal made and signed, ready to send.
type renewal struct {
	req protocol.PrekeyRequest
	// forgotten is set when the box's server holds no box at its address: it
	// forgot it, past its record's expiry, or the box was deleted. The
	// renewal then goes as a registration, which is how such a box comes
	// back (PROTOCOL.md §3, §7).
	forgotten bool
}

// sendRenewal publishes renewal r of statement n: as a new prekey, or to a
// server that forgot the box, as its registration. A box registered anew
// has no ACL at its server, so what this box kept of the last one the server
// took goes, and the next send or recv sends it again. It returns the
// reading the server took.
func (b *Box) sendRenewal(ctx context.Context, r renewal, n uint64) (taken, error) {
	if !r.forgotten {
		return b.publish(ctx, b.boxPath("/prekey"), r.req, n)
	}
	reg := protocol.RegisterRequest{Identity: b.id.Document(), Prekey: r.req.Prekey, PrekeySignature: r.req.PrekeySignature, SenderKeyTypes: r.req.SenderKeyTypes}
	at, err := b.publish(ctx, b.boxPath(""), reg, n)
	if err != nil {
		return taken{}, err
	}
	return at, removeIfExists(b.path("acl.json"))
}

// ownRead is what a renewal learned from its read of its own box.
type ownRead struct {
	// forgotten is set when the box's server holds no box at its address.
	forgotten bool
	// known is the highest certificate serial this box knows it has used:
	// what it published, and the served certificate's when the read could be
	// used.
	known uint64
	// kt is the key type the renewal makes: the one asked for, or the served
	// prekey's, or the published one's, or else post-quantum.
	kt protocol.KeyType
	// unread is why the remedy went on without its server's answer, or nil.
	unread error
}

// readOwn reads this box at its server (known), as a renewal does before
// it numbers anything, keeping what verifies of the box's own revocations.
// Every renewal asks, so the certificate it makes next is numbered above the
// highest serial it has been shown revoked, and is never revoked as it is
// made (PROTOCOL.md §2b), on a box restored from its identity too.
//
// A server that holds no box at this address shows nothing to number above
// or to hold to its order: the renewal is numbered above what this box knows
// of its own, and goes as a registration.
//
// With unused set, for the remedy, an answer it cannot use stops nothing: no
// answer, a served statement that does not verify, or one ordered before
// what this box published. The renewal is numbered from what the box knows,
// and the revocation still goes to whoever takes it (PROTOCOL.md §6.3). A
// plain renewal stops there: the refusal is the check.
func (b *Box) readOwn(ctx context.Context, kt protocol.KeyType, unused bool) (*ownRead, error) {
	out := &ownRead{kt: kt}
	o, err := b.known(ctx)
	if err != nil {
		return nil, err
	}
	out.forgotten = o.at == atNone
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
		case o.cert.Serial() < published || (o.cert.Serial() == published && o.statement.Serial < published):
			err = refuse("rollback: the server serves this box's prekey serial %d under certificate %d, before serial %d, which this box published", o.statement.Serial, o.cert.Serial(), published)
		default:
			if out.kt == "" {
				out.kt = o.statement.Type()
			}
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
		// Nothing served to read a type from and nothing published: a box
		// restored from its identity alone, at a server that forgot it, or
		// in the remedy one whose server's answer it cannot use. It takes
		// init's default.
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
	if own != nil && own.Through >= protocol.MaxSerial {
		return 0, nil, refuse("this box's identity has revoked its certificates through the highest serial there is, so no later certificate can be made: the address cannot renew")
	}
	if own != nil {
		known = max(known, own.Through)
	}
	if known >= protocol.MaxSerial {
		return 0, nil, refuse("this box's certificate serial is the highest there is, so no later certificate can be made: the address cannot renew")
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
	if known >= protocol.MaxSerial {
		return 0, nil, refuse("this box's certificate serial is the highest there is, so no later certificate can be made: the address cannot renew")
	}
	return protocol.SerialAt(b.now(), known), nil, nil
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
	stem := b.path("prekeys", strconv.FormatUint(next, 10))
	req.SenderKeyTypes = b.senderKeyTypes
	var err error
	if req.Prekey, err = os.ReadFile(stem + ".txt"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, out, err
	}
	if req.PrekeySignature, err = os.ReadFile(stem + ".txt.sig"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, out, err
	}
	return p, out, nil
}

// publishedType is the key type of statement n, which this box published, or
// "", the client's default, when it holds no statement n to read.
func (b *Box) publishedType(n uint64) protocol.KeyType {
	st, err := os.ReadFile(b.path("prekeys", strconv.FormatUint(n, 10)+".txt")) //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return ""
	}
	p, err := protocol.ParsePrekey(st)
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
// made while the clock read ahead of where it reads now: dropUnbegun), and
// whose working key the box holds. If it signed one that cannot be, the
// serial is spent. If it signed nothing, neither: a key it made and never
// signed is free to use.
func (b *Box) signedPrekey(serial uint64, kt protocol.KeyType) (p *protocol.Prekey, spent bool, err error) {
	stem := b.path("prekeys", strconv.FormatUint(serial, 10))
	if !exists(stem + ".txt.sig") {
		if err := removeIfExists(stem + ".made"); err != nil {
			return nil, false, err
		}
		return nil, false, removeIfExists(stem + ".txt")
	}
	st, err := os.ReadFile(stem + ".txt") //nolint:gosec // a path inside the box's own directory
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, false, err
	}
	sig, err := os.ReadFile(stem + ".txt.sig") //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return nil, false, err
	}
	p, _, err = protocol.VerifyPrekey(b.id, st, sig, b.now())
	if err != nil || p.Serial != serial || p.Type() != kt || p.Expired(b.now()) {
		return nil, true, nil //nolint:nilerr // a statement that does not verify is one this box will not send
	}
	if began, err := protocol.CertificateBegan(sig); err != nil || began.After(b.now().Add(-protocol.MaxSkew)) {
		return nil, true, nil //nolint:nilerr // under a certificate made while the clock read ahead
	}
	if _, _, err := b.worker(serial); err != nil {
		return nil, true, nil //nolint:nilerr // a statement whose working key this box cannot sign a pass with
	}
	if held, err := ageRecipient(stem + ".agekey"); err != nil || held != p.Key {
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

// highestBegun returns the highest serial this box has begun a prekey at: one
// it holds a key or a signed statement for, published or not. It is 0 when
// the box holds none.
func (b *Box) highestBegun() (uint64, error) {
	var top uint64
	for _, ext := range []string{".agekey", ".txt.sig"} {
		names, err := filepath.Glob(b.path("prekeys", "*"+ext))
		if err != nil {
			return 0, err
		}
		for _, name := range names {
			if n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(name), ext), 10, 64); err == nil {
				top = max(top, n)
			}
		}
	}
	return top, nil
}

// publishedSerial returns the highest prekey serial this box has published,
// or 0 if none is recorded.
func (b *Box) publishedSerial() (uint64, error) {
	s, err := os.ReadFile(b.path("serial"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseUint(strings.TrimSpace(string(s)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s is not a serial", b.path("serial"))
	}
	return n, nil
}

// recordPublished records serial as published, unless a higher one is.
func (b *Box) recordPublished(serial uint64) error {
	cur, err := b.publishedSerial()
	if err != nil || serial <= cur {
		return err
	}
	return writeFile(b.path("serial"), []byte(strconv.FormatUint(serial, 10)+"\n"))
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

// made returns when prekey n was signed, as the client that signed it kept
// it, in prekeys/<n>.made: a timestamp alone on its line. Nothing is
// inferred from the statement, whose lifetime is the box's to set. A
// prekey with no record has no time: Receive renews it, and dropRetired
// keeps every retired key while the newest has none.
func (b *Box) made(n uint64) (time.Time, error) {
	raw, err := os.ReadFile(b.path("prekeys", strconv.FormatUint(n, 10)+".made")) //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return time.Time{}, err
	}
	return protocol.ParseTime(strings.TrimSuffix(string(raw), "\n"))
}

// prekeyStatement returns prekey n's statement, as this box wrote it.
func (b *Box) prekeyStatement(n uint64) (*protocol.Prekey, error) {
	st, err := os.ReadFile(b.path("prekeys", strconv.FormatUint(n, 10)+".txt")) //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return nil, err
	}
	return protocol.ParsePrekey(st)
}

// renewIfDue publishes a new prekey, of the current type, when renewDue
// says so. The caller holds the lock. A failure is retried after
// renewRetry.
func (b *Box) renewIfDue(ctx context.Context) (*protocol.Prekey, error) {
	if !b.renewDue() {
		return nil, nil
	}
	if !b.renewFailed.IsZero() && b.now().Sub(b.renewFailed) < renewRetry {
		return nil, nil
	}
	p, err := b.rekey(ctx, "")
	if err != nil {
		b.renewFailed = b.now()
		return nil, err
	}
	b.renewFailed = time.Time{}
	return p, nil
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
	keys, err := filepath.Glob(b.path("prekeys", "*.agekey"))
	if err != nil {
		return err
	}
	var retired []uint64
	for _, k := range keys {
		if n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(k), ".agekey"), 10, 64); err == nil && n < cur {
			retired = append(retired, n)
		}
	}
	if len(retired) < 2 {
		return nil
	}
	slices.Sort(retired)
	newest := retired[len(retired)-1]
	if made, err := b.made(newest); err != nil || at.at.Sub(made) <= retiredGrace {
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
// made with it, if a renewal the server never took left one.
func (b *Box) removePrekey(n uint64) error {
	stem := b.path("prekeys", strconv.FormatUint(n, 10))
	for _, ext := range []string{".agekey", ".txt", ".made", ".txt.sig"} {
		if err := removeIfExists(stem + ext); err != nil {
			return err
		}
	}
	for _, ext := range []string{"", ".pub", "-cert.pub"} {
		if err := removeIfExists(b.workStem(n) + ext); err != nil {
			return err
		}
	}
	return nil
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
	keys, err := filepath.Glob(b.path("prekeys", "*.agekey"))
	if err != nil {
		return err
	}
	var top uint64
	for _, k := range keys {
		if n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(k), ".agekey"), 10, 64); err == nil && n > top {
			top = n
		}
	}
	for _, k := range keys {
		n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(k), ".agekey"), 10, 64)
		if err != nil || n >= top {
			continue
		}
		st, err := os.ReadFile(b.path("prekeys", fmt.Sprintf("%d.txt", n)))
		if err != nil {
			continue
		}
		p, err := protocol.ParsePrekey(st)
		if err != nil {
			continue
		}
		if !at.at.Before(p.NotAfter.Add(protocol.TTL)) {
			if err := b.removePrekey(n); err != nil {
				return err
			}
		}
	}
	return nil
}
