package client

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Rekey publishes a NEW prekey, of type kt, or of the current prekey's type
// if kt is empty, signed by a NEW working key under a new certificate. The
// three share one number, which this machine's clock gives
// ([protocol.SerialAt]). If an earlier Rekey signed one and the server did
// not take it, that one is sent again, unchanged, until it expires: a key is
// signed once, so no key is encrypted to for more than 33 days whatever the
// server does with what it was sent. It needs only the identity, so it also
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
// While a drain holds the lock it waits, up to rekeyLockWait: a drain is
// short, and a monthly run that gave up at once could let the prekey expire.
func (b *Box) Rekey(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, error) {
	l, err := b.lockWait(ctx, rekeyLockWait)
	if err != nil {
		return nil, err
	}
	p, _, err := b.rekey(ctx, kt, false)
	if e := l.release(); err == nil {
		err = e
	}
	return p, err
}

// rekeyLockWait is how long Rekey waits for the box's lock.
var rekeyLockWait = time.Minute

// rekey is Rekey with the lock held. It returns the prekey once the server
// took it, and the number of the statement it sent, taken or not: 0 when it
// did not get as far as one.
//
// With unused set it sends nothing an earlier attempt left: not a statement
// signed before this call, and not a key or working key made for one. It is
// for a box whose working key may have been taken ([Box.RenewAndRevoke]):
// whoever copied the box while a renewal waited holds that renewal's working
// key too, so sent again it would hand them the box's next certificate.
func (b *Box) rekey(ctx context.Context, kt protocol.KeyType, unused bool) (*protocol.Prekey, uint64, error) {
	p, made, err := b.renew(ctx, kt, unused)
	if err != nil {
		return nil, made, err
	}
	return p, made, b.Prune()
}

func (b *Box) renew(ctx context.Context, kt protocol.KeyType, unused bool) (*protocol.Prekey, uint64, error) {
	var ir protocol.IdentityResponse
	if _, err := b.call(ctx, http.MethodGet, b.boxPath("/identity"), nil, nil, &ir); err != nil {
		return nil, 0, err
	}
	// Its own record, so judged as one: whether this identity ever certified
	// the key that signed it, even if that certificate has since ended.
	cur, curCert, err := protocol.VerifyPrekeyRecord(b.id, ir.Prekey, ir.PrekeySignature)
	if err != nil {
		return nil, 0, refuse("this box's current prekey, as served: %v", err)
	}
	published, err := b.publishedSerial()
	if err != nil {
		return nil, 0, err
	}
	// A box's statements are ordered by certificate first, then by serial,
	// and this box gives a renewal's certificate and prekey one number. So
	// what it published is (published, published), and the server may serve
	// nothing ordered before it.
	if curCert.Serial() < published || (curCert.Serial() == published && cur.Serial < published) {
		return nil, 0, refuse("rollback: the server serves this box's prekey serial %d under certificate %d, before serial %d, which this box published", cur.Serial, curCert.Serial(), published)
	}
	if kt == "" {
		kt = cur.Type()
	}
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
	// The number must be above the served CERTIFICATE's serial, not the
	// served prekey's: the new statement is under a new certificate, which
	// outranks any prekey serial under the one before. So a prekey published
	// in this box's name at the highest serial there is, by whoever took its
	// working key, holds nothing: the next certificate passes it.
	known := max(curCert.Serial(), published)
	if known >= protocol.MaxSerial {
		return nil, 0, refuse("this box's certificate serial is the highest there is, so no later certificate can be made: the address cannot renew")
	}
	// A number an earlier attempt took, and that nothing has passed since,
	// is kept: its statement is the one sent again, and a key made for it
	// and never signed is used. Any other renewal takes a new number, from
	// this machine's clock (protocol.SerialAt): a box restored from its
	// identity knows only what the server shows it, and the clock puts its
	// certificate above every one made before, on whatever machine.
	begun, err := b.highestBegun()
	if err != nil {
		return nil, 0, err
	}
	var next uint64
	var p *protocol.Prekey
	switch {
	case begun > known && unused:
		// Whatever an earlier attempt left is passed over, as a spent
		// statement is: its key stays, as a retired one.
		known = begun
	case begun > known:
		signed, spent, err := b.signedPrekey(begun, kt)
		if err != nil {
			return nil, 0, err
		}
		if spent {
			known = begun // the new number is above the spent one too
		} else {
			next, p = begun, signed
		}
	}
	if next == 0 {
		if known >= protocol.MaxSerial {
			return nil, 0, refuse("this box's certificate serial is the highest there is, so no later certificate can be made: the address cannot renew")
		}
		next = protocol.SerialAt(b.now(), known)
	}
	if p == nil {
		if p, err = b.makePrekey(next, kt); err != nil {
			return nil, 0, err
		}
	}
	stem := b.path("prekeys", strconv.FormatUint(next, 10))
	req := protocol.PrekeyRequest{SenderKeyTypes: b.senderKeyTypes}
	if req.Prekey, err = os.ReadFile(stem + ".txt"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, 0, err
	}
	if req.PrekeySignature, err = os.ReadFile(stem + ".txt.sig"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, 0, err
	}
	// From here a statement at next exists, signed, whatever the server
	// makes of it.
	if err := b.publish(ctx, http.MethodPut, b.boxPath("/prekey"), req, next); err != nil {
		return nil, next, err
	}
	return p, next, nil
}

// signedPrekey looks at what an earlier attempt left for a serial. If it
// signed a statement that can still be sent, that statement is returned: the
// box's own, for this serial and the key it holds, of type kt, not expired,
// under a certificate that is valid now and whose working key the box holds.
// If it signed one that cannot be, the serial is spent. If it signed nothing,
// neither: a key it made and never signed is free to use.
func (b *Box) signedPrekey(serial uint64, kt protocol.KeyType) (p *protocol.Prekey, spent bool, err error) {
	stem := b.path("prekeys", strconv.FormatUint(serial, 10))
	if !exists(stem + ".txt.sig") {
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
	if _, _, err := b.worker(serial); err != nil {
		return nil, true, nil //nolint:nilerr // a statement whose working key this box cannot sign a pass with
	}
	if held, err := ageRecipient(stem + ".agekey"); err != nil || held != p.Key {
		return nil, true, nil //nolint:nilerr // a statement for a key this box does not hold
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

// retiredGrace is how long after a renewal a drain must begin before it may
// delete prekeys: room for a send the server took as the renewal landed.
const retiredGrace = time.Hour

// renewRetry is how long Receive waits to try a failed renewal again, so a
// refused one (a rate limit, a server that is down) is not tried every poll.
const renewRetry = time.Hour

// current returns the serial of the prekey this box published last, and
// when that prekey was made.
func (b *Box) current() (uint64, time.Time, error) {
	n, err := b.publishedSerial()
	if err != nil {
		return 0, time.Time{}, err
	}
	if n == 0 {
		return 0, time.Time{}, errors.New("this box has published no prekey")
	}
	made, err := b.made(n)
	return n, made, err
}

// made returns when prekey n was made. Both clients give every prekey the
// full lifetime, so it was made at its not_after less PrekeyLifetime.
func (b *Box) made(n uint64) (time.Time, error) {
	p, err := b.prekeyStatement(n)
	if err != nil {
		return time.Time{}, err
	}
	return p.NotAfter.Add(-protocol.PrekeyLifetime), nil
}

// prekeyStatement returns prekey n's statement, as this box wrote it.
func (b *Box) prekeyStatement(n uint64) (*protocol.Prekey, error) {
	st, err := os.ReadFile(b.path("prekeys", strconv.FormatUint(n, 10)+".txt")) //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return nil, err
	}
	return protocol.ParsePrekey(st)
}

// renewIfDue publishes a new prekey, of the current type, when the current
// one is more than renewAfter old or cannot be read, or when this box's own
// list names the certificate it is using: such a box takes no mail until it
// publishes under a new one, and [Box.RenewAndRevoke] leaves it so when the
// server refused its renewal. The caller holds the lock. A failure is
// retried after renewRetry.
func (b *Box) renewIfDue(ctx context.Context) (*protocol.Prekey, error) {
	if n, made, err := b.current(); err == nil && b.now().Sub(made) <= renewAfter && !b.ownListNames(n) {
		return nil, nil
	}
	if !b.renewFailed.IsZero() && b.now().Sub(b.renewFailed) < renewRetry {
		return nil, nil
	}
	p, _, err := b.rekey(ctx, "", false)
	if err != nil {
		b.renewFailed = b.now()
		return nil, err
	}
	b.renewFailed = time.Time{}
	return p, nil
}

// dropRetired deletes every retired prekey but the newest, after a drain
// that emptied the box and began more than retiredGrace after the newest
// retired prekey was made: every older one was retired by then. A send must
// name the recipient's current prekey serial, so mail encrypted to a retired
// prekey reached the server before the renewal that retired it, or with a
// send already in progress: such a drain collected all of it. The newest
// retired prekey is kept regardless. After this, mail encrypted to a deleted
// prekey is unrecoverable from the box's keys. irongall.sh does not do this;
// it keeps every retired prekey until Prune's deletion time.
func (b *Box) dropRetired(began time.Time) error {
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
	if made, err := b.made(newest); err != nil || began.Sub(made) <= retiredGrace {
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
	for _, ext := range []string{".agekey", ".txt", ".txt.sig"} {
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

// Prune deletes every retired prekey whose deletion time has come, whatever
// else happened: its not_after plus protocol.TTL. All mail encrypted to it
// arrived by its not_after and has expired by then; after this, that mail is
// unrecoverable from the box's keys. The newest prekey is never deleted.
func (b *Box) Prune() error {
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
		if !b.now().Before(p.NotAfter.Add(protocol.TTL)) {
			if err := b.removePrekey(n); err != nil {
				return err
			}
		}
	}
	return nil
}
