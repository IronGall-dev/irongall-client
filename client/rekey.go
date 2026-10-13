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

// Rekey publishes a NEW prekey at the next serial, of type kt, or of the
// current prekey's type if kt is empty, signed by a NEW working key under a
// new certificate. If an earlier Rekey signed one and the server did not
// take it, that one is sent again, unchanged, until it expires: a key is
// signed once, so no key is encrypted to for more than 33 days whatever the
// server does with what it was sent. It needs only the identity, so it also
// recovers a box that lost its prekeys or its working key. The upload carries
// a pass under the new certificate, and the server then takes no pass under
// an older one.
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
	p, err := b.rekey(ctx, kt)
	if e := l.release(); err == nil {
		err = e
	}
	return p, err
}

// rekeyLockWait is how long Rekey waits for the box's lock.
var rekeyLockWait = time.Minute

func (b *Box) rekey(ctx context.Context, kt protocol.KeyType) (*protocol.Prekey, error) {
	var ir protocol.IdentityResponse
	if _, err := b.call(ctx, http.MethodGet, b.boxPath("/identity"), nil, nil, &ir); err != nil {
		return nil, err
	}
	// Its own record, so judged as one: whether this identity ever certified
	// the key that signed it, even if that certificate has since ended.
	cur, _, err := protocol.VerifyPrekeyRecord(b.id, ir.Prekey, ir.PrekeySignature)
	if err != nil {
		return nil, refuse("this box's current prekey, as served: %v", err)
	}
	published, err := b.publishedSerial()
	if err != nil {
		return nil, err
	}
	if cur.Serial < published {
		return nil, refuse("rollback: the server serves this box's prekey serial %d, below %d, which this box published", cur.Serial, published)
	}
	if kt == "" {
		kt = cur.Type()
	}
	// A serial is signed once. A statement an earlier attempt signed, and
	// never saw published, is sent again exactly as it is: signed again, its
	// not_after counted from now, it would hand a server that fails every
	// renewal and keeps what it was sent the same key for 33 more days at
	// each retry, without end. Once such a statement can no longer be sent
	// (it expired, or a key of another type is wanted), the next serial is
	// signed: its key stays, as a retired one, for mail it may yet decrypt.
	// Nothing at or below the highest serial this box signed is signed anew,
	// and that one's files are never pruned, so a serial is never used twice.
	next := cur.Serial + 1
	signed, err := b.highestSigned()
	if err != nil {
		return nil, err
	}
	next = max(next, signed)
	p, spent, err := b.signedPrekey(next, kt)
	if err != nil {
		return nil, err
	}
	if spent {
		next++
	}
	if p == nil {
		if p, err = b.makePrekey(next, kt); err != nil {
			return nil, err
		}
	}
	stem := b.path("prekeys", strconv.FormatUint(next, 10))
	req := protocol.PrekeyRequest{SenderKeyTypes: b.senderKeyTypes}
	if req.Prekey, err = os.ReadFile(stem + ".txt"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, err
	}
	if req.PrekeySignature, err = os.ReadFile(stem + ".txt.sig"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, err
	}
	if err := b.publish(ctx, http.MethodPut, b.boxPath("/prekey"), req, next); err != nil {
		return nil, err
	}
	return p, b.Prune()
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

// highestSigned returns the highest serial this box holds a signed statement
// for, or 0.
func (b *Box) highestSigned() (uint64, error) {
	names, err := filepath.Glob(b.path("prekeys", "*.txt.sig"))
	if err != nil {
		return 0, err
	}
	var top uint64
	for _, name := range names {
		if n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(name), ".txt.sig"), 10, 64); err == nil && exists(name) {
			top = max(top, n)
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
// when that prekey was made. A box that has never renewed has published
// only serial 1.
func (b *Box) current() (uint64, time.Time, error) {
	n, err := b.publishedSerial()
	if err != nil {
		return 0, time.Time{}, err
	}
	n = max(n, 1)
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
// one is more than renewAfter old or cannot be read. The caller holds the
// lock. A failure is retried after renewRetry.
func (b *Box) renewIfDue(ctx context.Context) (*protocol.Prekey, error) {
	if _, made, err := b.current(); err == nil && b.now().Sub(made) <= renewAfter {
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
