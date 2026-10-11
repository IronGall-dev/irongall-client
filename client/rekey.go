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

	"github.com/drewstreib/crossbot-client/protocol"
)

// Rekey publishes a NEW prekey at the next serial, of type kt, or of the
// current prekey's type if kt is empty. It needs no token, only the identity,
// so it also recovers a box that lost its prekeys or its token. The new token
// it returns, encrypted to the new prekey, replaces the old one, which dies.
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
	cur, err := protocol.VerifyPrekey(b.id, ir.Prekey, ir.PrekeySignature)
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
	next := cur.Serial + 1
	stem := b.path("prekeys", strconv.FormatUint(next, 10))
	// A statement left by an attempt that never published is remade, so its
	// not_after is counted from now. Its key, if any, is reused when it is of
	// type kt: it was never published, as next is above every serial this
	// box published.
	for _, ext := range []string{".txt", ".txt.sig"} {
		if err := removeIfExists(stem + ext); err != nil {
			return nil, err
		}
	}
	p, err := b.makePrekey(next, kt)
	if err != nil {
		return nil, err
	}
	req := protocol.PrekeyRequest{Prekey: p.Statement()}
	if req.PrekeySignature, err = os.ReadFile(stem + ".txt.sig"); err != nil { //nolint:gosec // a path inside the box's own directory
		return nil, err
	}
	var tr protocol.TokenResponse
	if _, err := b.call(ctx, http.MethodPut, b.boxPath("/prekey"), req, nil, &tr); err != nil {
		return nil, err
	}
	if err := b.recordPublished(next); err != nil {
		return nil, err
	}
	if err := b.storeToken(tr.Token); err != nil {
		return nil, err
	}
	return p, b.Prune()
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
// full lifetime, so it was made at its not_after less MaxPrekeyLifetime.
func (b *Box) made(n uint64) (time.Time, error) {
	st, err := os.ReadFile(b.path("prekeys", strconv.FormatUint(n, 10)+".txt")) //nolint:gosec // a path inside the box's own directory
	if err != nil {
		return time.Time{}, err
	}
	p, err := protocol.ParsePrekey(st)
	if err != nil {
		return time.Time{}, err
	}
	return p.NotAfter.Add(-protocol.MaxPrekeyLifetime), nil
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
// prekey is unrecoverable from the box's keys. crossbot.sh does not do this;
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

// removePrekey deletes a prekey's key and its statement.
func (b *Box) removePrekey(n uint64) error {
	stem := b.path("prekeys", strconv.FormatUint(n, 10))
	for _, ext := range []string{".agekey", ".txt", ".txt.sig"} {
		if err := removeIfExists(stem + ext); err != nil {
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
