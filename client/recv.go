package client

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/dromas-dev/dromas-client/protocol"
)

// hexID is a message id as the server names it: the lowercase hex SHA-256 of
// the ciphertext. An id that is not one never touches a file name.
var hexID = regexp.MustCompile(`\A[0-9a-f]{64}\z`)

// Delivery is a message that passed every check.
type Delivery struct {
	ID       string // the SHA-256 of its ciphertext, as computed here
	Envelope *protocol.Envelope
	// Line is the envelope as ONE line of JSON, built by this client from the
	// checked fields (the identity document dropped), as kept in inbox/.
	// Print or pass on this, never Plaintext, whose bytes the sender chose.
	Line []byte
	// Plaintext is the envelope's line exactly as the sender signed it, and
	// Signature the signature block that verified over it: together they
	// show anyone that this sender wrote this to this box. The client keeps
	// neither on disk.
	Plaintext []byte
	Signature []byte
	// findings is what judge established, kept should the message yet be
	// refused (bad_id).
	findings *protocol.Findings
}

// Refusal is a message that failed a check. It was kept in refused/, never
// delivered, and acked so that it leaves the server. It never blocks its
// claimed sender: a forgery may be the operator framing them.
type Refusal struct {
	ID string
	// Code says which check failed: one of this package's Refused codes or
	// protocol's. Reason says it in this client's own words, which never
	// quote the message.
	Code   string
	Reason string
	// Findings is what the checks established about it before it was
	// refused (protocol.Findings): kept with it in refused/. Where the box
	// holds a revocation of the address that signed it, or of its
	// certificate, it is the clock and the identity alone, with Signed false,
	// as for a signature that does not verify (#265).
	Findings *protocol.Findings
}

// Result is what one Receive did.
type Result struct {
	// Delivered is the mail that landed in inbox/: from a sender the box
	// allowed, or from any sender under "unknown inbox".
	Delivered []Delivery
	// Held is mail that passed every check from a sender the box has not
	// allowed, kept in held/ under "unknown held" ([Box.Allow] moves it to
	// inbox/). Blocked names mail from a sender the box blocked, dropped.
	// Both were acked.
	Held    []Delivery
	Blocked []string
	// Duplicates are re-encrypted retries of messages already delivered:
	// acked, not delivered again.
	Duplicates []string
	Refused    []Refusal
	// More reports that the drain stopped at one of its limits (see
	// maxDrainMessages), its time among them (Options.DrainTime), or because
	// the server paced it: the rest is still on the server for the next
	// Receive, which goes on from what a fetch the time cut kept.
	More bool
	// Paced is how long the server asked the box to wait before taking out
	// more, when it paced the drain (a 429 fetch_paced or refetch_spent with
	// Retry-After, on a fetch); zero otherwise.
	Paced time.Duration
	// PollAfter is the server's poll interval, in seconds: the list's
	// Retry-After.
	PollAfter int64
	// Renewed is the prekey this Receive published, the current one being
	// more than a day old; nil if none was due.
	Renewed *protocol.Prekey
	// RenewErr is why a due renewal failed. The drain went ahead, and a
	// later Receive tries again, at most hourly.
	RenewErr error
	// ACLErr is why the box's ACL was not sent where it differs from the one
	// its server last took ([Box.SyncACL]), or from one another writer put
	// there, which the renewal's read then kept as taken (checkACL). The drain
	// went ahead, and the next send or Receive sends it.
	ACLErr error
	// ACLReplaced reports that the read of the ACL the box's server holds,
	// owed since a renewal recv began was taken and made by this Receive
	// (aclAt), found an ACL other than the one this box last sent it, which
	// another machine of the box, whoever holds its pass or the server itself
	// wrote, and that the box sent its own in its place (checkACL); or that a
	// sync since the last Receive replaced an ACL a restore adopted that held
	// what no file of the box says, or one another writer put that an owed
	// read kept and could not replace then (syncACL; #366, #377).
	ACLReplaced bool
	// NotMade is a statement the box's server served in its name, at the
	// box's last read of itself, that the box did not make, or nil
	// ([NotMade]).
	NotMade *NotMade
	// listedAt is the reading the server took for the drain's first list,
	// the date of the pass the list carried, and zero until it has answered:
	// what is deleted by it is deleted by a clock a server took, and never by
	// a reading no server has seen.
	listedAt taken
}

// Again is how long the box waits before its next Receive: the server's
// poll interval, or a paced drain's wait when that is the later, since the
// next Receive begins with a list, which is a poll (PROTOCOL.md §11.11, §11.5).
// Sooner would spend the box's polls, and be refused once they are spent,
// where the poll interval lets the server's pace of new mail refill
// meanwhile (#117).
func (r *Result) Again() time.Duration {
	return max(r.Paced, time.Duration(r.PollAfter)*time.Second)
}

// Receive drains the box: every page, every message, up to the drain's
// limits, its time among them (Options.DrainTime). Each message is judged
// by one gate (see [Box.judge]); only one that passes every check lands,
// where the box's say over its sender puts it: inbox/ for a sender it
// allowed, held/ for one it has not (unless its policy lands that mail in
// inbox/ too), and nowhere for one it blocked. Refused mail goes to
// refused/. All of it is acked. A transient error stops the drain and leaves the rest for the
// next one. It holds the box's lock throughout ([Box.hold]): a second
// Receive, or any other command that writes the box, waits for it.
//
// First it renews the prekey if the current one is more than a day old, so
// a box received at least monthly never lapses. Once that renewal is taken,
// a read of the ACL its server holds is owed, and the first Receive that can
// make it makes it, renewing or not, and replaces one the box did not send
// (aclAt, checkACL). A drain that empties the box
// then deletes the retired prekeys no mail can still need (see
// [Box.dropRetired]): all but the newest. And once the server has answered
// the drain's list, so has taken a pass dated by this machine's clock, the
// prekeys whose deletion time has come by that pass's date go too.
//
// A box that holds its own revocation receives nothing.
func (b *Box) Receive(ctx context.Context) (*Result, error) {
	return locked(ctx, b, func() (*Result, error) { return b.receive(ctx) })
}

func (b *Box) receive(ctx context.Context) (*Result, error) {
	// What this command has asked as it went: the renewal's ask for the
	// box's own revocation, then the drain's about each sender.
	asked := newLookups()
	renewed, renewErr := b.renewIfDue(ctx)
	// A renewal recv began owes, once it is taken, a read of the ACL the
	// server holds, about once a day, which this Receive makes while it is
	// owed, whether or not it renewed, so one that another writer put there
	// lasts until the read after the box's next renewal at most; with none
	// owed, only a change of the box's own is sent, with no read (aclAt).
	replaced, aclErr := b.aclAt(ctx)
	// One Result for the command, which a second drain adds to: what the first
	// landed and acked is said, whatever stopped it (#332). The two drains
	// share one bound in time, and nothing else is under it.
	res := &Result{}
	drainCtx, stop := context.WithTimeoutCause(ctx, b.drainTime, errDrainTime)
	defer stop()
	err := b.drain(drainCtx, asked, res)
	// A drain refused for what a renewal mends renews, and drains again, once:
	// a server that holds no box at this address, having forgotten it, which
	// the renewal's registration brings back (PROTOCOL.md §11.7, §12.4), or one
	// that holds the certificate in use revoked, which the refusal had this
	// box read and keep (proved).
	if err != nil && renewed == nil && renewErr == nil && b.mendable(err) {
		if renewed, renewErr = b.renewNow(ctx); renewed != nil {
			var again bool
			again, aclErr = b.aclAt(ctx)
			replaced = replaced || again
			err = b.drain(drainCtx, asked, res)
			// A server that answers the drain the same after the renewal it
			// took was not mended by it: the next such renewal waits
			// renewRetry, as one that failed does, so a server that answers so
			// at every list gets one an hour, never one at every Receive
			// (#328).
			if err != nil && b.mendable(err) {
				if herr := b.holdRenewal(fmt.Errorf("it was taken, and the drain after it was refused as the one before: %w", err)); herr != nil {
					err = errors.Join(err, herr)
				}
			}
		}
	}
	// A box shown its own revocation on the way, at its renewal, its ACL or
	// its drain, takes no mail and signs nothing more, and says that alone,
	// beside what it already did (#332, #335, #378): no renewal or ACL is left
	// to try again.
	if gone := ownRevoked(err, renewErr, aclErr); gone != nil {
		res.Renewed, res.ACLReplaced = renewed, replaced
		return res, gone
	}
	// A replacement of an ACL that held what no file of the box says, which
	// a sync made since the last Receive, is reported here (#366).
	if noted, nerr := b.replacedNote(); nerr != nil && err == nil {
		err = nerr
	} else {
		replaced = replaced || noted
	}
	res.Renewed, res.RenewErr, res.ACLErr, res.ACLReplaced = renewed, renewErr, aclErr, replaced
	if nm, nerr := b.notMade(); nerr != nil && err == nil {
		err = nerr
	} else {
		res.NotMade = nm
	}
	// Deleted by this clock only once the server has taken a pass dated by
	// it, and by that pass's date: a clock far ahead is stopped at its pass,
	// and the keys that mail waits for stay (PROTOCOL.md §12.4).
	if !res.listedAt.None() {
		// Only a drain that emptied the box may delete retired prekeys
		// early; and it leaves no message a partial could be of.
		if err == nil && !res.More {
			if err = b.dropRetired(res.listedAt); err == nil {
				err = b.dropPartials()
			}
		}
		if e := b.prune(res.listedAt); err == nil {
			err = e
		}
	}
	return res, err
}

// aclAt sends the box's ACL as a Receive does: checked against what the
// server holds once a renewal a Receive began is taken, by whatever recorded
// it, this Receive or another command after a process that ended (checkACL,
// the read owed: oweACLRead), and otherwise sent only when the box's own
// changed (syncACL). The read owed goes once it is made, the server's ACL
// answered and what it showed kept (checkACL): a list that cannot be read, a
// read the server did not answer, or a fault of the box before what it
// showed is kept leave it owed, and the next Receive reads again (#377). A
// box shown its own revocation owes none: the keep drops it
// (keepRevocation).
func (b *Box) aclAt(ctx context.Context) (bool, error) {
	owed, err := b.aclReadOwed()
	if err != nil {
		return false, err
	}
	if !owed {
		return false, b.syncACL(ctx)
	}
	replaced, made, err := b.checkACL(ctx)
	if !made {
		return replaced, err
	}
	if derr := b.update(func(s store) error { return s.del(bucketIntent, "acl-read") }); derr != nil {
		return replaced, errors.Join(err, derr)
	}
	step("ACL read made")
	return replaced, err
}

// oweACLRead records, before a renewal a Receive makes, that a read of the
// ACL the box's server holds is owed once a renewal above the prekey it
// published last is taken: under "acl-read", that prekey's serial, unless a
// read is owed already, from a renewal not taken since.
func (b *Box) oweACLRead() error {
	if err := b.update(func(s store) error {
		if s.get(bucketIntent, "acl-read") != nil {
			return nil
		}
		published, err := decimal(s.get(bucketBox, "serial"), "serial")
		if err != nil {
			return err
		}
		return s.put(bucketIntent, "acl-read", strconv.AppendUint(nil, published, 10))
	}); err != nil {
		return err
	}
	step("ACL read owed")
	return nil
}

// aclReadOwed reports whether a read of the ACL the box's server holds is
// owed: a renewal a Receive began, or a later one, has been taken and
// recorded, and the read has not been made since.
func (b *Box) aclReadOwed() (owed bool, err error) {
	err = b.view(func(s store) error {
		raw := s.get(bucketIntent, "acl-read")
		if raw == nil {
			return nil
		}
		before, err := decimal(raw, "acl-read")
		if err != nil {
			return err
		}
		published, err := decimal(s.get(bucketBox, "serial"), "serial")
		owed = published > before
		return err
	})
	return owed, err
}

// mendable reports whether a drain's error is one a renewal mends: the
// server holds no box at this address, or this box holds a revocation of the
// certificate it uses.
func (b *Box) mendable(err error) bool {
	// The box's own revocation is mended by nothing: it signs nothing more
	// (#335).
	if ownRevoked(err) != nil {
		return false
	}
	if code(err) == protocol.CodeNoSuchMailbox {
		return true
	}
	n, perr := b.publishedSerial()
	return perr == nil && b.ownRevokes(n)
}

// A drain is bounded, so that a server which lists mail without end, or
// serves answers as large as it may, or as slowly as it may, costs one
// Receive a known amount of time and disk at most. A drain that reaches a
// limit stops there: what is left stays on the server for the next Receive.
var (
	maxDrainMessages = 1000     // messages handled in one drain
	maxDrainBytes    = 64 << 20 // of ciphertext fetched in one drain
	maxDrainPages    = 100      // list pages followed in one drain
)

// DefaultDrainTime is how long one Receive drains while bytes move, unless
// Options.DrainTime (recv --drain-time) says otherwise: the drain's bound in
// time, beside its others. At it a call under way is cut, and a fetch keeps
// what it read for the next Receive to go on from (partial.go), so a drain
// of large mail on a slow link completes over several (#2, #381).
const DefaultDrainTime = 15 * time.Minute

// errDrainTime is the cause of a drain's context's end at its bound in
// time: no error, the drain's limit (DefaultDrainTime). net/http gives a
// call it cut the cause as its error, so it is a deadline's too.
var errDrainTime = fmt.Errorf("the drain ran as long as one drain runs: %w", context.DeadlineExceeded)

// drain drains the box until its list ends or a limit stops it. A call that
// its bound in time cut (Options.DrainTime, the cause of ctx's end) stops
// it as its other limits do, with Result.More and no error: what it
// delivered stays delivered, and a fetch under way kept what it read.
func (b *Box) drain(ctx context.Context, asked *lookups, res *Result) error {
	err := b.drainPages(ctx, asked, res)
	if err != nil && errors.Is(context.Cause(ctx), errDrainTime) && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)) {
		res.More = true
		return nil
	}
	return err
}

func (b *Box) drainPages(ctx context.Context, asked *lookups, res *Result) error {
	// Where mail lands is read once, before anything is acked: a policy or
	// a list that cannot be read stops the drain, and the mail stays on the
	// server.
	who, err := b.readSenders()
	if err != nil {
		return err
	}
	cursor := ""
	messages, fetched := 0, 0
	// What an error names: the list's path, never a cursor, which is the
	// server's own text (PROTOCOL.md §11.3).
	listed := b.boxPath("/messages")
	for page := 0; ; page++ {
		if page == maxDrainPages {
			res.More = true
			return nil
		}
		path := listed
		if cursor != "" {
			// A cursor is URL-safe as a list hands it out: one that is not
			// makes the list no answer (protocol.CheckCursor).
			path += "?cursor=" + cursor
		}
		var hdr http.Header
		if page == 0 {
			// The tag of the last poll that found the box empty: a 304 then
			// says it is empty still (PROTOCOL.md §12.3).
			hdr, err = b.ifNoneMatch()
			if err != nil {
				return err
			}
		}
		var list protocol.MessageList
		resp, at, err := b.ownerTaken(ctx, http.MethodGet, path, hdr, nil, &list)
		if err != nil {
			// A server that says this box is revoked, or its certificate, was
			// held to what it shows (proved, in call).
			return err
		}
		if page == 0 {
			res.listedAt = at
			// Pruned by this clock only once the server has taken a pass
			// dated by it, and by that pass's date: a drain that a clock far
			// off would prune is stopped at its pass first (PROTOCOL.md §15.7,
			// §12.4).
			if err := b.pruneSeen(at); err != nil {
				return err
			}
		}
		n, err := protocol.PollInterval(resp.Header.Get("Retry-After"))
		if err != nil {
			return fmt.Errorf("GET %s: %w", listed, err)
		}
		res.PollAfter = int64(min(n, maxWaitSeconds))
		if resp.StatusCode == http.StatusNotModified {
			// A 304 carries the tag of the page it is about (RFC 9110
			// §15.4.5). One about another tag than the one sent says
			// nothing of the page that tag named (RFC 9111 §4.3.4): it is
			// no answer, and the tag goes, so the next poll asks for the
			// page in full.
			if !sameTag(resp.Header.Get("ETag"), hdr.Get("If-None-Match")) {
				if err := b.update(func(s store) error { return s.del(bucketBox, "etag") }); err != nil {
					return err
				}
				return fmt.Errorf("GET %s: a 304 about another tag than the one the poll sent", listed)
			}
			return nil
		}
		if page == 0 {
			if err := b.keepETag(&list, resp.Header.Get("ETag")); err != nil {
				return err
			}
		}
		for _, m := range list.Messages {
			if !hexID.MatchString(m.ID) {
				continue
			}
			if messages == maxDrainMessages || fetched >= maxDrainBytes || errors.Is(context.Cause(ctx), errDrainTime) {
				res.More = true
				return nil
			}
			n, err := b.receiveOne(ctx, m, res, asked, who)
			// A server that paces how much a box takes out stops the drain
			// as a drain's own limits do: what is left waits on the server.
			// Only the fetch's own answer is pacing (receiveOne): any other
			// call's refusal in the drain is an error (#116).
			var paced *pacedError
			if errors.As(err, &paced) {
				res.More, res.Paced = true, paced.wait
				return nil
			}
			if err != nil {
				return err
			}
			messages++
			fetched += n
		}
		if list.NextCursor == nil {
			return nil
		}
		cursor = *list.NextCursor
	}
}

// pacedError is the server pacing a drain, as only the answer to a fetch
// says it (PROTOCOL.md §11.12): a 429 fetch_paced or refetch_spent, with how
// long to wait.
type pacedError struct {
	wait time.Duration
	err  error
}

func (e *pacedError) Error() string { return e.err.Error() }
func (e *pacedError) Unwrap() error { return e.err }

// receiveOne judges one message of a list unless its id was already handled,
// stores the verdict, and acks it, and returns the bytes of ciphertext it
// fetched. The fetch answers the ciphertext alone, of the size the list
// gives; when it came, on the server's word, is the list's. It goes on from
// what an earlier fetch of the message kept, and keeps what it reads should
// it be cut (partial.go). An error is transient, a fetch that
// is not of that size, or a fault of this box (an unreadable key, a full
// disk): the message stays on the server for the next drain, never judged
// by a box that cannot judge it.
//
// Files are named by the SHA-256 of the ciphertext as computed here, never by
// the server's id; a message whose id is not that hash is refused. The hash
// is of the whole, what was kept and what this fetch read, so bytes a server
// splices into a range are refused as any wrong ciphertext is.
func (b *Box) receiveOne(ctx context.Context, m protocol.MessageInfo, res *Result, asked *lookups, who *senders) (fetched int, err error) {
	id := m.ID
	handled, err := b.seenHash(id)
	if err != nil {
		return 0, err
	}
	if !handled {
		p, err := b.resume(id, m.Size)
		if err != nil {
			return 0, err
		}
		ct := &ciphertext{size: m.Size, keep: p}
		_, err = b.ownerWith(ctx, http.MethodGet, b.boxPath("/messages/"+id), p.ask(), nil, ct)
		fetched = p.got()
		// A fault of this box at keeping what the fetch read is the error,
		// ahead of the fetch's own and never joined to it: a cut at the
		// drain's time is the bound reached (drain), and a fault in its chain
		// would be taken for one, with nothing kept.
		if eerr := p.end(); eerr != nil {
			return fetched, eerr
		}
		var api *APIError
		switch {
		case code(err) == protocol.CodeNoSuchMessage:
			return 0, p.drop() // already gone
		case errors.As(err, &api) && (api.Problem.Code == protocol.CodeFetchPaced || api.Problem.Code == protocol.CodeRefetchSpent) && api.RetryAfter > 0:
			return 0, &pacedError{wait: api.RetryAfter, err: err}
		case err != nil:
			return fetched, err
		}
		h := sha256.Sum256(ct.bytes)
		local := hex.EncodeToString(h[:])
		v, err := b.judge(ctx, ct.bytes, asked)
		if err != nil {
			return fetched, err
		}
		// The server's id is held to the hash whatever the verdict, a
		// duplicate's included, with what the checks found (#264).
		if v.refusal == nil && local != id {
			v = verdict{refusal: &Refusal{Code: RefusedID, Reason: "the server's id for it is not the SHA-256 of its ciphertext", Findings: v.found}, found: v.found}
		}
		d, why := v.delivery, v.refusal
		switch {
		case why != nil:
			// The message as served, with none of the server's strings in
			// the clear but those of their form (keptRefusal), and beside it
			// why it was refused, in this client's words, and what the checks
			// established about it.
			if err := b.keepRefused(local, &m, ct.bytes, why); err != nil {
				return fetched, err
			}
			why.ID = local
			res.Refused = append(res.Refused, *why)
		case v.dup:
			res.Duplicates = append(res.Duplicates, local)
		default:
			// Stored before it is recorded as seen, and both, on disk,
			// before the ack: a crash or power loss in between delivers it
			// again, never loses it. Mail from a blocked sender is recorded
			// as seen too, so that a retry of it is a duplicate.
			d.ID = local
			where := who.land(d.Envelope.From)
			switch where {
			case landInbox:
				err = writeFile(b.path("inbox", local+".json"), d.Line)
			case landHeld:
				err = writeFile(b.path("held", local+".json"), d.Line)
			}
			if err != nil {
				return fetched, err
			}
			step("delivery written")
			// A message refused once, whose ack was lost, and delivered
			// now, keeps nothing in refused/ (#211): its file goes first,
			// then what the box's state keeps of it, with the line.
			if err := removeIfExists(b.path("refused", local+".json")); err != nil {
				return fetched, err
			}
			if err := b.update(func(s store) error {
				if err := recordSeen(s, ct.bytes, d.Envelope); err != nil {
					return err
				}
				return s.del(bucketRefused, local)
			}); err != nil {
				return fetched, err
			}
			step("delivery seen")
			switch where {
			case landInbox:
				res.Delivered = append(res.Delivered, *d)
			case landHeld:
				res.Held = append(res.Held, *d)
			default:
				res.Blocked = append(res.Blocked, local)
			}
		}
		// Judged, and the verdict on disk: what was kept of it goes.
		if err := p.drop(); err != nil {
			return fetched, err
		}
	}
	_, err = b.owner(ctx, http.MethodDelete, b.boxPath("/messages/"+id), nil, nil)
	if code(err) == protocol.CodeNoSuchMessage {
		return fetched, nil
	}
	return fetched, err
}

// verdict is what judge found of one message: delivered, a duplicate of one
// delivered before, or refused, and in each case what its checks
// established (found).
type verdict struct {
	delivery *Delivery
	dup      bool
	refusal  *Refusal
	found    *protocol.Findings
}

// judge runs every check on one message, its ciphertext alone, in this
// order, and returns the delivery only if all of them pass; otherwise why
// says which failed, in a code and in this client's own words. An error is
// this box's own fault, not the message's: no verdict.
//
//  1. Decryption with every retained prekey, of a file with exactly one
//     native recipient stanza, counted before anything is decrypted
//     (decrypt, oneNative).
//  2. What came out is an envelope line and then a signature block.
//  3. The envelope is one JSON object, as protocol.Unmarshal reads one.
//  4. The line carries the sender's identity document, and its from is that
//     document's hash.
//  5. The signature over the line as decrypted, in this box's message
//     namespace, by a working key that identity certified.
//  6. The rest of the envelope: version 1, to is this box, msg_id in its
//     form, and sent_at no older than protocol.TTL (33 days), not before the
//     floor the seen-set was pruned at (seenFloor), and at most
//     protocol.MaxSkew ahead.
//  7. Revocation: this box holds no revocation of the sender. The server is
//     asked for one, once for each sender in a drain. A revocation that
//     verifies refuses the message and every later one, whenever they were
//     signed. A server that says it holds none has answered. No answer is an
//     error: the message stays on the server for the next drain. The same
//     answer carries the sender's revocation of its certificates, if it has
//     one: mail signed under a revoked certificate is refused the same way,
//     and the address goes on.
//  8. Replay: the locally computed ciphertext hash is not in the seen-set.
//  9. Retry: (from, msg_id) is not in the seen-set. A match is a duplicate.
//
// The numbers are PROTOCOL.md §12.3's. protocol.Examine makes checks 2 to 6,
// all but the floor, which is this box's own and judge's. Who the sender is,
// is never asked of the server, nor read from its list: the message carries
// what proves it. The one thing asked is whether a revocation of that sender
// exists, and the answer proves itself. The sender's identity is pinned only
// once all of that has passed.
func (b *Box) judge(ctx context.Context, ct []byte, asked *lookups) (verdict, error) {
	now := b.now()
	found := &protocol.Findings{At: now}
	refused := func(code, reason string) (verdict, error) {
		// A refusal says who signed it only where this box holds no
		// revocation of that address or of that certificate, read from what
		// it holds, with no ask: an identity that revoked the key disowned
		// what it signs, and the record names it as the identity it claims,
		// as for a signature that does not verify (#265).
		if found.Signed && found.Identity != nil {
			held, err := b.held(*found.Identity)
			if err != nil {
				return verdict{}, fmt.Errorf("a fault of this box, so the message stays on the server: %w", err)
			}
			if held.Revoked || held.Certificates != nil && held.Certificates.Revokes(found.Serial) {
				*found = protocol.Findings{At: found.At, Identity: found.Identity}
			}
		}
		return verdict{refusal: &Refusal{Code: code, Reason: reason, Findings: found}, found: found}, nil
	}
	ids, err := b.prekeyIdentities()
	if err != nil {
		return verdict{}, err
	}
	r, err := decrypt(ct, ids)
	switch {
	case errors.Is(err, errNoNative):
		return refused(RefusedDecrypt, "it is encrypted to no recipient of a prekey's type, which no server takes as a send: nothing was decrypted")
	case errors.Is(err, errNotOneNative):
		return refused(RefusedDecrypt, "it is not encrypted to exactly one recipient of a prekey's type, as every server takes a send: nothing was decrypted")
	case err != nil:
		return refused(RefusedDecrypt, "it does not decrypt with this box's prekeys")
	}
	p, err := io.ReadAll(io.LimitReader(r, protocol.MaxCiphertext)) // less than its ciphertext, which is at most that
	if err != nil {
		return refused(RefusedDecrypt, "it does not decrypt with this box's prekeys")
	}
	signed, found, err := protocol.Examine(p, b.id.Address(), now)
	if err != nil {
		var e *protocol.EnvelopeError
		if errors.As(err, &e) {
			return refused(e.Code, e.Why)
		}
		return verdict{}, err
	}
	from, env := signed.Sender.Address(), signed.Envelope
	// Freshness has a floor too: a sent_at before the highest cutoff the
	// seen-set was pruned at may be a message whose line went, and so may one
	// up to protocol.TTL above it, a retry of such a message, dated afresh up
	// to a TTL after its first copy (check 9 knows a retry by that copy's
	// line).
	floor, err := b.seenFloor()
	if err != nil {
		return verdict{}, err
	}
	if floor > 0 && env.SentAt.Unix() < floor+int64(protocol.TTL/time.Second) {
		return refused(protocol.RefusedStale, "sent_at is before this box's replay set reaches back to, since its clock once read later than it does now")
	}
	gone, err := b.revoked(from)
	if err != nil {
		return verdict{}, fmt.Errorf("a fault of this box, so the message stays on the server: %w", err)
	}
	if !gone && !asked.answered[from] {
		if gone, err = b.lookupRevocation(ctx, from, asked); err != nil {
			return verdict{}, fmt.Errorf("whether its sender is revoked could not be asked, so the message stays on the server: %w", err)
		}
	}
	if gone {
		return refused(RefusedRevoked, "its sender's address is revoked, and the revocation verifies: nothing signed for that address is taken, whenever it was signed")
	}
	certs, err := b.revokedCerts(from)
	if err != nil {
		return verdict{}, err
	}
	if certs != nil && certs.Revokes(signed.Certificate.Serial()) {
		return refused(RefusedCertificate, "it is signed under a certificate its sender's identity has revoked: nothing signed under it is taken, whenever it was signed")
	}
	h := sha256.Sum256(ct)
	seen, err := b.seenHash(hex.EncodeToString(h[:]))
	if err != nil {
		return verdict{}, err
	}
	if seen {
		return refused(RefusedReplay, "replay: this ciphertext was already received")
	}
	if err := b.pin(signed.Sender); err != nil {
		return verdict{}, err
	}
	again, err := b.seenMsgID(from, env.MsgID)
	if err != nil {
		return verdict{}, err
	}
	if again {
		return verdict{dup: true, found: found}, nil
	}
	line, err := keptLineOf(env)
	if err != nil {
		return verdict{}, err
	}
	return verdict{delivery: &Delivery{Envelope: env, Line: line, Plaintext: signed.Line, Signature: signed.Signature, findings: found}, found: found}, nil
}

// keptLineOf is the line inbox/ and held/ keep of a delivered envelope, and
// recv prints: the envelope without its identity document, what nobody sees
// escaped (escapeUnseen). keptLine takes a kept file only when it is this
// line, byte for byte.
func keptLineOf(env *protocol.Envelope) ([]byte, error) {
	shown := *env
	shown.Identity = nil
	line, err := shown.Marshal()
	if err != nil {
		return nil, err
	}
	return escapeUnseen(line), nil
}

// escapeUnseen escapes, in a line a reader is shown or a box keeps, the
// characters a reader cannot see or that some readers end a line at, with
// the same value. A body can carry them raw inside a JSON string, the only
// place JSON allows them. The line breaks other than LF are U+0085, U+2028
// and U+2029 (Python's str.splitlines, Node's readline). The ones nobody sees
// are Unicode's Default_Ignorable_Code_Point (DerivedCoreProperties, Unicode
// 18.0): tag characters, BiDi controls and marks, zero-width characters,
// variation selectors. A model reads each of these as text, and a person sees
// none, so a body could carry an instruction past whoever looks. Escaped, it
// is in plain sight, and a JSON reader still gets every character
// (PRECEDENTS.md, Part 2). dromas.sh's dr_line escapes the same list.
func escapeUnseen(line []byte) []byte {
	var b strings.Builder
	for _, r := range string(line) {
		if !escaped(r) {
			b.WriteRune(r)
			continue
		}
		if r > 0xFFFF {
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, hi, lo)
		} else {
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return []byte(b.String())
}

// escaped reports whether escapeUnseen escapes r.
func escaped(r rune) bool {
	if r == 0x85 || r == 0x2028 || r == 0x2029 {
		return true
	}
	for _, x := range defaultIgnorable {
		if r >= x[0] && r <= x[1] {
			return true
		}
	}
	return false
}

// defaultIgnorable is Unicode 18.0's Default_Ignorable_Code_Point, range for
// range (DerivedCoreProperties-18.0.0.txt). dromas.sh's dr_line holds the
// same list.
var defaultIgnorable = [][2]rune{
	{0x00AD, 0x00AD}, {0x034F, 0x034F}, {0x061C, 0x061C}, {0x115F, 0x1160}, {0x17B4, 0x17B5},
	{0x180B, 0x180F}, {0x200B, 0x200F}, {0x202A, 0x202E}, {0x2060, 0x206F}, {0x3164, 0x3164},
	{0xFE00, 0xFE0F}, {0xFEFF, 0xFEFF}, {0xFFA0, 0xFFA0}, {0xFFF0, 0xFFF8}, {0x1BCA0, 0x1BCA3},
	{0x1D173, 0x1D17A}, {0xE0000, 0xE0FFF},
}

// The replay set: each accepted message, by the hash of its ciphertext, with
// its sent_at, its sender and its msg_id, kept until sent_at +
// protocol.SeenFor, so the replay check covers the window the freshness check
// takes a message in, and the floor (seenFloor) covers a clock that steps
// back further. Two indexes beside it, in the same transactions: by sender
// and msg_id, which a retry is known by, and by sent_at, which a prune walks
// (#11).

// seenTimeKey is a line's key in seen-time: its sent_at, eight bytes
// big-endian, so the keys' order is the times', then its hash.
func seenTimeKey(sentAt int64, h string) string {
	return string(binary.BigEndian.AppendUint64(nil, uint64(max(sentAt, 0)))) + h
}

func (b *Box) seenHash(h string) (seen bool, err error) {
	err = b.view(func(s store) error { seen = s.get(bucketSeen, h) != nil; return nil })
	return seen, err
}

func (b *Box) seenMsgID(from protocol.Address, msgID string) (seen bool, err error) {
	err = b.view(func(s store) error { seen = s.get(bucketSeenSender, from.String()+" "+msgID) != nil; return nil })
	return seen, err
}

// recordSeen adds a delivered message to the replay set and its indexes.
func recordSeen(s store, ciphertext []byte, env *protocol.Envelope) error {
	sum := sha256.Sum256(ciphertext)
	h := hex.EncodeToString(sum[:])
	if err := s.put(bucketSeen, h, fmt.Appendf(nil, "%d %s %s", env.SentAt.Unix(), env.From, env.MsgID)); err != nil {
		return err
	}
	if err := s.put(bucketSeenSender, env.From.String()+" "+env.MsgID, []byte(h)); err != nil {
		return err
	}
	return s.put(bucketSeenTime, seenTimeKey(env.SentAt.Unix(), h), nil)
}

// pruneSeen drops the lines past protocol.SeenFor by the reading at, one a
// server took. When it drops one, the floor rises to the cutoff in the same
// transaction, so a clock that later reads further back than SeenFor allows
// for still takes no message whose line went (seenFloor).
func (b *Box) pruneSeen(at taken) error {
	cutoff := at.At().Add(-protocol.SeenFor).Unix()
	return b.update(func(s store) error {
		var old [][]byte
		if err := s.each(bucketSeenTime, func(k, _ []byte) error {
			if len(k) < 8 || int64(binary.BigEndian.Uint64(k)) >= cutoff { //nolint:gosec // a time in seconds, kept from an int64
				return errDone
			}
			old = append(old, k)
			return nil
		}); err != nil && !errors.Is(err, errDone) {
			return err
		}
		if len(old) == 0 {
			return nil
		}
		if err := b.raiseFloor(s, cutoff); err != nil {
			return err
		}
		for _, k := range old {
			h := string(k[8:])
			line := strings.Fields(string(s.get(bucketSeen, h)))
			if len(line) == 3 {
				if err := s.del(bucketSeenSender, line[1]+" "+line[2]); err != nil {
					return err
				}
			}
			if err := s.del(bucketSeen, h); err != nil {
				return err
			}
			if err := s.del(bucketSeenTime, string(k)); err != nil {
				return err
			}
		}
		return nil
	})
}

// errDone stops a walk of a bucket where it has found what it walked for.
var errDone = errors.New("done")

// seenFloor is the highest cutoff a prune of the replay set has dropped a
// line at, or 0 when it has dropped none: a message whose sent_at is before
// it, or less than protocol.TTL above it, is stale whatever the clock now
// reads, since its line, or its first copy's, may be gone. It is how a
// Kerberos server that has lost its replay cache refuses until the window
// has passed (RFC 4120 §3.2.3).
func (b *Box) seenFloor() (floor int64, err error) {
	err = b.view(func(s store) error {
		n, err := decimal(s.get(bucketBox, "seen-floor"), "seen-floor")
		floor = int64(min(n, uint64(math.MaxInt64))) //nolint:gosec // bounded above
		return err
	})
	return floor, err
}

// raiseFloor sets the floor to t, unless it is already that high.
func (b *Box) raiseFloor(s store, t int64) error {
	floor, err := b.seenFloor()
	if err != nil || floor >= t {
		return err
	}
	return s.put(bucketBox, "seen-floor", strconv.AppendInt(nil, t, 10))
}

// entityTag is an ETag as a box keeps one: an entity-tag of RFC 9110 §8.8.3,
// weak or strong, in printable ASCII, and short. A server's tag of any other
// form is not sent back.
var entityTag = regexp.MustCompile(`\A(W/)?"[\x21\x23-\x7e]{0,128}"\z`)

// sameTag reports whether two tags, each in the form a box keeps, are the
// same by the weak comparison (RFC 9110 §8.8.3.2): a proxy on the way may
// mark a tag weak.
func sameTag(a, b string) bool {
	return entityTag.MatchString(a) && entityTag.MatchString(b) && strings.TrimPrefix(a, "W/") == strings.TrimPrefix(b, "W/")
}

// ifNoneMatch is the header a poll sends: If-None-Match with the tag the box
// keeps, or none when it keeps none, or one of another form.
func (b *Box) ifNoneMatch() (http.Header, error) {
	var t []byte
	if err := b.view(func(s store) error { t = s.get(bucketBox, "etag"); return nil }); err != nil {
		return nil, err
	}
	if !entityTag.Match(t) {
		return nil, nil
	}
	return http.Header{"If-None-Match": {string(t)}}, nil
}

// keepETag keeps the tag of a first page that found the box empty, so the
// next poll can be answered 304, and drops any once a page holds mail: a 304
// then says only that the box is still empty, and never hides mail
// (PROTOCOL.md §12.3).
func (b *Box) keepETag(list *protocol.MessageList, tag string) error {
	return b.update(func(s store) error {
		if list.Count == 0 && len(list.Messages) == 0 && entityTag.MatchString(tag) {
			return s.put(bucketBox, "etag", []byte(tag))
		}
		return s.del(bucketBox, "etag")
	})
}
