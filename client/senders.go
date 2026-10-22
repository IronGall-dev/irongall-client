package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// A box says who may write to it (PROTOCOL.md §5.0, §6.2): the senders it
// allows, whose mail lands in inbox/; the senders it blocks, whose mail it
// drops; and, in its policy, where the rest's mail lands and whether its
// server refuses them. Mail lands by a verified sender only, after every
// check of judge: a sender the box has not allowed is held, never refused,
// since it proved who it is. Its server holds the box's ACL, which the box
// makes from the same files and sends whenever they change, so that the
// server refuses what the box would drop.

// The values of a box's policy.
const (
	// LandHeld and LandInbox are where mail from a sender the box has not
	// allowed lands: held/ (the default), or inbox/ as any other.
	LandHeld  = "held"
	LandInbox = "inbox"
	// AdmitAll and AdmitAllowed are whom the box's server takes mail from:
	// every sender the box has not blocked (the default), or only those it
	// has allowed.
	AdmitAll     = "all"
	AdmitAllowed = "allowed"
)

// Policy is what a box's policy file says. A box with none, or a line left
// out, has the default.
type Policy struct {
	// Unknown is where mail from a sender the box has not allowed lands:
	// LandHeld or LandInbox.
	Unknown string `json:"unknown"`
	// Server is whom the box's server takes mail from: AdmitAll or
	// AdmitAllowed.
	Server string `json:"server"`
}

// DefaultPolicy is the policy of a box whose policy file says nothing: mail
// from a sender the box has not allowed is held, and the server refuses
// only senders the box has blocked.
func DefaultPolicy() Policy { return Policy{Unknown: LandHeld, Server: AdmitAll} }

func (p Policy) check() error {
	if (p.Unknown != LandHeld && p.Unknown != LandInbox) || (p.Server != AdmitAll && p.Server != AdmitAllowed) {
		return errors.New(`a policy is "unknown held" or "unknown inbox", and "server all" or "server allowed"`)
	}
	return nil
}

// Policy reads the box's policy file: "<setting> <value>" lines, "unknown
// held" or "unknown inbox", and "server all" or "server allowed", each at
// most once, with blank lines and lines starting with "#" skipped. A file
// with any other line is an error, never a default: a policy that cannot be
// read stops what depends on it until it is put right.
func (b *Box) Policy() (Policy, error) {
	p := DefaultPolicy()
	data, err := os.ReadFile(b.path("policy"))
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	seen := map[string]bool{}
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) == 2 && seen[f[0]] {
			return p, refuse("%s, line %d: %s is set twice", b.path("policy"), i+1, f[0])
		}
		switch {
		case len(f) == 2 && f[0] == "unknown" && (f[1] == LandHeld || f[1] == LandInbox):
			p.Unknown = f[1]
		case len(f) == 2 && f[0] == "server" && (f[1] == AdmitAll || f[1] == AdmitAllowed):
			p.Server = f[1]
		default:
			return p, refuse(`%s, line %d: not "unknown held", "unknown inbox", "server all" or "server allowed"`, b.path("policy"), i+1)
		}
		seen[f[0]] = true
	}
	return p, nil
}

// SetPolicy writes the box's policy file. The server learns what it changes
// at the box's next send, recv, allow or block ([Box.SyncACL]).
func (b *Box) SetPolicy(ctx context.Context, p Policy) error {
	if err := p.check(); err != nil {
		return err
	}
	return b.lockedFinishedDo(ctx, func() error { return writeFile(b.path("policy"), p.file()) })
}

// file is the policy file that says p.
func (p Policy) file() []byte { return []byte("unknown " + p.Unknown + "\nserver " + p.Server + "\n") }

// addresses reads one of the box's address lists, allowed or blocked: an
// address to a line, with blank lines and lines starting with "#" skipped,
// as the policy file's are and OpenSSH's list files' (#181). Any other line
// is an error, a "#" after an address on its line among them.
func (b *Box) addresses(name string) ([]protocol.Address, error) {
	data, err := os.ReadFile(b.path(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []protocol.Address
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		a, err := protocol.ParseAddress(line)
		if err != nil {
			return nil, refuse("%s, line %d: not an address (64 lowercase hex characters)", b.path(name), i+1)
		}
		out = append(out, a)
	}
	return out, nil
}

// addTo adds an address to one of the box's address lists, unless it is
// there, and reports whether it added it: a line after what the file holds,
// the whole file written beside it and moved into place (writeFile), so a
// crash leaves the list as it was or with the line, never a line cut short,
// which would stop every drain and send until it was put right.
func (b *Box) addTo(name string, a protocol.Address) (bool, error) {
	n, err := b.addAll(name, []protocol.Address{a})
	return n == 1, err
}

// addAll is addTo of each address in addrs, in one write, and returns how
// many it added.
func (b *Box) addAll(name string, addrs []protocol.Address) (int, error) {
	have, err := b.addresses(name)
	if err != nil {
		return 0, err
	}
	var lines []byte
	n := 0
	for _, a := range addrs {
		if slices.Contains(have, a) {
			continue
		}
		have = append(have, a)
		lines = append(lines, a.String()+"\n"...)
		n++
	}
	if n == 0 {
		return 0, nil
	}
	data, err := os.ReadFile(b.path(name))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n') // a line someone wrote without its end
	}
	return n, writeFile(b.path(name), append(data, lines...))
}

// Allowed returns the senders whose mail lands in inbox/ whatever the
// policy says: those the allowed file lists and those an alias names.
func (b *Box) Allowed() ([]protocol.Address, error) {
	allowed, err := b.addresses("allowed")
	if err != nil {
		return nil, err
	}
	as, err := b.Aliases()
	if err != nil {
		return nil, err
	}
	for _, a := range as {
		allowed = append(allowed, a.Address)
	}
	return protocol.NewACLList(false, allowed).Addrs, nil
}

// Blocked returns the senders whose mail this box drops, and its server
// refuses.
func (b *Box) Blocked() ([]protocol.Address, error) {
	blocked, err := b.addresses("blocked")
	if err != nil {
		return nil, err
	}
	return protocol.NewACLList(false, blocked).Addrs, nil
}

// Where mail from a verified sender lands.
const (
	landInbox = iota
	landHeld
	landBlocked
)

// senders is what a drain reads once of the box's say over its senders.
type senders struct {
	policy           Policy
	allowed, blocked protocol.ACLList
}

func (b *Box) readSenders() (*senders, error) {
	p, err := b.Policy()
	if err != nil {
		return nil, err
	}
	allowed, err := b.Allowed()
	if err != nil {
		return nil, err
	}
	blocked, err := b.Blocked()
	if err != nil {
		return nil, err
	}
	return &senders{policy: p, allowed: protocol.ACLList{Addrs: allowed}, blocked: protocol.ACLList{Addrs: blocked}}, nil
}

// land says where mail from a verified sender lands: dropped if the box
// blocked it, which wins over allowing it; inbox/ if the box allowed it or
// its policy lands every sender's there; otherwise held/.
func (s *senders) land(from protocol.Address) int {
	switch {
	case s.blocked.Has(from):
		return landBlocked
	case s.allowed.Has(from) || s.policy.Unknown == LandInbox:
		return landInbox
	}
	return landHeld
}

// HeldSender is the mail held/ keeps from one sender.
type HeldSender struct {
	From protocol.Address `json:"from"`
	// IDs name its messages in held/, oldest first by sent_at: held/<id>.json
	// is the line recv would have printed.
	IDs         []string `json:"ids"`
	FirstSentAt string   `json:"first_sent_at"`
	LastSentAt  string   `json:"last_sent_at"`
}

// heldMessage is a line this client kept in held/, read back.
type heldMessage struct {
	ID     string
	From   protocol.Address
	SentAt string
	Env    *protocol.Envelope
	Line   []byte
	kept   time.Time // when the drain wrote it: the order it arrived in, among messages sent in one second
}

// heldMail reads held/: each message this client kept there, oldest first by
// sent_at, and in the order they were kept within a second. A file that is
// not one of this client's lines ([Box.keptLine]) is skipped.
func (b *Box) heldMail() ([]heldMessage, error) {
	names, err := filepath.Glob(b.path("held", "*.json"))
	if err != nil {
		return nil, err
	}
	var out []heldMessage
	for _, n := range names {
		id := strings.TrimSuffix(filepath.Base(n), ".json")
		if !hexID.MatchString(id) {
			continue
		}
		data, err := os.ReadFile(n) //nolint:gosec // a file of this box's held/
		if err != nil {
			return nil, err
		}
		fi, err := os.Stat(n)
		if err != nil {
			return nil, err
		}
		line, from, env, ok := b.keptLine(data)
		if !ok {
			continue
		}
		out = append(out, heldMessage{ID: id, From: from, SentAt: env.SentAt.UTC().Format(protocol.TimeLayout), Env: env, Line: line, kept: fi.ModTime()})
	}
	slices.SortStableFunc(out, func(x, y heldMessage) int {
		if c := strings.Compare(x.SentAt, y.SentAt); c != 0 {
			return c
		}
		return x.kept.Compare(y.kept)
	})
	return out, nil
}

// HeldMail returns the mail held/ keeps, by sender, the sender with the oldest
// first. It reads only held/, and calls no server.
func (b *Box) HeldMail() ([]HeldSender, error) {
	ms, err := b.heldMail()
	if err != nil {
		return nil, err
	}
	var out []HeldSender
	at := map[protocol.Address]int{}
	for _, m := range ms {
		i, ok := at[m.From]
		if !ok {
			i = len(out)
			at[m.From] = i
			out = append(out, HeldSender{From: m.From, FirstSentAt: m.SentAt})
		}
		out[i].IDs = append(out[i].IDs, m.ID)
		out[i].LastSentAt = m.SentAt
	}
	return out, nil
}

// Allow allows a sender: its mail lands in inbox/ from now on, whatever the
// policy says, and what held/ keeps from it moves there. A sender the box
// blocks is refused, with nothing done: blocking wins. The moved messages
// are returned as Receive delivers them, oldest first, but for Plaintext and
// Signature, which the box never kept. Then the server is
// sent the box's ACL, if the change is one it holds ([Box.SyncACL]): an
// error from that leaves the sender allowed here.
func (b *Box) Allow(ctx context.Context, a protocol.Address) ([]Delivery, error) {
	return locked(ctx, b, func() ([]Delivery, error) {
		moved, err := b.allow(a)
		if err != nil {
			return moved, err
		}
		return moved, b.syncACL(ctx)
	})
}

func (b *Box) allow(a protocol.Address) ([]Delivery, error) {
	// Blocking wins: allowing a sender the box blocks would move its mail to
	// inbox/ while its later mail is dropped, so nothing is done (#179).
	blocked, err := b.Blocked()
	if err != nil {
		return nil, err
	}
	if slices.Contains(blocked, a) {
		return nil, refuse("%s is blocked, and blocking wins, so nothing is allowed or moved: delete its line in %s first", a, b.path("blocked"))
	}
	if _, err := b.addTo("allowed", a); err != nil {
		return nil, err
	}
	ms, err := b.heldMail()
	if err != nil {
		return nil, err
	}
	var moved []Delivery
	for _, m := range ms {
		if m.From != a {
			continue
		}
		if err := os.Rename(b.path("held", m.ID+".json"), b.path("inbox", m.ID+".json")); err != nil {
			return moved, err
		}
		moved = append(moved, Delivery{ID: m.ID, Envelope: m.Env, Line: m.Line})
	}
	if len(moved) == 0 {
		return nil, nil
	}
	if err := syncDir(b.path("inbox")); err != nil {
		return moved, err
	}
	return moved, syncDir(b.path("held"))
}

// Block blocks a sender: its mail is dropped from now on, and its server
// refuses it, which deletes what the server holds from it; what held/ keeps
// from it is deleted. It returns how many held messages it deleted. Blocking
// wins over allowing. An error sending the server the box's ACL leaves the
// sender blocked here, and the next send, recv, allow or block sends it.
func (b *Box) Block(ctx context.Context, a protocol.Address) (int, error) {
	return locked(ctx, b, func() (int, error) {
		n, err := b.block(a)
		if err != nil {
			return n, err
		}
		return n, b.syncACL(ctx)
	})
}

func (b *Box) block(a protocol.Address) (int, error) {
	if _, err := b.addTo("blocked", a); err != nil {
		return 0, err
	}
	ms, err := b.heldMail()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, m := range ms {
		if m.From != a {
			continue
		}
		if err := removeIfExists(b.path("held", m.ID+".json")); err != nil {
			return n, err
		}
		n++
	}
	if n == 0 {
		return 0, nil
	}
	return n, syncDir(b.path("held"))
}

// RebuildAllowed adds back to the allowed file every address the box has
// an alias for or has sent mail to, as sent/ names them, and returns how
// many it added. What the file lists stays. It is for a box whose allowed
// file was lost: send, alias and allow keep it otherwise.
func (b *Box) RebuildAllowed(ctx context.Context) (int, error) {
	return lockedFinished(ctx, b, b.rebuildAllowed)
}

func (b *Box) rebuildAllowed() (int, error) {
	as, err := b.Aliases()
	if err != nil {
		return 0, err
	}
	var addrs []protocol.Address
	for _, a := range as {
		addrs = append(addrs, a.Address)
	}
	sent, err := filepath.Glob(b.path("sent", "*.json"))
	if err != nil {
		return 0, err
	}
	for _, n := range sent {
		to, _, _ := strings.Cut(filepath.Base(n), ".")
		if a, err := protocol.ParseAddress(to); err == nil {
			addrs = append(addrs, a)
		}
	}
	added := 0
	for _, a := range protocol.NewACLList(false, addrs).Addrs {
		ok, err := b.addTo("allowed", a)
		if err != nil {
			return added, err
		}
		if ok {
			added++
		}
	}
	return added, nil
}

// wantACL is the ACL the box's files say its server should hold: it denies
// the senders the box blocked, and allows every other sender, or under
// "server allowed" only those the box allowed.
func (b *Box) wantACL() (*protocol.ACL, error) {
	s, err := b.readSenders()
	if err != nil {
		return nil, err
	}
	acl := &protocol.ACL{Allow: protocol.ACLList{Any: true}, Deny: s.blocked}
	if s.policy.Server == AdmitAllowed {
		acl.Allow = s.allowed
	}
	return acl, nil
}

// tookACL is the ACL the box's server last took, as it answered, which the
// box keeps; nil if it has taken none.
func (b *Box) tookACL() (*protocol.ACL, error) {
	var data []byte
	if err := b.view(func(s store) error { data = s.get(bucketBox, "acl"); return nil }); err != nil || data == nil {
		return nil, err
	}
	var d protocol.ACLDocument
	if err := protocol.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("the ACL the box's state file keeps: %w", err)
	}
	acl, err := protocol.CheckACL(&d, 0)
	if err != nil {
		return nil, fmt.Errorf("the ACL the box's state file keeps: %w", err)
	}
	return acl, nil
}

// ACLPending reports whether the box's files say an ACL other than the one
// its server last took: the next send, recv, allow or block sends it.
func (b *Box) ACLPending(ctx context.Context) (bool, error) {
	return reading(ctx, b, b.aclPending)
}

// aclPending is ACLPending inside a command or a reading.
func (b *Box) aclPending() (bool, error) {
	want, err := b.wantACL()
	if err != nil {
		return false, err
	}
	took, err := b.tookACL()
	if err != nil {
		return false, err
	}
	return !want.SameLists(took), nil
}

// SyncACL sends the box's server the ACL the box's files say, unless that
// is the one it took last, which is the case for a box that has blocked
// nobody and lets every sender reach the server: such a box sends none, and
// its server holds none. Each one sent replaces whatever the server holds,
// whoever wrote it, and carries no If-Match (PROTOCOL.md §6.2): the box's
// files are what its ACL is, so what another machine of the box sent is
// replaced, not merged, and a precondition would only add a read and a 412
// to end the same way. One the server answers box_changed (the box changed
// while it handled the request) is sent again as it is, once. The server's
// answer must be the ACL sent, and is kept in acl.json. It reads nothing of
// the server first, so it does not see an ACL another writer put there since:
// [Box.Receive] reads that at each renewal (checkACL).
func (b *Box) SyncACL(ctx context.Context) error {
	return b.lockedDo(ctx, func() error { return b.syncACL(ctx) })
}

func (b *Box) syncACL(ctx context.Context) error {
	// A restore that has yet to adopt its server's ACL adopts it before
	// anything is compared or sent.
	if _, err := b.adoptPending(ctx); err != nil {
		return err
	}
	want, err := b.wantACL()
	if err != nil {
		return err
	}
	took, err := b.tookACL()
	if err != nil {
		return err
	}
	if want.SameLists(took) {
		return nil
	}
	return b.sendACL(ctx, want)
}

// checkACL is syncACL with the ACL the box's server holds read first, as
// Receive does after each renewal it makes, about once a day: another
// writer may have put one since this box last sent its own, another machine
// of the box, whoever holds its pass (PROTOCOL.md §6.1b) or the server
// itself, and syncACL,
// which compares the box's files with what it last sent, would never see
// it. It reads GET …/acl and compares the lists with those the box's files
// make, never a tag, whose making is the server's own; where they differ it
// sends the box's own, as syncACL does, with no If-Match. It reports whether
// the server held an ACL other than the one this box last sent, which this
// box has now replaced with its own. A read that fails is no answer: the box
// sends what syncACL would, and the next renewal reads again. The read is the
// one call it adds, to a renewal and to nothing else.
func (b *Box) checkACL(ctx context.Context) (bool, error) {
	// A restore that has yet to adopt its server's ACL adopts it first, and
	// compares with what it read.
	held, err := b.adoptPending(ctx)
	if err != nil {
		return false, err
	}
	want, err := b.wantACL()
	if err != nil {
		return false, err
	}
	took, err := b.tookACL()
	if err != nil {
		return false, err
	}
	if held == nil {
		if held, err = b.heldACL(ctx); err != nil {
			return false, b.syncACL(ctx)
		}
	}
	switch {
	case !want.SameLists(held):
		if err := b.sendACL(ctx, want); err != nil {
			return false, err
		}
		return !held.SameLists(took), nil
	case !want.SameLists(took):
		// The server already holds what the box's files say: it is kept as
		// taken, and nothing is sent.
		return false, b.keepTook(held)
	}
	return false, nil
}

// heldACL reads the ACL the box's server holds: one allowing everyone and
// denying nothing for a box that has put none.
func (b *Box) heldACL(ctx context.Context) (*protocol.ACL, error) {
	var d protocol.ACLDocument
	if _, err := b.owner(ctx, http.MethodGet, b.boxPath("/acl"), nil, &d); err != nil {
		return nil, err
	}
	return protocol.CheckACL(&d, 0)
}

// sendACL sends the box's ACL, want, and keeps the server's answer as the
// ACL it took: once more after a box_changed, as it is.
func (b *Box) sendACL(ctx context.Context, want *protocol.ACL) error {
	got, err := b.putACL(ctx, want)
	if code(err) == protocol.CodeBoxChanged {
		got, err = b.putACL(ctx, want)
	}
	if err != nil {
		return fmt.Errorf("the server did not take this box's ACL: %w", err)
	}
	return b.keepTook(got)
}

// keepTook keeps acl as the ACL the box's server last took.
func (b *Box) keepTook(acl *protocol.ACL) error {
	data, err := json.Marshal(acl.Document())
	if err != nil {
		return err
	}
	return b.update(func(s store) error { return s.put(bucketBox, "acl", data) })
}

// A box restored from its identity alone has none of its owner's lists:
// they went with the lost machine. The open ACL its empty files make would
// replace, at its first renewal (checkACL), whatever its server holds, every
// block in it. So a restore adopts the ACL its server holds, and the heal
// applies from then on (#366).
//
// A renewal of a box that has published nothing, and that has none of its
// allowed, blocked and policy files, marks the adoption as begun before it
// signs anything (beginAdoption, in readOwn). Once a renewal is taken, which
// gives the box a pass, the box reads GET …/acl and writes its lists from it
// (adoptPending): Init's restore and Rekey do at once, and syncACL and
// checkACL do first while the mark stands, so no ACL is compared or sent
// before it. A box restored with any of those files, as the README says to
// back them up, adopts nothing: its files are its ACL, as ever.
//
// What a hostile server gains by lying there, once: an allow entry it adds
// lands that sender's mail in inbox/ and not in held/, once its signature
// verifies; a deny entry it adds, or an allow list that puts the box under
// "server allowed", has mail dropped or refused that the server could drop
// anyway. Each stays in the box's files until its owner edits them. It
// forges no sender.

// beginAdoption marks the adoption of its server's ACL as begun, on a box
// that has published nothing and has none of its owner's lists.
func (b *Box) beginAdoption() error {
	published, err := b.publishedSerial()
	if err != nil || published > 0 {
		return err
	}
	for _, name := range []string{"allowed", "blocked", "policy"} {
		if _, err := os.Lstat(b.path(name)); !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return b.update(func(s store) error { return s.put(bucketIntent, "adopt-acl", []byte("begun")) })
}

// adoptPending adopts the ACL the box's server holds, when a restore marked
// the adoption as begun: it reads GET …/acl and adds its entries to the
// box's lists, a deny's to blocked and an allow list's to allowed, and with
// an allow list the policy "server allowed", unless the box has a policy
// file. Then, in one transaction, the ACL read is kept as the one the server
// last took, and the mark goes. Run again after a crash, it adds nothing
// twice. What no file of the box says, a deny of AnyAddress or addresses
// beside an allow of AnyAddress, is not adopted: the box's next ACL replaces
// it, as the heal does. It returns the ACL it read, or nil when no adoption
// was pending.
func (b *Box) adoptPending(ctx context.Context) (*protocol.ACL, error) {
	var pending bool
	if err := b.view(func(s store) error { pending = s.get(bucketIntent, "adopt-acl") != nil; return nil }); err != nil || !pending {
		return nil, err
	}
	held, err := b.heldACL(ctx)
	if err != nil {
		return nil, fmt.Errorf("this box was restored from its identity alone, and the ACL its server holds, whose lists it takes as its own, could not be read: the next recv, send, allow or block reads it again before it sends any: %w", err)
	}
	if _, err := b.addAll("blocked", held.Deny.Addrs); err != nil {
		return nil, err
	}
	if !held.Allow.Any {
		if _, err := b.addAll("allowed", held.Allow.Addrs); err != nil {
			return nil, err
		}
		if _, err := os.Lstat(b.path("policy")); errors.Is(err, fs.ErrNotExist) {
			if err := writeFile(b.path("policy"), Policy{Unknown: LandHeld, Server: AdmitAllowed}.file()); err != nil {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		}
	}
	step("lists adopted")
	data, err := json.Marshal(held.Document())
	if err != nil {
		return nil, err
	}
	if err := b.update(func(s store) error {
		if err := s.put(bucketBox, "acl", data); err != nil {
			return err
		}
		return s.del(bucketIntent, "adopt-acl")
	}); err != nil {
		return nil, err
	}
	step("adoption recorded")
	return held, nil
}

// putACL sends an ACL, and returns the server's answer, which must be that
// ACL.
func (b *Box) putACL(ctx context.Context, acl *protocol.ACL) (*protocol.ACL, error) {
	var d protocol.ACLDocument
	if _, err := b.owner(ctx, http.MethodPut, b.boxPath("/acl"), acl.Document(), &d); err != nil {
		return nil, err
	}
	got, err := protocol.CheckACL(&d, 0)
	if err != nil || !got.SameLists(acl) {
		return nil, errors.New("the server answered with another ACL than the one sent")
	}
	return got, nil
}
