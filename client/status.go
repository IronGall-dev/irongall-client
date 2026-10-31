package client

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/dromas-dev/dromas-client/client/internal/sign"
	"github.com/dromas-dev/dromas-client/protocol"
)

// Status is what a mailbox can say of itself from its own files, with no call to
// the server: what a wrapper reads to learn that the mailbox needs a look.
type Status struct {
	Address protocol.Address `json:"address"`
	// Mode is the mailbox's mode (PROTOCOL.md §5): "identity", where its
	// identity signs what it says, or "working_key", where a working key under
	// a certificate does, read from the revocation of its certificates it
	// keeps.
	Mode string `json:"mode"`
	// Format is the mailbox's format (client/doc.go), this client's: a
	// mailbox in another is refused, never read ([FormatError]).
	Format int `json:"format"`
	// Paths is where the mailbox keeps each of its files and directories, as
	// this run found the mailbox, by name: "mailbox", its directory, then
	// each in it (paths).
	Paths map[string]string `json:"paths"`
	// PrekeySerial and PrekeyNotAfter are the prekey this mailbox published
	// last: zero and empty if it holds none.
	PrekeySerial   uint64 `json:"prekey_serial"`
	PrekeyNotAfter string `json:"prekey_not_after"`
	// PrekeyMade is when that prekey was signed, by the record its client
	// kept: empty if there is none, and the next recv renews it.
	PrekeyMade string `json:"prekey_made,omitempty"`
	// PrekeyLifetime is how long each new prekey is valid for, in seconds:
	// the mailbox's prekey-lifetime file, or 33 days. Zero if the file names no
	// lifetime, and the mailbox then renews no prekey until it is put right.
	PrekeyLifetime int64 `json:"prekey_lifetime"`
	// CertificateSerial and CertificateNotAfter are, in working-key mode,
	// the certificate of the working key in use, the one made with that
	// prekey: zero and empty, and not written, if the mailbox holds none it can
	// sign with, and in identity mode, where its identity signs.
	CertificateSerial   uint64 `json:"certificate_serial,omitempty"`
	CertificateNotAfter string `json:"certificate_not_after,omitempty"`
	// RenewalPendingSince is when this mailbox signed the oldest new prekey it
	// still holds and has not seen published: empty if every renewal went
	// through.
	RenewalPendingSince string `json:"renewal_pending_since,omitempty"`
	Inbox               int    `json:"inbox"`
	Sent                int    `json:"sent"`
	Outbox              int    `json:"outbox"`
	OutboxFailed        int    `json:"outbox_failed"`
	Refused             int    `json:"refused"`
	// Held counts the messages held/ keeps from senders this mailbox has not allowed.
	Held int `json:"held"`
	// Policy is what the mailbox's policy file says, or the default.
	Policy Policy `json:"policy"`
	// Revoked is true when the mailbox holds a revocation of its own address
	// that verifies: the address is finished.
	Revoked bool `json:"revoked,omitempty"`
	// PrekeyNotMade is a statement the mailbox's server served in its name, at
	// its last read of itself, that it did not make, or nil ([NotMade]).
	PrekeyNotMade *NotMade `json:"prekey_not_made,omitempty"`
	// Attention says, in words, each thing that needs a look. It is empty
	// when nothing does.
	Attention []string `json:"attention"`
}

// paths are the files and directories of a mailbox its owner reads, writes or
// backs up, by the name Status gives each, and their paths in its directory.
var paths = []struct{ name, path string }{
	{"mailbox", ""}, {"identity", "identity"}, {"state", "state"},
	{"work", "work"}, {"prekeys", "prekeys"}, {"prekey_lifetime", "prekey-lifetime"},
	{"inbox", "inbox"}, {"held", "held"}, {"refused", "refused"}, {"outbox", "outbox"}, {"sent", "sent"},
	{"aliases", "aliases"}, {"allowed", "allowed"}, {"blocked", "blocked"}, {"policy", "policy"},
}

// Status reads the mailbox's own files and its state, read-only: it waits while a
// command writes the mailbox, and changes nothing.
func (b *Mailbox) Status(ctx context.Context) (*Status, error) {
	return reading(ctx, b, b.status)
}

func (b *Mailbox) status() (*Status, error) {
	s := &Status{Address: b.id.Address(), Format: b.format, Paths: map[string]string{}, Attention: []string{}}
	for _, p := range paths {
		abs, err := filepath.Abs(b.path(p.path))
		if err != nil {
			return nil, err
		}
		s.Paths[p.name] = abs
	}
	// A revoked mailbox is finished, and that comes before anything else it holds.
	if gone, err := b.revoked(b.id.Address()); err != nil {
		return nil, err
	} else if gone {
		s.Revoked = true
		s.Attention = append(s.Attention, "this mailbox's address is revoked, for good, and the revocation verifies: it sends and receives nothing more. Make a new mailbox and give its address to those who wrote to this one")
	}
	m, merr := b.mode()
	s.Mode = modeName(m)
	if merr != nil {
		s.Attention = append(s.Attention, merr.Error())
	}
	var switching bool
	if err := b.view(func(st store) error { switching = st.get(bucketIntent, "switch") != nil; return nil }); err != nil {
		return nil, err
	}
	if switching {
		s.Attention = append(s.Attention, "a move to working-key mode is under way: dromas cert switch, with this mailbox's address in full, finishes it")
	}
	var err error
	if s.Policy, err = b.policy(); err != nil {
		s.Attention = append(s.Attention, fmt.Sprintf("the mailbox's policy cannot be read, so it neither sends nor receives until that is put right: %v", err))
	}
	switch pending, perr := b.aclPending(); {
	case err != nil: // said above
	case perr != nil:
		s.Attention = append(s.Attention, fmt.Sprintf("whom this mailbox allows or blocks cannot be read, so it neither sends nor receives until that is put right: %v", perr))
	case pending:
		why, err := b.aclWhy()
		if err != nil {
			return nil, err
		}
		s.Attention = append(s.Attention, why+": the next send, recv, allow or block sends this mailbox's own")
	}
	for dir, n := range map[string]*int{"inbox/*.json": &s.Inbox, "sent/*.json": &s.Sent, "outbox/*.P": &s.Outbox, "outbox/failed/*.P": &s.OutboxFailed, "refused/*.json": &s.Refused, "held/*.json": &s.Held} {
		names, err := filepath.Glob(b.path(filepath.FromSlash(dir)))
		if err != nil {
			return nil, err
		}
		*n = len(names)
	}
	if d, err := b.prekeyLifetime(); err != nil {
		s.Attention = append(s.Attention, fmt.Sprintf("the mailbox's prekey lifetime cannot be read, so it renews no prekey until that is put right (dromas prekey lifetime sets it): %v", err))
	} else {
		s.PrekeyLifetime = int64(d / time.Second)
	}
	serial, err := b.current()
	cur, perr := b.prekeyStatement(serial)
	switch {
	case err != nil || perr != nil:
		s.Attention = append(s.Attention, "this mailbox holds no prekey it published: dromas prekey renew publishes one, and senders are refused until then")
	default:
		s.PrekeySerial, s.PrekeyNotAfter = serial, cur.NotAfter.UTC().Format(protocol.TimeLayout)
		if made, err := b.made(serial); err == nil {
			s.PrekeyMade = made.Format(protocol.TimeLayout)
		}
		if cur.Expired(b.now()) {
			s.Attention = append(s.Attention, fmt.Sprintf("the prekey expired at %s: senders are refused until dromas recv or dromas prekey renew renews it", s.PrekeyNotAfter))
		}
	}
	switch _, cert, werr := b.currentSigner(); {
	case werr != nil && (err != nil || perr != nil || s.Revoked || merr != nil):
	case errors.Is(werr, sign.ErrNotIdentityMode):
		s.Attention = append(s.Attention, werr.Error())
	case werr != nil && m == sign.WorkingKeyMode:
		s.Attention = append(s.Attention, "this mailbox holds no working key it can sign with, or its certificate has ended: it cannot poll or send until dromas prekey renew makes new ones")
	case werr != nil:
		s.Attention = append(s.Attention, fmt.Sprintf("this mailbox cannot sign: %v", werr))
	case cert != nil:
		s.CertificateSerial, s.CertificateNotAfter = cert.Serial(), cert.NotAfter().Format(protocol.TimeLayout)
		if !cert.SignsMessages(b.now()) {
			s.Attention = append(s.Attention, fmt.Sprintf("the certificate ends at %s, too soon to sign messages: sends are refused until dromas recv or dromas prekey renew renews it", s.CertificateNotAfter))
		}
	}
	// A statement signed for a serial above the published one is a renewal
	// the server did not take, or whose answer never arrived.
	signed, err := b.prekeys()
	if err != nil {
		return nil, err
	}
	first := uint64(0)
	for _, n := range signed {
		if n > serial {
			first = n
			break
		}
	}
	if first != 0 {
		since := "an unknown time"
		if made, err := b.made(first); err == nil {
			since = made.Format(protocol.TimeLayout)
			s.RenewalPendingSince = since
		}
		s.Attention = append(s.Attention, fmt.Sprintf("a new prekey signed at %s was never seen published: the server refused it or did not answer; dromas recv sends it again", since))
	}
	if s.PrekeyNotMade, err = b.notMade(); err != nil {
		return nil, err
	}
	if s.PrekeyNotMade != nil {
		s.Attention = append(s.Attention, s.PrekeyNotMade.Words())
	}
	if s.Refused > 0 {
		s.Attention = append(s.Attention, fmt.Sprintf("%d refused in refused/ (%s): each failed a check and was never delivered; dromas refused list says which, and dromas refused rm deletes them", s.Refused, b.refusedCodes()))
	}
	if s.Held > 0 {
		s.Attention = append(s.Attention, fmt.Sprintf("%d held in held/ from senders this mailbox has not allowed: dromas held list lists them by sender; dromas peer allow <address> delivers a sender's to inbox/, and dromas peer block <address> deletes them", s.Held))
	}
	s.Attention = append(s.Attention, b.versionsAttention()...)
	if s.Outbox > 0 {
		s.Attention = append(s.Attention, fmt.Sprintf("%d in outbox/ not delivered yet: dromas outbox flush sends them again", s.Outbox))
	}
	if s.OutboxFailed > 0 {
		s.Attention = append(s.Attention, fmt.Sprintf("%d in outbox/failed/ can never be delivered: delete a file to drop it", s.OutboxFailed))
	}
	return s, nil
}

// refusedCodes lists the distinct codes of the messages in refused/, from
// what the mailbox's state keeps of each: a message it keeps no code for counts
// as "unknown".
func (b *Mailbox) refusedCodes() string {
	qs, _ := b.refusedMessages()
	var codes []string
	for _, q := range qs {
		if !slices.Contains(codes, q.Code) {
			codes = append(codes, q.Code)
		}
	}
	slices.Sort(codes)
	return strings.Join(codes, ", ")
}
