package client

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Status is what a box can say of itself from its own files, with no call to
// the server: what a wrapper reads to learn that the box needs a look.
type Status struct {
	Address protocol.Address `json:"address"`
	// PrekeySerial and PrekeyNotAfter are the prekey this box published
	// last: zero and empty if it holds none.
	PrekeySerial   uint64 `json:"prekey_serial"`
	PrekeyNotAfter string `json:"prekey_not_after"`
	// CertificateSerial and CertificateNotAfter are the certificate of the
	// working key in use, the one made with that prekey: zero and empty if
	// the box holds none it can sign with.
	CertificateSerial   uint64 `json:"certificate_serial"`
	CertificateNotAfter string `json:"certificate_not_after"`
	// RenewalPendingSince is when this box signed the oldest new prekey it
	// still holds and has not seen published: empty if every renewal went
	// through.
	RenewalPendingSince string `json:"renewal_pending_since,omitempty"`
	Inbox               int    `json:"inbox"`
	Sent                int    `json:"sent"`
	Outbox              int    `json:"outbox"`
	OutboxFailed        int    `json:"outbox_failed"`
	Quarantine          int    `json:"quarantine"`
	// Revoked is true when the box holds a revocation of its own address
	// that verifies: the address is finished.
	Revoked bool `json:"revoked,omitempty"`
	// Attention says, in words, each thing that needs a look. It is empty
	// when nothing does.
	Attention []string `json:"attention"`
}

// Status reads the box's own files. It takes no lock and changes nothing.
func (b *Box) Status() (*Status, error) {
	s := &Status{Address: b.id.Address(), Attention: []string{}}
	// A revoked box is finished, and that comes before anything else it holds.
	if gone, err := b.revoked(b.id.Address()); err != nil {
		return nil, err
	} else if gone {
		s.Revoked = true
		s.Attention = append(s.Attention, "this box's address is revoked, for good, and the revocation verifies: it sends and receives nothing more. Make a new box and give its address to those who wrote to this one")
	}
	for dir, n := range map[string]*int{"inbox/*.json": &s.Inbox, "sent/*.json": &s.Sent, "outbox/*.P": &s.Outbox, "outbox/failed/*.P": &s.OutboxFailed, "quarantine/*.json": &s.Quarantine} {
		names, err := filepath.Glob(b.path(filepath.FromSlash(dir)))
		if err != nil {
			return nil, err
		}
		*n = len(names)
	}
	serial, _, err := b.current()
	cur, perr := b.prekeyStatement(serial)
	switch {
	case err != nil || perr != nil:
		s.Attention = append(s.Attention, "this box holds no prekey it published: irongall rekey publishes one, and senders are refused until then")
	default:
		s.PrekeySerial, s.PrekeyNotAfter = serial, cur.NotAfter.UTC().Format(protocol.TimeLayout)
		if cur.Expired(b.now()) {
			s.Attention = append(s.Attention, fmt.Sprintf("the prekey expired at %s: senders are refused until irongall recv or irongall rekey renews it", s.PrekeyNotAfter))
		}
	}
	if _, cert, werr := b.currentWorker(); werr != nil {
		if err == nil && perr == nil {
			s.Attention = append(s.Attention, "this box holds no working key it can sign with, or its certificate has ended: it cannot poll or send until irongall rekey makes new ones")
		}
	} else {
		s.CertificateSerial, s.CertificateNotAfter = cert.Serial(), cert.NotAfter().Format(protocol.TimeLayout)
		if !cert.SignsMail(b.now()) {
			s.Attention = append(s.Attention, fmt.Sprintf("the certificate ends at %s, too soon to sign mail: sends are refused until irongall recv or irongall rekey renews it", s.CertificateNotAfter))
		}
	}
	// A statement signed for a serial above the published one is a renewal
	// the server did not take, or whose answer never arrived.
	signed, err := filepath.Glob(b.path("prekeys", "*.txt.sig"))
	if err != nil {
		return nil, err
	}
	first := uint64(0)
	for _, name := range signed {
		n, err := strconv.ParseUint(strings.TrimSuffix(filepath.Base(name), ".txt.sig"), 10, 64)
		if err == nil && n > serial && (first == 0 || n < first) {
			first = n
		}
	}
	if first != 0 {
		since := "an unknown time"
		if p, err := b.prekeyStatement(first); err == nil {
			since = p.NotAfter.Add(-protocol.PrekeyLifetime).UTC().Format(protocol.TimeLayout)
			s.RenewalPendingSince = since
		}
		s.Attention = append(s.Attention, fmt.Sprintf("a new prekey signed at %s was never seen published: the server refused it or did not answer; irongall recv sends it again", since))
	}
	if s.Quarantine > 0 {
		s.Attention = append(s.Attention, fmt.Sprintf("%d refused in quarantine/ (%s): each failed a check and was never delivered; its .reason file says which, and both files are yours to delete once looked at", s.Quarantine, b.quarantineCodes()))
	}
	if s.Outbox > 0 {
		s.Attention = append(s.Attention, fmt.Sprintf("%d in outbox/ not delivered yet: irongall flush sends them again", s.Outbox))
	}
	if s.OutboxFailed > 0 {
		s.Attention = append(s.Attention, fmt.Sprintf("%d in outbox/failed/ can never be delivered: delete a file to drop it", s.OutboxFailed))
	}
	return s, nil
}

// quarantineCodes lists the distinct codes of the mail in quarantine/, from
// the .reason files this client wrote. A file that does not start with a
// code counts as "unknown": nothing else is taken from it.
func (b *Box) quarantineCodes() string {
	names, _ := filepath.Glob(b.path("quarantine", "*.json"))
	var codes []string
	for _, name := range names {
		code := "unknown"
		if data, err := os.ReadFile(strings.TrimSuffix(name, ".json") + ".reason"); err == nil { //nolint:gosec // a path inside the box's own directory
			if c, _, ok := strings.Cut(string(data), ":"); ok && codeGrammar.MatchString(c) {
				code = c
			}
		}
		if !slices.Contains(codes, code) {
			codes = append(codes, code)
		}
	}
	slices.Sort(codes)
	return strings.Join(codes, ", ")
}
