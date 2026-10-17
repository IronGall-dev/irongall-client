package client

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// NoRevocationServers is the one word that, in place of a list of
// revocation servers, means none: a box then asks its own server only.
const NoRevocationServers = "none"

// revocationServerWait bounds one request of a revocation server. Its
// answer is a record of a few hundred bytes, and a box does not wait on it
// as it waits on the server its mail is on. (A variable only so that a test
// can shorten it.)
var revocationServerWait = 10 * time.Second

// serverGrammar is a server as a box's list names one: http or https, a
// host, a port if it has one, and nothing after it. Both clients hold a
// list to the same form.
var serverGrammar = regexp.MustCompile(`^https?://(\[[0-9a-f:]+\]|[a-z0-9]([a-z0-9.-]*[a-z0-9])?)(:[0-9]{1,5})?$`)

// ParseRevocationServers reads a list of revocation servers as a box's
// owner writes one, in $IRONGALL_REVOCATION_SERVERS or in the box's
// revocation-servers file: each is a server's URL, as https://host or
// https://host:port, with spaces, commas or line ends between. The one word
// NoRevocationServers is the empty list, which is not nil: the box asks its
// own server only. Text that names nothing is nil, as if it were not there.
func ParseRevocationServers(s string) ([]string, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	if len(fields) == 0 {
		return nil, nil
	}
	if len(fields) == 1 && fields[0] == NoRevocationServers {
		return []string{}, nil
	}
	list := []string{}
	for _, f := range fields {
		if !serverGrammar.MatchString(f) {
			return nil, fmt.Errorf("%.80q is not a revocation server: one is named as https://host or https://host:port, in lowercase, with nothing after it; %q alone means none", f, NoRevocationServers)
		}
		if !slices.Contains(list, f) {
			list = append(list, f)
		}
	}
	return list, nil
}

// RevocationServers returns the revocation servers this box asks beside its
// own server, and publishes to (PROTOCOL.md §6.3): what Options named;
// otherwise what the box's revocation-servers file names; otherwise none.
// The box's own server is never among them: it is asked anyway, and every
// mailbox server is a revocation server too.
//
// A lookup tells a revocation server which address its asker corresponds
// with. So none is asked unless the box's owner named it.
func (b *Box) RevocationServers() ([]string, error) {
	list := b.revocationServers
	if list == nil && b.dir != "" {
		raw, err := os.ReadFile(b.path("revocation-servers"))
		if err == nil {
			if list, err = ParseRevocationServers(string(raw)); err != nil {
				return nil, fmt.Errorf("this box's revocation-servers file: %w", err)
			}
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	var out []string
	for _, s := range list {
		if !serverGrammar.MatchString(s) {
			return nil, fmt.Errorf("%.80q is not a revocation server: one is named as https://host or https://host:port, in lowercase, with nothing after it", s)
		}
		if s != b.base && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// lookups is what one command has asked as it went: one send, one flush,
// one drain, or one question.
type lookups struct {
	// answered are the addresses this command has its answers about, of the
	// box's own server and of the revocation servers: a drain asks nothing
	// more about them, and a send reads their box at each post but asks no
	// revocation server again.
	answered map[protocol.Address]bool
	// silent are the revocation servers that gave no answer. One is not
	// asked again by the same command: a server that is down costs a
	// command one wait, however many addresses it asks about.
	silent map[string]bool
}

func newLookups() *lookups {
	return &lookups{answered: map[protocol.Address]bool{}, silent: map[string]bool{}}
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

// askRevocationServers asks each revocation server this box lists what it
// holds about a, with no pass, and keeps what verifies. It reports whether
// the box now holds a revocation of a.
//
// A revocation server can only add. A record it shows is checked and kept as
// one from any source is. That it holds none is its word, and changes
// nothing. And no answer from it changes nothing either, where no answer
// from the box's own server stops a send and a drain: mail does not wait on
// a server it does not pass through. One that gave no answer is told to
// Options.NoAnswer, and is not asked again by the same command.
func (b *Box) askRevocationServers(ctx context.Context, a protocol.Address, l *lookups) (bool, error) {
	servers, err := b.RevocationServers()
	if err != nil {
		return false, err
	}
	for _, s := range servers {
		if l.silent[s] {
			continue
		}
		var rec protocol.Revocations
		err := b.revocationServer(ctx, s, http.MethodGet, a, nil, &rec)
		switch Code(err) {
		case protocol.CodeNotRevoked, protocol.CodeNoSuchMailbox:
			continue
		}
		if err != nil {
			// The command itself was stopped: that is not the server's
			// silence.
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			l.silent[s] = true
			if b.noAnswer != nil {
				b.noAnswer(s, err)
			}
			continue
		}
		if gone, err := b.take(a, &rec); gone || err != nil {
			return gone, err
		}
	}
	return false, nil
}

// revocationServer makes one call of a revocation server about a: no pass,
// and no longer than revocationServerWait.
func (b *Box) revocationServer(ctx context.Context, server, method string, a protocol.Address, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, revocationServerWait)
	defer cancel()
	_, err := b.callAt(ctx, server, method, "/v1/"+a.String()+"/revocations", in, nil, out)
	return err
}

// ServerError is a server that did not take a record, and why.
type ServerError struct {
	Server string
	Err    error
}

// NotPublishedError is a record that not every server took: the box's own
// server, or a revocation server it lists. A record is published at each of
// them whatever the others answer, so that a server that refuses one, or is
// down, does not keep it from the rest.
type NotPublishedError struct {
	Address protocol.Address
	// Took are the servers that took the record, and Failed those that did
	// not, the box's own server first.
	Took   []string
	Failed []ServerError
}

func (e *NotPublishedError) Error() string {
	var failed []string
	for _, f := range e.Failed {
		failed = append(failed, fmt.Sprintf("%s: %v", f.Server, f.Err))
	}
	took := "no server took it"
	if len(e.Took) > 0 {
		took = "it was taken by " + strings.Join(e.Took, " and ")
	}
	return fmt.Sprintf("the record of %s was NOT taken by %s; %s. Whoever asks a server that did not take it is not shown it: publish it again, and a server that holds it answers as before", e.Address, strings.Join(failed, "; and NOT by "), took)
}

// Unwrap returns why each server did not take the record, the box's own
// server first.
func (e *NotPublishedError) Unwrap() []error {
	errs := make([]error, len(e.Failed))
	for i, f := range e.Failed {
		errs[i] = f.Err
	}
	return errs
}

// Publish publishes a record to the server opt names and to each revocation
// server it lists: a revocation of an address, a revocation of its
// certificates, or both. It needs no box and no key, only the record, so a
// box that is lost can still be revoked with a record made in advance
// ([Box.Revocation]). Each part is checked here first, and a record with a
// part that does not verify goes nowhere.
//
// Every server is tried, whatever the others answer. If one did not take the
// record the error is a [NotPublishedError], unless the box's own server is
// the only one there is, whose error is returned as it is.
func Publish(ctx context.Context, opt Options, rec *protocol.Revocations) (protocol.Address, error) {
	return newBox("", opt).Publish(ctx, rec)
}

// Publish is [Publish] as this box: to its own server and to the revocation
// servers it lists. It keeps nothing: see [Box.KeepRevocation].
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
	return a, b.publishRecord(ctx, a, rec)
}

// publishRecord sends a checked record to this box's server and to each
// revocation server it lists, all of them, and says which did not take it.
func (b *Box) publishRecord(ctx context.Context, a protocol.Address, rec *protocol.Revocations) error {
	servers, err := b.RevocationServers()
	if err != nil {
		return err
	}
	e := &NotPublishedError{Address: a}
	_, own := b.call(ctx, http.MethodPut, "/v1/"+a.String()+"/revocations", rec, nil, nil)
	if Code(own) == protocol.CodeRevoked && b.servesRevocation(ctx, a) {
		own = nil // the address is ended there already, which covers whatever the record revokes
	}
	if own != nil {
		if len(servers) == 0 {
			return own
		}
		e.Failed = append(e.Failed, ServerError{Server: b.base, Err: own})
	} else {
		e.Took = append(e.Took, b.base)
	}
	for _, s := range servers {
		err := b.revocationServer(ctx, s, http.MethodPut, a, rec, nil)
		if Code(err) == protocol.CodeRevoked && b.servesRevocationAt(ctx, s, a) {
			err = nil // as at the box's own server: the address is ended there already
		}
		if err != nil {
			e.Failed = append(e.Failed, ServerError{Server: s, Err: err})
			continue
		}
		e.Took = append(e.Took, s)
	}
	if len(e.Failed) > 0 {
		return e
	}
	return nil
}

// servesRevocation reports whether this box's server shows a revocation of
// address a that verifies. A server answers a record sent for an address it
// holds revoked with revoked, without checking the record (PROTOCOL.md
// §6.3); that answer is taken only once what it serves is checked, and
// nothing of it is kept here.
func (b *Box) servesRevocation(ctx context.Context, a protocol.Address) bool {
	_, err := b.call(ctx, http.MethodGet, "/v1/"+a.String(), nil, nil, nil)
	rec := recordOf(err)
	if rec == nil || len(rec.Revocation) == 0 {
		return false
	}
	_, err = protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	return err == nil
}

// servesRevocationAt is servesRevocation of a revocation server, by its own
// read: whether what it serves of address a is a revocation that verifies.
func (b *Box) servesRevocationAt(ctx context.Context, server string, a protocol.Address) bool {
	var rec protocol.Revocations
	if err := b.revocationServer(ctx, server, http.MethodGet, a, nil, &rec); err != nil || len(rec.Revocation) == 0 {
		return false
	}
	_, err := protocol.VerifyRevocation(a, rec.Identity, rec.Revocation)
	return err == nil
}
