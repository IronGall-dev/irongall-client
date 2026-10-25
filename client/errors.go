package client

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/dromas-dev/dromas-client/protocol"
)

// RefusedError is a check that failed. The operation stopped there: nothing
// was encrypted, sent, delivered or recorded past the failed check.
type RefusedError struct {
	// Code is the refusal's code, for a check that has one of its own:
	// RefusedPrekeyType. Otherwise it is empty.
	Code   string
	Reason string
}

func (e *RefusedError) Error() string { return "REFUSED: " + e.Reason }

func refuse(format string, args ...any) error {
	return &RefusedError{Reason: fmt.Sprintf(format, args...)}
}

// lookupError is a read of a box that served nothing to seal to: no answer,
// no such box, or "revoked" with nothing that verifies ([Box.resolve]).
// Whatever code it carries, it is no answer about a message, which waits in
// the outbox ([Box.post]).
type lookupError struct{ err error }

func (e *lookupError) Error() string { return e.err.Error() }
func (e *lookupError) Unwrap() error { return e.err }

// Why a message was refused, as codes: with protocol's (bad_message,
// bad_envelope, bad_identity, bad_signature, reattributed, stale), a closed
// set; and why a send refused its recipient's prekey statement when nothing is
// wrong with it (RefusedPrekeyType). A refusal's words are this client's own
// and never quote the message, its claimed sender's text or the server's:
// whoever reads a refusal may be a model.
const (
	RefusedDecrypt    = "undecryptable"           // not encrypted to a prekey this box holds, or not to exactly one recipient of a prekey's type
	RefusedReplay     = "replay"                  // this ciphertext was already received
	RefusedID         = "bad_id"                  // the server's id for it is not the SHA-256 of its ciphertext
	RefusedPrekeyType = "unsupported_prekey_type" // the recipient's prekey is an age recipient of a type this client cannot encrypt to
)

// APIError is a non-2xx answer from the server. Problem is the RFC 9457 body
// when the server sent one with a code this client knows, for the status the
// code has, beside the type that is the code's own (PROTOCOL.md §11.3);
// otherwise its code is empty.
type APIError struct {
	Status  int
	Problem protocol.Problem
	// RetryAfter is the server's Retry-After, or zero.
	RetryAfter time.Duration
	// Dated is the time in the answer's Date header, and Read this box's
	// clock when the answer came: both zero unless the call carried a pass
	// and the answer a Date. They are set side by side in the error for a
	// pass or a statement refused for its time, and never adopted: a box
	// checks everything against its own clock, and a server may lie about
	// the time as about anything else.
	Dated, Read time.Time
}

// Error is the status and the code, then what the code means, in this
// client's own words, with the values the error carries once each is checked
// to its type. Nothing the server wrote is in it: its detail, hint and title
// are for a person reading the body, and whoever reads this may be a model
// (PROTOCOL.md §11.3). A code this client does not know is not printed at all,
// since any text can be made to fit a code's grammar.
func (e *APIError) Error() string {
	c := e.Problem.Code
	s := fmt.Sprintf("ERROR %d: an answer this client does not know", e.Status)
	switch {
	case c.Known():
		s = fmt.Sprintf("ERROR %d %s: %s", e.Status, c, e.words())
	case e.Status >= 300 && e.Status <= 399:
		s = fmt.Sprintf("ERROR %d: a redirect, which this client never follows: the API answers where it is called", e.Status)
	}
	if n := int(e.RetryAfter / time.Second); n == 1 {
		s += "; the server asks to wait 1 second"
	} else if n > 1 {
		s += fmt.Sprintf("; the server asks to wait %d seconds", n)
	}
	return s + e.clock()
}

// words says what e's code means, and what to do about it.
func (e *APIError) words() string {
	p := &e.Problem
	switch p.Code {
	case protocol.CodeBadRequest:
		return "the server could not read the request: a bug in this client, or a server that reads the protocol otherwise"
	case protocol.CodeBadAddress:
		return "the server does not take that as an address, which is 64 lowercase hex characters"
	case protocol.CodeBadEncoding:
		return "the server read a byte field as not base64 in its one encoding: a bug in this client, or in the server"
	case protocol.CodeIdentityMismatch:
		return "the server finds that the identity document does not hash to the address, or is not in its one form"
	case protocol.CodeBadKey:
		return "the server refused a key, certificate or prekey statement this box sent, as malformed or not verifying: dromas prekey renew signs a new statement, and a box that cannot register needs a new identity (dromas init)"
	case protocol.CodePrekeyNotNew:
		return "the server has seen that prekey before, and every prekey is a new key: dromas prekey renew makes one"
	case protocol.CodePrekeyTime:
		return "the server finds the prekey statement, or the certificate it is under, not valid at its clock"
	case protocol.CodeUnsupportedKeyType:
		s := "the server does not register identities of this box's key type"
		if t := knownTypes(p.KeyTypes); t != "" {
			s += "; it registers " + t
		}
		return s + ". dromas init makes an ssh-ed25519 identity unless told otherwise"
	case protocol.CodeNotAge:
		return "the server does not read the ciphertext as an age file: a bug in this client, or in the server"
	case protocol.CodeWrongRecipientType:
		return "the server finds the ciphertext not encrypted to one recipient of the type of the box's prekey: a post-quantum box needs age 1.3 or later"
	case protocol.CodeBadRevocation:
		return "the server does not take that record as a revocation its address's own identity signed"
	case protocol.CodeUnauthorized:
		return "the server refused this box's pass, and a new one: check that the server's URL names the box's own server"
	case protocol.CodePassExpired:
		return "the server refused this box's pass, and a new one, as not valid at its clock"
	case protocol.CodeCertificateNotCurrent:
		s := "the server takes this box's pass under another certificate than the one it signs under"
		if p.CertificateSerial != nil {
			s += fmt.Sprintf(", serial %d", *p.CertificateSerial)
		}
		return s + ", as after a restore or a renewal on another machine, and the one this box signs under may be revoked too: dromas prekey renew certifies a new working key above it"
	case protocol.CodeCertificateRevoked:
		return "the server holds the certificate this box signs under as one its identity revoked: dromas prekey renew certifies a new working key above it"
	case protocol.CodeUnknownSender:
		return "the server does not know this box: it is not registered there, or was forgotten there (dromas init registers a box, and dromas prekey renew registers one again)"
	case protocol.CodeSenderRevoked:
		return "the server answers that this box is revoked: this client takes that only from a revocation that verifies"
	case protocol.CodeSenderNotAllowed:
		return "the recipient's ACL does not let this box write to it: only the recipient can change that"
	case protocol.CodeSenderKeyType:
		return "the recipient's client does not verify identities of this box's key type: a box with an ssh-ed25519 identity can write to any box"
	case protocol.CodeAdoptKeyRefused:
		return "the server refused the adopt key as spent, expired, revoked or not its own: ask the account for a new one"
	case protocol.CodeNoSuchMailbox:
		return "the server holds no box at that address: never registered, or forgotten"
	case protocol.CodeNoSuchMessage:
		return "the server holds no message with that id: acked or expired"
	case protocol.CodeNotRevoked:
		return "the server holds no revocation of that address"
	case protocol.CodeConflict:
		s := "the server holds a newer version of what was sent, or another"
		switch {
		case p.Through != nil:
			s += fmt.Sprintf(": a revocation of certificates through serial %d", *p.Through)
		case p.PrekeySerial != nil:
			s += fmt.Sprintf(": prekey serial %d", *p.PrekeySerial)
		}
		return s
	case protocol.CodeBoxChanged:
		return "the box changed on the server while the request was handled: send it again as it is"
	case protocol.CodeStalePrekey:
		return "the box has a newer prekey than the one the message was encrypted to"
	case protocol.CodePrekeyExpired:
		return "the box's prekey has expired at the server, so it takes no mail until its owner renews it"
	case protocol.CodeRequestTimeout:
		return "the server stopped waiting for the request's body, which arrived too slowly for it: send it again"
	case protocol.CodeRevoked:
		return "the server answers that that box is revoked: this client takes that only from a revocation that verifies"
	case protocol.CodePreconditionFailed:
		return "what the server holds no longer has the tag the request's If-Match named"
	case protocol.CodeTooLarge:
		return "too large for the server" + limit(p, ": its limit is %d")
	case protocol.CodeRateLimited:
		return rateLimited(p)
	case protocol.CodeFetchPaced:
		return "the server paces how much new mail the box takes out: the rest waits on the server"
	case protocol.CodeRefetchSpent:
		return "the message was fetched before, and the server takes no more fetches of it for now: a client keeps each message when it fetches it"
	case protocol.CodePairFull:
		s := "the recipient holds as much unacked mail from this box as it takes"
		if p.Unacked != nil {
			s += fmt.Sprintf(": %d messages", *p.Unacked)
			if t, err := protocol.ParseTime(p.OldestExpiresAt); err == nil {
				s += ", the oldest expiring " + t.Format(protocol.TimeLayout)
			}
		}
		return s
	case protocol.CodeMailboxFull:
		s := "the recipient's box is full"
		if p.Count != nil {
			s += fmt.Sprintf(": it holds %d messages", *p.Count)
		}
		return s
	case protocol.CodeMailboxBusy:
		return "the recipient's box has taken as much new mail as it takes for now: dromas outbox flush posts it again"
	case protocol.CodeUnavailable:
		return "the server is not ready to answer"
	}
	return "an answer this client does not know"
}

// quotaWords say what each limit a rate_limited names has counted.
var quotaWords = map[protocol.Quota]string{
	protocol.QuotaPolls:                  "the box has polled as often as the server takes for now",
	protocol.QuotaPages:                  "the box has listed as many pages after the first as the server takes for now",
	protocol.QuotaCalls:                  "the box has made as many calls as the server takes for now",
	protocol.QuotaSends:                  "the box has sent as many messages as the server takes for now",
	protocol.QuotaRenewals:               "the box has renewed its prekey as many times as the server takes for now",
	protocol.QuotaCertificates:           "the box's identity has certified as many new working keys as the server takes for now",
	protocol.QuotaCertificateRevocations: "the box's identity has raised its revocation of certificates as many times as the server takes for now",
	protocol.QuotaRegistrations:          "as many boxes have been registered from this machine's IP address as the server takes for now",
	protocol.QuotaRegistrationsRange:     "as many boxes have been registered from this machine's IPv6 /48 as the server takes for now",
	protocol.QuotaMisses:                 "this machine's IP address has made as many calls that named no box or carried nothing that verified as the server takes for now",
	protocol.QuotaSendsBeforePass:        "this machine's IP address has made as many sends as the server takes for now",
	protocol.QuotaRequests:               "this machine's IP address has made as many requests as the server takes for now",
}

// rateLimited says which limit a rate_limited names, when this client knows
// it, with how many a day it takes for one counted by the day; otherwise whom
// it was counted against, when this client knows that.
func rateLimited(p *protocol.Problem) string {
	if s, ok := quotaWords[p.QuotaID]; ok {
		switch p.QuotaID {
		case protocol.QuotaSends:
			return s + limit(p, " (%d a day)") + ": an account can lift a box's limits (dromas account adopt)"
		case protocol.QuotaRenewals, protocol.QuotaCertificates, protocol.QuotaCertificateRevocations:
			return s + limit(p, " (%d a day)")
		}
		return s
	}
	switch p.Subject {
	case protocol.SubjectBox:
		return "the server takes no more calls of this kind from this box for now"
	case protocol.SubjectIP:
		return "the server takes no more calls of this kind from this machine's IP address for now"
	}
	return "the server takes no more calls of this kind for now"
}

// limit is format with the limit p carries, or "" when it carries none.
func limit(p *protocol.Problem, format string) string {
	if p.Limit == nil {
		return ""
	}
	return fmt.Sprintf(format, *p.Limit)
}

// knownTypes is the key types among names that this client knows, so that a
// server's list prints nothing a server made up.
func knownTypes(names []string) string {
	var known []string
	for _, n := range names {
		if slices.Contains(protocol.IdentityTypes(), n) && !slices.Contains(known, n) {
			known = append(known, n)
		}
	}
	return strings.Join(known, ", ")
}

// clock is what an error says about this machine's clock when the server
// refused the pass, or a prekey statement, for its time: what the clock
// reads, and the date on the server's answer. A new pass does not cure that
// refusal, so it is nearly always a clock, and a server takes a pass from a
// box whose clock is less than PassLifetime slow and no more than
// MaxPassLifetime less PassLifetime fast (protocol.MaxSkew).
//
// The date is the server's word and is given as that. A server may lie about
// the time, and a clock set by a lie makes an ended certificate valid again
// and stale mail fresh, so the sentence sends its reader to a time source of
// their own and never to the server's.
func (e *APIError) clock() string {
	c := e.Problem.Code
	if (c != protocol.CodePassExpired && c != protocol.CodePrekeyTime) || e.Dated.IsZero() || e.Read.IsZero() {
		return ""
	}
	slow, fast := protocol.PassLifetime, protocol.MaxPassLifetime-protocol.PassLifetime
	how := "the same"
	switch d := e.Read.Sub(e.Dated); {
	case d < 0:
		how = fmt.Sprintf("%s behind that", -d)
	case d > 0:
		how = fmt.Sprintf("%s ahead of that", d)
	}
	return fmt.Sprintf("; the server dates its answer %s, and this machine's clock reads %s, %s. A server refuses a pass from a clock %d minutes or more behind its own, or more than %d ahead, a certificate made by a clock more than %d ahead, and a prekey statement dated more than an hour ahead of it. Check this machine's clock against a time source you trust, not against the server",
		e.Dated.Format(protocol.TimeLayout), e.Read.Format(protocol.TimeLayout), how, slow/time.Minute, fast/time.Minute, fast/time.Minute)
}

// codeGrammar is the grammar of a code, as the box's state keeps one for
// each message quarantine/ holds (quarantineRecord).
var codeGrammar = regexp.MustCompile(`\A[a-z0-9_]{1,40}\z`)

// code is the error's code, if err is an [APIError]: read where the call
// that answered is made, never from an error whose calls are not known, so
// it stays in this package.
func code(err error) protocol.Code {
	var e *APIError
	if errors.As(err, &e) {
		return e.Problem.Code
	}
	return ""
}
