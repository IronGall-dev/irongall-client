package client

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// RefusedError is a check that failed. The operation stopped there: nothing
// was encrypted, sent, delivered or recorded past the failed check.
type RefusedError struct {
	Reason string
}

func (e *RefusedError) Error() string { return "REFUSED: " + e.Reason }

func refuse(format string, args ...any) error {
	return &RefusedError{Reason: fmt.Sprintf(format, args...)}
}

// Why a message was refused, as codes: with protocol's (bad_message,
// bad_envelope, bad_identity, bad_signature, reattributed, stale), a closed
// set. A refusal's words are this client's own and never quote the message,
// its claimed sender's text or the server's: whoever reads a refusal may be a
// model.
const (
	RefusedDecrypt = "undecryptable" // not encrypted to a prekey this box holds
	RefusedReplay  = "replay"        // this ciphertext was already received
	RefusedID      = "bad_id"        // the server's id for it is not the SHA-256 of its ciphertext
)

// APIError is a non-2xx answer from the server. Problem is the RFC 9457 body
// when the server sent one; its Code and Hint say what to do.
type APIError struct {
	Status  int
	Problem protocol.Problem
	// RetryAfter is the server's Retry-After, or zero.
	RetryAfter time.Duration
	// Dated is the time in the answer's Date header, and Read this box's
	// clock when the answer came: both zero unless the call carried a pass
	// and the answer a Date. They are set side by side in the error for a
	// pass refused for its time, and never adopted: a box checks everything
	// against its own clock, and a server may lie about the time as about
	// anything else.
	Dated, Read time.Time
}

// Error is the status and code, then what the server says: its detail (which
// names the limit hit, and for a rate limit the seconds to wait) and its
// hint. Those are the server's words, not this client's, and are printed as
// such: in quotes, on one line, printable ASCII only, and no longer than
// serverWords each. A code that is not a code is not printed.
func (e *APIError) Error() string {
	code := string(e.Problem.Code)
	if !codeGrammar.MatchString(code) {
		return fmt.Sprintf("ERROR %d", e.Status)
	}
	var says []string
	for _, s := range []string{e.Problem.Detail, e.Problem.Hint} {
		if s = plain(s); s != "" {
			says = append(says, s)
		}
	}
	if len(says) == 0 {
		return fmt.Sprintf("ERROR %d %s", e.Status, code) + e.clock()
	}
	return fmt.Sprintf("ERROR %d %s; the server says: %q", e.Status, code, strings.Join(says, "; ")) + e.clock()
}

// clock is what an error says about this machine's clock when the server
// refused the pass for its time: what the clock reads, and the date on the
// server's answer. A new pass does not cure that refusal, so it is nearly
// always a clock, and a server takes a pass from a box whose clock is less
// than PassLifetime slow and no more than MaxPassLifetime less PassLifetime
// fast (protocol.MaxSkew).
//
// The date is the server's word and is given as that. A server may lie about
// the time, and a clock set by a lie makes an ended certificate valid again
// and stale mail fresh, so the sentence sends its reader to a time source of
// their own and never to the server's.
func (e *APIError) clock() string {
	if e.Problem.Code != protocol.CodePassExpired || e.Dated.IsZero() || e.Read.IsZero() {
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
	return fmt.Sprintf("; the server dates its answer %s, and this machine's clock reads %s, %s. A server refuses a pass from a clock %d minutes or more behind its own, or more than %d ahead. Check this machine's clock against a time source you trust, not against the server",
		e.Dated.Format(protocol.TimeLayout), e.Read.Format(protocol.TimeLayout), how, slow/time.Minute, fast/time.Minute)
}

// serverWords is the most of a server's detail or hint that is printed.
const serverWords = 200

var codeGrammar = regexp.MustCompile(`\A[a-z0-9_]{1,40}\z`)

// plain returns text someone else chose as one bounded line of printable
// ASCII: anything else in it becomes a space.
func plain(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i >= serverWords {
			b.WriteString("...")
			break
		}
		if r < ' ' || r > '~' {
			r = ' '
		}
		b.WriteRune(r)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// Code returns the error's code, if err is an [APIError].
func Code(err error) protocol.Code {
	var e *APIError
	if errors.As(err, &e) {
		return e.Problem.Code
	}
	return ""
}
