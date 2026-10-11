package client

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/drewstreib/crossbot-client/protocol"
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

// APIError is a non-2xx answer from the server. Problem is the RFC 9457 body
// when the server sent one; its Code and Hint say what to do.
type APIError struct {
	Status  int
	Problem protocol.Problem
	// RetryAfter is the server's Retry-After, or zero.
	RetryAfter time.Duration
}

// Error is the status and code, then the server's detail (which names the
// limit hit, and for a rate limit the seconds to wait) and its hint.
func (e *APIError) Error() string {
	if e.Problem.Code == "" {
		return fmt.Sprintf("ERROR %d", e.Status)
	}
	var says []string
	for _, s := range []string{e.Problem.Detail, e.Problem.Hint} {
		if s != "" {
			says = append(says, s)
		}
	}
	if len(says) == 0 {
		return fmt.Sprintf("ERROR %d %s", e.Status, e.Problem.Code)
	}
	return fmt.Sprintf("ERROR %d %s: %s", e.Status, e.Problem.Code, strings.Join(says, "; "))
}

// Code returns the error's code, if err is an [APIError].
func Code(err error) protocol.Code {
	var e *APIError
	if errors.As(err, &e) {
		return e.Problem.Code
	}
	return ""
}
