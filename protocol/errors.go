package protocol

import "net/http"

// Code is an API error's machine code. Every error response carries one, with
// a hint naming the client command that fixes it.
type Code string

// The error codes, grouped by HTTP status.
const (
	// 400
	CodeBadRequest         Code = "bad_request"          // not JSON, a missing or unknown field, a bad cursor
	CodeBadAddress         Code = "bad_address"          // not 64 hex characters, or a from that is not lowercase
	CodeBadEncoding        Code = "bad_encoding"         // a byte field that is not base64
	CodeIdentityMismatch   Code = "identity_mismatch"    // the identity does not hash to the address, or breaks its grammar
	CodeBadKey             Code = "bad_key"              // a bad key or prekey statement, or a prekey that is not new
	CodeNotAge             Code = "not_age"              // the ciphertext is not an age file
	CodeWrongRecipientType Code = "wrong_recipient_type" // not exactly one stanza of a live prekey type

	// 401
	CodeUnauthorized Code = "unauthorized" // no token, or a bad one
	CodeTokenStale   Code = "token_stale"  // POST …/token, decrypt, retry

	// 403
	CodeBadSignature     Code = "bad_signature"
	CodeUnknownSender    Code = "unknown_sender"     // not registered, not yet active, or closed
	CodeSenderRevoked    Code = "sender_revoked"     // YOUR box is revoked
	CodeSenderNotAllowed Code = "sender_not_allowed" // not on the box's allow list, or on its block list
	CodeAdoptKeyRefused  Code = "adopt_key_refused"  // an adopt key that is spent, expired, revoked or not this server's

	// 404
	CodeNoSuchMailbox Code = "no_such_mailbox" // never registered, still pending, or closed
	CodeNoSuchMessage Code = "no_such_message" // acked or expired: treat it as gone

	// 409
	CodeConflict      Code = "conflict"       // a replay that is not byte-identical
	CodeStalePrekey   Code = "stale_prekey"   // a newer prekey exists: re-fetch, re-encrypt the same envelope
	CodePrekeyExpired Code = "prekey_expired" // the box's owner must publish a new prekey

	// 410
	CodeRevoked Code = "revoked" // the box you named is revoked, forever

	// 413
	CodeTooLarge Code = "too_large"

	// 429, all with Retry-After
	CodeRateLimited Code = "rate_limited"
	CodePairFull    Code = "pair_full"
	CodeMailboxFull Code = "mailbox_full"

	// 503, with Retry-After
	CodeUnavailable Code = "unavailable"
)

var statuses = map[Code]int{
	CodeBadRequest:         http.StatusBadRequest,
	CodeBadAddress:         http.StatusBadRequest,
	CodeBadEncoding:        http.StatusBadRequest,
	CodeIdentityMismatch:   http.StatusBadRequest,
	CodeBadKey:             http.StatusBadRequest,
	CodeNotAge:             http.StatusBadRequest,
	CodeWrongRecipientType: http.StatusBadRequest,
	CodeUnauthorized:       http.StatusUnauthorized,
	CodeTokenStale:         http.StatusUnauthorized,
	CodeBadSignature:       http.StatusForbidden,
	CodeUnknownSender:      http.StatusForbidden,
	CodeSenderRevoked:      http.StatusForbidden,
	CodeSenderNotAllowed:   http.StatusForbidden,
	CodeAdoptKeyRefused:    http.StatusForbidden,
	CodeNoSuchMailbox:      http.StatusNotFound,
	CodeNoSuchMessage:      http.StatusNotFound,
	CodeConflict:           http.StatusConflict,
	CodeStalePrekey:        http.StatusConflict,
	CodePrekeyExpired:      http.StatusConflict,
	CodeRevoked:            http.StatusGone,
	CodeTooLarge:           http.StatusRequestEntityTooLarge,
	CodeRateLimited:        http.StatusTooManyRequests,
	CodePairFull:           http.StatusTooManyRequests,
	CodeMailboxFull:        http.StatusTooManyRequests,
	CodeUnavailable:        http.StatusServiceUnavailable,
}

// Status returns the code's HTTP status, or 0 for a code this version does
// not know.
func (c Code) Status() int { return statuses[c] }

// TypeURI returns the Problem Details "type" for the code.
func (c Code) TypeURI() string { return "https://irongall.dev/errors/" + string(c) }

// ProblemContentType is the media type of every error body (RFC 9457).
const ProblemContentType = "application/problem+json"

// Problem is an error body: RFC 9457 Problem Details, plus the extension
// members code and hint. Hint names the client command that fixes the error,
// never a raw command line; detail explains it for generic clients.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   Code   `json:"code"`
	Hint   string `json:"hint,omitempty"`

	// pair_full only: how many messages from this sender the box holds
	// unacked, and when the oldest of them expires.
	Unacked         *int   `json:"unacked,omitempty"`
	OldestExpiresAt string `json:"oldest_expires_at,omitempty"`
}
