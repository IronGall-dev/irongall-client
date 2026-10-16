package protocol

import (
	"maps"
	"net/http"
	"slices"
)

// Code is an API error's machine code, from the closed list below
// (PROTOCOL.md §13). A code names what a client does about the error: one
// call that can fail for causes a client meets differently has a code for
// each, and where the call itself tells them apart (a too_large on an ACL is
// entries, on a send bytes) one code serves.
type Code string

// The error codes, grouped by HTTP status.
const (
	// 400
	CodeBadRequest         Code = "bad_request"          // not JSON, a missing or unknown field, a bad cursor
	CodeBadAddress         Code = "bad_address"          // not 64 hex characters, or a from that is not lowercase
	CodeBadEncoding        Code = "bad_encoding"         // a byte field that is not base64
	CodeIdentityMismatch   Code = "identity_mismatch"    // the identity does not hash to the address, or breaks its grammar
	CodeBadKey             Code = "bad_key"              // an identity key, certificate or prekey statement that is malformed or does not verify
	CodePrekeyNotNew       Code = "prekey_not_new"       // the prekey was published before: every prekey is a new key
	CodePrekeyTime         Code = "prekey_time"          // the statement or its certificate is not valid at the server's clock
	CodeUnsupportedKeyType Code = "unsupported_key_type" // an identity of a key type this server does not register
	CodeNotAge             Code = "not_age"              // the ciphertext is not an age file
	CodeWrongRecipientType Code = "wrong_recipient_type" // not exactly one stanza of a live prekey type
	CodeBadRevocation      Code = "bad_revocation"       // not a revocation of the address: the document does not hash to it, or the signature is not its identity's own

	// 401, with WWW-Authenticate
	CodeUnauthorized          Code = "unauthorized"            // no pass, or one that is not this box's, for this server
	CodePassExpired           Code = "pass_expired"            // the pass, or the certificate it is under, is not valid at the server's clock: sign another, retry
	CodeCertificateNotCurrent Code = "certificate_not_current" // the pass or statement is under a certificate that is neither the box's current one nor above it
	CodeCertificateRevoked    Code = "certificate_revoked"     // the pass or statement is under a certificate the box's identity revoked

	// 403
	CodeUnknownSender    Code = "unknown_sender"     // not registered, or closed
	CodeSenderRevoked    Code = "sender_revoked"     // YOUR box is revoked
	CodeSenderNotAllowed Code = "sender_not_allowed" // not on the box's allow list, or on its block list
	CodeSenderKeyType    Code = "sender_key_type"    // the box's client does not verify identities of YOUR box's key type
	CodeAdoptKeyRefused  Code = "adopt_key_refused"  // an adopt key that is spent, expired, revoked or not this server's

	// 404
	CodeNoSuchMailbox Code = "no_such_mailbox" // never registered, or closed
	CodeNoSuchMessage Code = "no_such_message" // acked or expired: treat it as gone
	CodeNotRevoked    Code = "not_revoked"     // no revocation of this address is held here

	// 409
	CodeConflict      Code = "conflict"       // what is held is newer, or another: a replay that is not byte-identical
	CodeBoxChanged    Code = "box_changed"    // the box changed while the request was handled: send it again as it is
	CodeStalePrekey   Code = "stale_prekey"   // a newer prekey exists: re-fetch, re-encrypt the same envelope
	CodePrekeyExpired Code = "prekey_expired" // the box's owner must publish a new prekey

	// 410
	CodeRevoked Code = "revoked" // the box you named is revoked, forever

	// 413
	CodeTooLarge Code = "too_large"

	// 429, all with Retry-After
	CodeRateLimited       Code = "rate_limited"        // more calls than a limit takes for now
	CodeRenewalsSpent     Code = "renewals_spent"      // the box's prekey renewals for the day
	CodeIdentityActsSpent Code = "identity_acts_spent" // the identity's certificates and revocations of certificates for the day
	CodeSendsSpent        Code = "sends_spent"         // the box's sends for the day
	CodeFetchPaced        Code = "fetch_paced"         // the box has taken out as much new mail as it may for now: the rest waits
	CodeRefetchSpent      Code = "refetch_spent"       // the message was fetched before, and fetching again is spent for now
	CodePairFull          Code = "pair_full"
	CodeMailboxFull       Code = "mailbox_full"
	CodeMailboxBusy       Code = "mailbox_busy" // the box has taken as much new mail as it takes for now

	// 503, with Retry-After
	CodeUnavailable Code = "unavailable"
)

var codes = map[Code]struct {
	status int
	title  string
}{
	CodeBadRequest:            {http.StatusBadRequest, "Bad request"},
	CodeBadAddress:            {http.StatusBadRequest, "Bad address"},
	CodeBadEncoding:           {http.StatusBadRequest, "Bad encoding"},
	CodeIdentityMismatch:      {http.StatusBadRequest, "Identity mismatch"},
	CodeBadKey:                {http.StatusBadRequest, "Bad key"},
	CodePrekeyNotNew:          {http.StatusBadRequest, "Prekey not new"},
	CodePrekeyTime:            {http.StatusBadRequest, "Prekey not valid now"},
	CodeUnsupportedKeyType:    {http.StatusBadRequest, "Unsupported key type"},
	CodeNotAge:                {http.StatusBadRequest, "Not an age file"},
	CodeWrongRecipientType:    {http.StatusBadRequest, "Wrong recipient type"},
	CodeBadRevocation:         {http.StatusBadRequest, "Bad revocation"},
	CodeUnauthorized:          {http.StatusUnauthorized, "Unauthorized"},
	CodePassExpired:           {http.StatusUnauthorized, "Pass expired"},
	CodeCertificateNotCurrent: {http.StatusUnauthorized, "Certificate not current"},
	CodeCertificateRevoked:    {http.StatusUnauthorized, "Certificate revoked"},
	CodeUnknownSender:         {http.StatusForbidden, "Unknown sender"},
	CodeSenderRevoked:         {http.StatusForbidden, "Sender revoked"},
	CodeSenderNotAllowed:      {http.StatusForbidden, "Sender not allowed"},
	CodeSenderKeyType:         {http.StatusForbidden, "Sender key type"},
	CodeAdoptKeyRefused:       {http.StatusForbidden, "Adopt key refused"},
	CodeNoSuchMailbox:         {http.StatusNotFound, "No such mailbox"},
	CodeNoSuchMessage:         {http.StatusNotFound, "No such message"},
	CodeNotRevoked:            {http.StatusNotFound, "Not revoked"},
	CodeConflict:              {http.StatusConflict, "Conflict"},
	CodeBoxChanged:            {http.StatusConflict, "Box changed"},
	CodeStalePrekey:           {http.StatusConflict, "Stale prekey"},
	CodePrekeyExpired:         {http.StatusConflict, "Prekey expired"},
	CodeRevoked:               {http.StatusGone, "Revoked"},
	CodeTooLarge:              {http.StatusRequestEntityTooLarge, "Too large"},
	CodeRateLimited:           {http.StatusTooManyRequests, "Rate limited"},
	CodeRenewalsSpent:         {http.StatusTooManyRequests, "Renewals spent"},
	CodeIdentityActsSpent:     {http.StatusTooManyRequests, "Identity acts spent"},
	CodeSendsSpent:            {http.StatusTooManyRequests, "Sends spent"},
	CodeFetchPaced:            {http.StatusTooManyRequests, "Fetch paced"},
	CodeRefetchSpent:          {http.StatusTooManyRequests, "Refetch spent"},
	CodePairFull:              {http.StatusTooManyRequests, "Pair full"},
	CodeMailboxFull:           {http.StatusTooManyRequests, "Mailbox full"},
	CodeMailboxBusy:           {http.StatusTooManyRequests, "Mailbox busy"},
	CodeUnavailable:           {http.StatusServiceUnavailable, "Unavailable"},
}

// Status returns the code's HTTP status, or 0 for a code this version does
// not know.
func (c Code) Status() int { return codes[c].status }

// Title returns the code's Problem Details title, or "" for a code this
// version does not know.
func (c Code) Title() string { return codes[c].title }

// Codes returns every code this version knows, sorted.
func Codes() []Code {
	return slices.Sorted(maps.Keys(codes))
}

// Known reports whether c is a code this version knows.
func (c Code) Known() bool { _, ok := codes[c]; return ok }

// TypeURI returns the Problem Details "type" for the code.
func (c Code) TypeURI() string { return "https://irongall.dev/errors/" + string(c) }

// ProblemContentType is the media type of every error body (RFC 9457).
const ProblemContentType = "application/problem+json"

// Problem is an error body: RFC 9457 Problem Details, with the extension
// members code and hint, and one member for each value the error carries
// (PROTOCOL.md §13). Every value in detail is also a member of its own
// (AEP-193), so a client needs nothing from detail, hint or title: they are
// a server's words, for a person reading the body, and a client shows none
// of them. A client says what the code means in its own words, with the
// members it has checked to their types.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int64  `json:"status"`
	Detail string `json:"detail,omitempty"`
	Code   Code   `json:"code"`
	Hint   string `json:"hint,omitempty"`

	// Limit is the limit hit: the most bytes a body or a ciphertext may
	// hold, or entries an ACL (too_large); the sends, renewals or identity
	// acts a day takes (sends_spent, renewals_spent, identity_acts_spent).
	Limit *uint64 `json:"limit,omitempty"`
	// Messages is how many messages a full box holds (mailbox_full).
	Messages *uint64 `json:"messages,omitempty"`
	// Unacked and OldestExpiresAt are how many messages from this sender the
	// box holds unacked, and when the oldest of them expires (pair_full).
	Unacked         *int64 `json:"unacked,omitempty"`
	OldestExpiresAt string `json:"oldest_expires_at,omitempty"`
	// Version is the version of the ACL held (conflict).
	Version *uint64 `json:"version,omitempty"`
	// PrekeySerial and CertificateSerial are the serials of the prekey and
	// of the certificate the server holds as the box's current ones
	// (stale_prekey; conflict and certificate_not_current give the one that
	// a new statement must be above).
	PrekeySerial      *uint64 `json:"prekey_serial,omitempty"`
	CertificateSerial *uint64 `json:"certificate_serial,omitempty"`
	// Through is the serial a revocation of certificates held runs through
	// (conflict).
	Through *uint64 `json:"through,omitempty"`
	// KeyTypes are the identity key types a server registers
	// (unsupported_key_type), and KeyType the one a box's client does not
	// verify (sender_key_type).
	KeyTypes []string `json:"key_types,omitempty"`
	KeyType  string   `json:"key_type,omitempty"`
	// Member is the request member that is missing or unknown (bad_request).
	Member string `json:"member,omitempty"`
}
