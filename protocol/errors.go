package protocol

import (
	"maps"
	"net/http"
	"slices"
)

// Code is an API error's machine code, from the closed list below
// (PROTOCOL.md §11.3). A code names what a client does about the error: one
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
	CodeCertificateRevoked    Code = "certificate_revoked"     // a certificate the box's identity revoked: which calls, PROTOCOL.md §8 and §11.4

	// 403
	CodeUnknownSender    Code = "unknown_sender"     // not registered
	CodeSenderRevoked    Code = "sender_revoked"     // YOUR box is revoked
	CodeSenderNotAllowed Code = "sender_not_allowed" // not on the box's allow list, or on its block list
	CodeSenderKeyType    Code = "sender_key_type"    // the box's client does not verify identities of YOUR box's key type
	CodeAdoptKeyRefused  Code = "adopt_key_refused"  // an adopt key that is spent, expired, revoked or not this server's

	// 404
	CodeNoSuchMailbox Code = "no_such_mailbox" // never registered, or forgotten
	CodeNoSuchMessage Code = "no_such_message" // acked or expired: treat it as gone
	CodeNotRevoked    Code = "not_revoked"     // no revocation of this address is held here

	// 409
	CodeConflict      Code = "conflict"       // what is held is newer, or another: a replay that is not byte-identical
	CodeBoxChanged    Code = "box_changed"    // the box changed while the request was handled: send it again as it is
	CodeStalePrekey   Code = "stale_prekey"   // a newer prekey exists: re-fetch, re-encrypt the same envelope
	CodePrekeyExpired Code = "prekey_expired" // the box's owner must publish a new prekey

	// 408
	CodeRequestTimeout Code = "request_timeout" // the body did not arrive in the time the server waits for it: send it again

	// 410
	CodeRevoked Code = "revoked" // the box you named is revoked, forever

	// 412
	CodePreconditionFailed Code = "precondition_failed" // an If-Match the server evaluated false (RFC 9110 §13.1.1)

	// 413
	CodeTooLarge Code = "too_large"

	// 429, all with Retry-After
	CodeRateLimited  Code = "rate_limited"  // a limit takes no more for now: which one is quota_id, and whom it counted against subject
	CodeFetchPaced   Code = "fetch_paced"   // the box has taken out as much new mail as it may for now: the rest waits
	CodeRefetchSpent Code = "refetch_spent" // the message was fetched before, and fetching again is spent for now
	CodePairFull     Code = "pair_full"
	CodeMailboxFull  Code = "mailbox_full"
	CodeMailboxBusy  Code = "mailbox_busy" // the box has taken as much new mail as it takes for now

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
	CodeRequestTimeout:        {http.StatusRequestTimeout, "Request timeout"},
	CodeRevoked:               {http.StatusGone, "Revoked"},
	CodePreconditionFailed:    {http.StatusPreconditionFailed, "Precondition failed"},
	CodeTooLarge:              {http.StatusRequestEntityTooLarge, "Too large"},
	CodeRateLimited:           {http.StatusTooManyRequests, "Rate limited"},
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

// TypePrefix begins every code's Problem Details "type": a tag URI (RFC
// 4151) that names the problem and resolves to nothing (PROTOCOL.md §11.3).
// The date is a whole day after dromas.dev was registered: RFC 4151 reads a
// month alone as its first day, before the registration. A tag is a name,
// never a location.
const TypePrefix = "tag:dromas.dev,2026-10-26:errors/"

// TypeURI returns the Problem Details "type" for the code.
func (c Code) TypeURI() string { return TypePrefix + string(c) }

// ProblemContentType is the media type of every error body (RFC 9457).
const ProblemContentType = "application/problem+json"

// Problem is an error body: RFC 9457 Problem Details, with the extension
// members code and hint, and one member for each value the error carries
// (PROTOCOL.md §11.3). Every value in detail is also a member of its own
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
	// hold, or entries an ACL (too_large); how many a day a limit counted by
	// the day takes (rate_limited with QuotaSends, QuotaRenewals,
	// QuotaCertificates or QuotaCertificateRevocations).
	Limit *uint64 `json:"limit,omitempty"`
	// QuotaID is the limit a rate_limited names, and Subject whom it was
	// counted against (Google's QuotaFailure.Violation). A client shows each
	// only once it knows the value.
	QuotaID Quota   `json:"quota_id,omitempty"`
	Subject Subject `json:"subject,omitempty"`
	// Count is how many messages a full box holds, as its list counts them
	// (mailbox_full).
	Count *uint64 `json:"count,omitempty"`
	// Unacked and OldestExpiresAt are how many messages from this sender the
	// box holds unacked, and when the oldest of them expires (pair_full).
	Unacked         *int64 `json:"unacked,omitempty"`
	OldestExpiresAt string `json:"oldest_expires_at,omitempty"`
	// PrekeySerial and CertificateSerial are serials of a prekey and of a
	// certificate: which ones each code names is PROTOCOL.md §11.3's.
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
	// Member is the request member or query parameter that is missing,
	// unknown, given twice or not of its form (bad_request).
	Member string `json:"member,omitempty"`
	// Record is the revocation record of the address a 410 revoked names,
	// which the read of a box always carries, and any other call's where its
	// server answers from the record (PROTOCOL.md §11.3). A client checks it,
	// and takes "revoked" on nothing less.
	Record *Revocations `json:"record,omitempty"`
}

// checkType holds a record a problem carries to the type it names, as one
// read alone is held.
func (p *Problem) checkType() error {
	if p.Record != nil {
		return p.Record.checkType()
	}
	return nil
}

// CodeAt returns the problem's code if it counts in an answer of the given
// status: a code this version knows, under its own status, in a body whose
// type is that code's own (PROTOCOL.md §11.3). Otherwise it returns "", and
// the answer is read by its status alone: a body that names its problem
// twice and disagrees names none.
func (p *Problem) CodeAt(status int) Code {
	if p.Code.Known() && p.Code.Status() == status && p.Type == p.Code.TypeURI() {
		return p.Code
	}
	return ""
}

// Quota is a limit a rate_limited names in quota_id, from the closed set
// below (PROTOCOL.md §11.5), as Google's QuotaFailure names one in its
// quota_id. Each is counted against one subject. A server's limit outside the
// set names none, and gives its subject alone.
type Quota string

// The quotas, by whom each is counted against.
const (
	QuotaPolls                  Quota = "polls"                   // a box's polls
	QuotaPages                  Quota = "pages"                   // a box's list pages after the first
	QuotaCalls                  Quota = "calls"                   // a box's calls with its pass that no other limit counts
	QuotaSends                  Quota = "sends"                   // a box's sends, a number a day
	QuotaRenewals               Quota = "renewals"                // a box's renewals under its current certificate, a number a day
	QuotaCertificates           Quota = "certificates"            // its identity's new certificates, a number a day
	QuotaCertificateRevocations Quota = "certificate_revocations" // its identity's raises of its revocation of certificates, a number a day

	QuotaRegistrations      Quota = "registrations"       // registrations from an IP address: an IPv4 address or an IPv6 /64
	QuotaRegistrationsRange Quota = "registrations_range" // registrations from an IPv6 /48
	QuotaMisses             Quota = "misses"              // calls from an IP address that named no box or carried nothing that verified
	QuotaSendsBeforePass    Quota = "sends_before_pass"   // sends from an IP address, counted before their pass is read
	QuotaRequests           Quota = "requests"            // calls from an IP address that carry no pass the server has checked, registrations and renewals among them, and requests no route matches
)

// Subject is whom a rate_limited was counted against (subject).
type Subject string

// The subjects.
const (
	SubjectBox Subject = "box" // the box the call proved itself to be, or whose identity signed it
	SubjectIP  Subject = "ip"  // the IP address the call came from, as the quota keys it
)

var quotas = map[Quota]Subject{
	QuotaPolls:                  SubjectBox,
	QuotaPages:                  SubjectBox,
	QuotaCalls:                  SubjectBox,
	QuotaSends:                  SubjectBox,
	QuotaRenewals:               SubjectBox,
	QuotaCertificates:           SubjectBox,
	QuotaCertificateRevocations: SubjectBox,
	QuotaRegistrations:          SubjectIP,
	QuotaRegistrationsRange:     SubjectIP,
	QuotaMisses:                 SubjectIP,
	QuotaSendsBeforePass:        SubjectIP,
	QuotaRequests:               SubjectIP,
}

// Known reports whether q is a quota this version knows.
func (q Quota) Known() bool { _, ok := quotas[q]; return ok }

// Subject returns whom q is counted against, or "" for a quota this version
// does not know.
func (q Quota) Subject() Subject { return quotas[q] }

// Quotas returns every quota this version knows, sorted.
func Quotas() []Quota { return slices.Sorted(maps.Keys(quotas)) }

// Known reports whether s is a subject this version knows.
func (s Subject) Known() bool { return s == SubjectBox || s == SubjectIP }
