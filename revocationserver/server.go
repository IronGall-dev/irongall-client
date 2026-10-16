// Package revocationserver is a revocation server: a small server that keeps
// what an address's identity has signed about it, a revocation of the address
// or of its certificates, and hands it to whoever asks for
// that address (PROTOCOL.md §6.3, "Revocation servers").
//
// It is to revocations what a keyserver is to keys, and it is no mailbox
// server. It has no boxes, takes no pass and holds no key. It answers two
// calls, for any address:
//
//	PUT /v1/<address>/revocations   keep a record, once it verifies
//	GET /v1/<address>/revocations   the record held, or 404 not_revoked
//
// A record proves itself: its identity document hashes to the address, and
// each statement in it is signed by that identity's own key. So a revocation
// server signs nothing and is trusted for nothing. It can keep a record
// back; it cannot make one. It lists nothing, and it is filled by upload, by
// a box's owner or by anyone who holds the record.
//
// It is built from the protocol package alone, and from nothing of a mailbox
// server: that it can be is the point of it.
package revocationserver

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// The defaults of Options.
const (
	// DefaultMaxBody is the largest body a mailbox server's own
	// PUT …/revocations takes.
	DefaultMaxBody = 64 << 10
	// DefaultWritesPerHour is how many records one caller may bring in an
	// hour. A box's owner brings one when a key is lost.
	DefaultWritesPerHour = 10
	// DefaultMaxAddresses bounds what the server holds: with MaxBody it is
	// the most disk it can be made to fill.
	DefaultMaxAddresses = 100_000
)

// Options configures a [Server]. Dir is required; a zero in any other field
// is its default.
type Options struct {
	// Dir is where the records are kept, one file for each address. A
	// revocation server keeps nothing else, and one process uses a directory at a time.
	Dir string
	// MaxBody is the largest request body taken, in bytes.
	MaxBody int64
	// WritesPerHour is how many records one caller may bring in an hour: each
	// costs a signature check or two, and may cost a write. A caller is an
	// IPv4 address or an IPv6 /64. Negative: no limit.
	WritesPerHour int
	// MaxAddresses is how many addresses the server holds a record of. Once
	// it holds that many it takes a record only for an address it already
	// holds. Negative: no bound.
	MaxAddresses int
	// TrustedProxies are the peers whose word for who is calling is taken:
	// from one of them, the caller is the address ClientIPHeader carries.
	// From anyone else, and when either is unset, it is the peer itself.
	TrustedProxies []netip.Prefix
	// ClientIPHeader is the request header a trusted proxy puts the
	// caller's address in.
	ClientIPHeader string
	// Now is the clock the write limit reads; time.Now if nil. Nothing a
	// revocation server checks is timed: a revocation carries no date.
	Now func() time.Time
	// Log gets one line for each record kept and each failure of the
	// store; nothing is logged if nil. A lookup is never logged: it would
	// record who asked about whom.
	Log *log.Logger
}

// Server is a revocation server over one directory.
type Server struct {
	store  *store
	opt    Options
	writes *limiter
	// mu makes a PUT's read, merge and write one step.
	mu sync.Mutex
}

// Open opens the revocation server kept in opt.Dir, making the directory if it is not
// there. It fails if another process has it open.
func Open(opt Options) (*Server, error) {
	if opt.Dir == "" {
		return nil, errors.New("a revocation server needs a directory to keep its records in")
	}
	if opt.MaxBody == 0 {
		opt.MaxBody = DefaultMaxBody
	}
	if opt.WritesPerHour == 0 {
		opt.WritesPerHour = DefaultWritesPerHour
	}
	if opt.MaxAddresses == 0 {
		opt.MaxAddresses = DefaultMaxAddresses
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	st, err := openStore(opt.Dir)
	if err != nil {
		return nil, err
	}
	return &Server{store: st, opt: opt, writes: newLimiter(opt.WritesPerHour, time.Hour)}, nil
}

// Close lets go of the directory.
func (s *Server) Close() error { return s.store.close() }

// Held returns how many addresses the server holds a record of.
func (s *Server) Held() int { return s.store.count() }

// about is what the server's root answers: what it is, for whoever was handed
// only its name.
const about = `irongall revocation server

It keeps what an address's identity has signed about it: a revocation of the
address, a revocation of its certificates, or both. It answers for an
address its asker already holds, and it lists nothing.

  GET /v1/<address>/revocations   the record held, or 404 not_revoked
  PUT /v1/<address>/revocations   keep a record, once it verifies

A record proves itself, so check it: this server signs nothing and is trusted
for nothing. It is no mailbox server and holds no box.

The protocol: https://github.com/IronGall-dev/irongall-client (PROTOCOL.md, 6.3)
`

// Handler returns the server's routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, about)
	})
	mux.HandleFunc("GET /v1/{addr}/revocations", s.handle(s.get))
	mux.HandleFunc("PUT /v1/{addr}/revocations", s.handle(s.put))
	return mux
}

// handle adapts a handler that returns its refusal. No answer about an
// address may be kept by a cache: a 404 that outlived an upload would be
// this server's word outliving the fact.
func (s *Server) handle(h func(http.ResponseWriter, *http.Request) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		err := h(w, r)
		if err == nil {
			return
		}
		var p *problem
		if !errors.As(err, &p) {
			s.logf("the store failed: %v", err)
			p = refuse(protocol.CodeUnavailable, "retry later, or ask another revocation server", "the server could not complete the request")
			p.retryAfter = time.Minute
		}
		p.write(w)
	}
}

func (s *Server) logf(format string, args ...any) {
	if s.opt.Log != nil {
		s.opt.Log.Printf(format, args...)
	}
}

// get is GET /v1/<address>/revocations: the record held, as it was kept. An
// address the server holds nothing about is answered from memory.
func (s *Server) get(w http.ResponseWriter, r *http.Request) error {
	a, err := pathAddress(r)
	if err != nil {
		return err
	}
	rec, err := s.store.read(a)
	if err != nil {
		return err
	}
	if rec == nil {
		return refuse(protocol.CodeNotRevoked, "nothing to do: this revocation server holds no revocation of that address. That is its word, and another server or the box's owner may hold one", "no revocation of this address is held here")
	}
	writeJSON(w, http.StatusOK, rec)
	return nil
}

const (
	hintRecord = "a record is the identity document with what the identity key itself signed: a revocation of the address (irongall revocation make prints it), a revocation of its certificates (irongall cert revoke-earlier), or both"
	hintFull   = "publish it at another revocation server, and tell this one's operator"
	hintHigher = "GET the same path for the one held: it covers every certificate yours does"
)

// put is PUT /v1/<address>/revocations: a record, kept once every part of it
// verifies. It asks for no pass: the identity's signature is the whole
// authority, and whoever holds a record may bring it.
//
// A revocation of the address is kept for good: 201 the first time, 200
// after. A revocation of certificates runs through a serial, and the highest
// stands: one through a lower serial than the one held is 409, and the same
// one again changes nothing. A revoked address takes no revocation of its
// certificates. A body may carry both, and everything in it is checked
// before anything is kept.
//
// What is already held, sent again, is answered with no signature checked.
// Everything else counts against its caller before it is checked, whether
// or not it then verifies.
func (s *Server) put(w http.ResponseWriter, r *http.Request) error {
	a, err := pathAddress(r)
	if err != nil {
		return err
	}
	var req protocol.Revocations
	if err := s.body(w, r, &req); err != nil {
		return err
	}
	hasCerts := req.RevokedCertificates != nil || req.RevokedCertificatesSignature != nil
	switch {
	case req.Identity == nil:
		return refuse(protocol.CodeBadRequest, hintRecord, "missing field \"identity\"")
	case hasCerts && (req.RevokedCertificates == nil || req.RevokedCertificatesSignature == nil):
		return refuse(protocol.CodeBadRequest, hintRecord, "a revocation of certificates comes with its signature: \"revoked_certificates\" and \"revoked_certificates_signature\"")
	case !hasCerts && req.Revocation == nil:
		return refuse(protocol.CodeBadRequest, hintRecord, "the record holds no revocation of the address and none of its certificates")
	}
	if protocol.Address(sha256.Sum256(req.Identity)) != a {
		return refuse(protocol.CodeIdentityMismatch, hintRecord, "the identity document does not hash to the address")
	}
	held, err := s.store.read(a)
	if err != nil {
		return err
	}
	if held != nil {
		if done, err := answered(w, &req, held); done {
			return err
		}
	}
	if ok, wait := s.writes.take(callerKey(s.caller(r)), s.opt.Now()); !ok {
		p := refuse(protocol.CodeRateLimited, "retry after the time given", "too many records from this address in an hour")
		p.retryAfter = wait
		return p
	}
	var certs *protocol.RevokedCertificates
	if hasCerts {
		if certs, err = protocol.VerifyRevokedCertificates(a, req.Identity, req.RevokedCertificates, req.RevokedCertificatesSignature); err != nil {
			return unverified(err, "this is not a revocation of this address's certificates")
		}
	}
	if req.Revocation != nil {
		if _, err := protocol.VerifyRevocation(a, req.Identity, req.Revocation); err != nil {
			return unverified(err, "this is not a revocation of this address")
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// Read again, now that nothing else can change it.
	if held, err = s.store.read(a); err != nil {
		return err
	}
	if held != nil && held.Revocation != nil && req.Revocation == nil {
		return revoked()
	}
	keep := protocol.Revocations{Identity: req.Identity}
	if held != nil {
		keep = *held
	}
	status, changed := http.StatusOK, false
	// A revoked address takes no revocation of its certificates: it is
	// ended, and that says which of its certificates still stand.
	if certs != nil && keep.Revocation == nil && !bytes.Equal(req.RevokedCertificates, keep.RevokedCertificates) {
		if keep.RevokedCertificates != nil {
			was, err := protocol.ParseRevokedCertificates(keep.RevokedCertificates)
			if err != nil {
				return fmt.Errorf("the revocation of certificates kept for %s: %w", a, err)
			}
			if certs.Through <= was.Through {
				return refuse(protocol.CodeConflict, hintHigher, "a revocation of this address's certificates through serial %d is held, and nothing revokes fewer", was.Through)
			}
		}
		keep.RevokedCertificates, keep.RevokedCertificatesSignature, changed = req.RevokedCertificates, req.RevokedCertificatesSignature, true
	}
	if req.Revocation != nil && keep.Revocation == nil {
		keep.Revocation = req.Revocation
		status, changed = http.StatusCreated, true
	}
	if changed {
		if held == nil && s.opt.MaxAddresses > 0 && s.store.count() >= s.opt.MaxAddresses {
			s.logf("full: %d addresses are held, and a record of another was refused", s.store.count())
			p := refuse(protocol.CodeUnavailable, hintFull, "this revocation server holds as many addresses as it is set to hold, and takes a record only for one of those")
			p.retryAfter = time.Hour
			return p
		}
		if err := s.store.write(a, &keep); err != nil {
			return err
		}
		s.logf("kept for %s: revoked=%t certificates=%t", a, keep.Revocation != nil, keep.RevokedCertificates != nil)
	}
	writeJSON(w, status, struct{}{})
	return nil
}

// answered answers a record from what is held alone, with no signature
// checked, when that settles it: a revoked address takes no revocation of its
// certificates, and what is held byte for byte was verified when it was kept.
// It reports whether it answered.
func answered(w http.ResponseWriter, req, held *protocol.Revocations) (bool, error) {
	if held.Revocation != nil && req.Revocation == nil {
		return true, revoked()
	}
	// A part that is sent is one that is held, byte for byte. An empty one
	// is no part held: it goes on to be checked, and refused.
	same := func(sent, kept protocol.Bytes) bool { return len(sent) > 0 && bytes.Equal(sent, kept) }
	if !same(req.Identity, held.Identity) {
		return false, nil
	}
	if req.Revocation != nil && !same(req.Revocation, held.Revocation) {
		return false, nil
	}
	if req.RevokedCertificates != nil && (!same(req.RevokedCertificates, held.RevokedCertificates) || !same(req.RevokedCertificatesSignature, held.RevokedCertificatesSignature)) {
		return false, nil
	}
	writeJSON(w, http.StatusOK, struct{}{})
	return true, nil
}

// revoked is the answer to a revocation of certificates for an address whose
// revocation is held.
func revoked() *problem {
	return refuse(protocol.CodeRevoked, "the address is revoked, for good: GET the same path for the record, and check it", "a revocation of this address is held here, and a revoked address takes no revocation of its certificates")
}

// unverified is the answer to a part of a record that did not verify.
func unverified(err error, what string) *problem {
	if errors.Is(err, protocol.ErrIdentityType) {
		return refuse(protocol.CodeUnsupportedKeyType, "publish it at a revocation server that verifies that key type", "the identity is of a key type this server does not verify, so it cannot check what the identity signed")
	}
	return refuse(protocol.CodeBadRevocation, hintRecord, "%s", what)
}

// body reads a request body into v: one JSON object, no unknown member, at
// most MaxBody bytes.
func (s *Server) body(w http.ResponseWriter, r *http.Request, v any) error {
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.opt.MaxBody))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return refuse(protocol.CodeTooLarge, "send less", "the request body is over %d bytes", s.opt.MaxBody)
		}
		return refuse(protocol.CodeBadRequest, "", "the request body could not be read")
	}
	switch err := protocol.UnmarshalRequest(data, v); {
	case err == nil:
		return nil
	case errors.Is(err, protocol.ErrNotBase64):
		return refuse(protocol.CodeBadEncoding, "base64 of the exact file bytes", "a byte field is not standard base64 in its one encoding")
	case errors.Is(err, protocol.ErrUnknownMember):
		return refuse(protocol.CodeBadRequest, hintRecord, "%v", err)
	}
	return refuse(protocol.CodeBadRequest, hintRecord, "the body is not the JSON object expected, read as PROTOCOL.md §0b reads one")
}

// pathAddress reads the address in the path: 64 hex characters, folded to
// lowercase, as a mailbox server reads one.
func pathAddress(r *http.Request) (protocol.Address, error) {
	a, err := protocol.ParseAddress(strings.ToLower(r.PathValue("addr")))
	if err != nil {
		return a, refuse(protocol.CodeBadAddress, "an address is 64 hex characters", "the path does not name an address")
	}
	return a, nil
}

// caller is who a request counts against: the address a trusted proxy names
// in ClientIPHeader, otherwise the peer's own.
func (s *Server) caller(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || s.opt.ClientIPHeader == "" || !slices.ContainsFunc(s.opt.TrustedProxies, func(p netip.Prefix) bool { return p.Contains(peer.Unmap()) }) {
		return host
	}
	if ip, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(s.opt.ClientIPHeader))); err == nil {
		return ip.String()
	}
	return host
}

// callerKey is what a caller is counted under: an IPv4 address, or an IPv6
// address's /64, since one subscriber holds a whole /64.
func callerKey(host string) string {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if ip = ip.Unmap(); ip.Is4() {
		return ip.String()
	}
	p, err := ip.Prefix(64)
	if err != nil {
		return ip.String()
	}
	return p.String()
}

// problem is a refusal: an RFC 9457 body with the protocol's code and a
// hint, as a mailbox server sends one.
type problem struct {
	protocol.Problem
	retryAfter time.Duration
}

func (p *problem) Error() string { return string(p.Code) + ": " + p.Detail }

// titles are the summaries of the codes a revocation server sends.
var titles = map[protocol.Code]string{
	protocol.CodeBadRequest:         "Bad request",
	protocol.CodeBadAddress:         "Bad address",
	protocol.CodeBadEncoding:        "Bad encoding",
	protocol.CodeIdentityMismatch:   "Identity mismatch",
	protocol.CodeBadRevocation:      "Bad revocation",
	protocol.CodeUnsupportedKeyType: "Unsupported key type",
	protocol.CodeNotRevoked:         "Not revoked",
	protocol.CodeConflict:           "Conflict",
	protocol.CodeRevoked:            "Revoked",
	protocol.CodeTooLarge:           "Too large",
	protocol.CodeRateLimited:        "Rate limited",
	protocol.CodeUnavailable:        "Unavailable",
}

func refuse(code protocol.Code, hint, format string, args ...any) *problem {
	return &problem{Problem: protocol.Problem{Type: code.TypeURI(), Title: titles[code], Status: int64(code.Status()), Detail: fmt.Sprintf(format, args...), Code: code, Hint: hint}}
}

func (p *problem) write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", protocol.ProblemContentType)
	if p.retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int((p.retryAfter+time.Second-1)/time.Second)))
	}
	w.WriteHeader(p.Code.Status())
	_ = json.NewEncoder(w).Encode(p.Problem)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
