// Package fakeserver is an in-memory dromas server for the client's tests:
// honest, and just enough of the API for a client to register, renew its
// prekey, send, list page by page, fetch and ack, each call carrying its
// mailbox's pass. It is NOT the dromas.dev server, and checks little of what
// that server checks. Like every server it keeps and serves a revocation of
// any address, with a mailbox here or none (PROTOCOL.md §11.15), and holds an
// address to its mode by the revocation of its certificates it keeps
// (PROTOCOL.md §5): in identity mode it takes the identity's statements and
// passes and no certificate (409 identity_mode), and in working-key mode a
// certificate above the revocation alone (401 certificate_revoked).
//
// A test plays the hostile operator two ways: with SetMiddle, a function that
// sees every request and can rewrite it, answer it or forge the reply; and
// with the operator's own powers over storage (Inject, Count, Prekey). It
// logs every call it is sent, as the client sent it (Requests). Nothing the
// client is told to trust comes from here: every forgery a test makes is one
// a real operator could make (internal/forge has the common ones).
package fakeserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/api/apitest"
	"github.com/dromas-dev/dromas-client/protocol"
)

// Server is a running fake server.
type Server struct {
	URL string

	srv       *httptest.Server
	now       func() time.Time
	mu        sync.Mutex
	mailboxes map[protocol.Address]*mailbox
	held      map[protocol.Address]*held // the revocations of addresses with no mailbox here
	keys      map[string]string          // adopt key → account, each good once
	middle    func(w http.ResponseWriter, r *http.Request, next http.Handler)
	page      int                     // the most messages a list's page holds
	hold      time.Duration           // the longest this server holds a list (SetHold)
	log       []Request               // every call, oldest first
	policy    protocol.ServerDocument // GET /v1/, and what every answer under /v1/ says of a version by it (SetPolicy)
}

// Request is one call the server was sent, as the client sent it, before
// any middleware saw it.
type Request struct {
	Method, Path, Query string // the path and the raw query apart
	Pass                bool   // it carried an Authorization header
	Version             string // its Dromas-Version, as sent: "" for none
}

type mailbox struct {
	wake      chan struct{} // closed at the mailbox's next change, for a held list (changed)
	identity  []byte
	statement []byte
	signature []byte
	prekey    *protocol.Prekey
	signer    *protocol.Signer // the current statement's signer: passes are taken by it only
	key       []byte           // that signer's key's wire bytes: the identity's key, or the certificate
	keep      time.Time        // the latest it is kept until (PROTOCOL.md §13): raised, never lowered
	account   string                // the account it is in, or ""
	senders   []string              // the sender key types it declared with its current prekey
	revocations
	acl      *protocol.ACL // its sender ACL; nil: none, which admits everyone
	messages map[string]*message
	seq      int // the number of the last message stored, which orders them
}

// revocations are what an address's identity signed about it that the server
// keeps, whether or not the address has a mailbox here.
type revocations struct {
	revoked []byte // the identity's revocation: the address is ended for good
	// The identity's revocation of its certificates, as put, and parsed.
	certList, certListSig []byte
	listed                *protocol.RevokedCertificates
}

// held is what the server keeps of an address with no mailbox here: the
// identity's document and what it signed about the address. A registration
// of the address takes them on.
type held struct {
	identity []byte
	revocations
}

// message is what the server keeps of a message: no sender (PROTOCOL.md
// §13).
type message struct {
	ciphertext []byte
	receivedAt time.Time
	seq        int // its place in the mailbox: a list's cursor is the last one it gave
}

// New starts a server on the clock now, on a loopback port, stopped when the
// test ends: a process of its own, such as the shell client's curl, reaches it.
func New(t testing.TB, now func() time.Time) *Server {
	s, h := newServer(t, now)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	s.URL, s.srv = srv.URL, srv
	return s
}

// NewInMemory is a server on httptest's in-memory network, which Client
// reaches: one a test can run in a testing/synctest bubble, whose time is
// fake and moves only when every goroutine waits.
func NewInMemory(t testing.TB, now func() time.Time) *Server {
	s, h := newServer(t, now)
	srv := httptest.NewTestServer(t, h)
	// Its client reaches it at any address; a loopback one is a base the
	// client calls over plain HTTP.
	s.URL, s.srv = "http://127.0.0.1", srv
	return s
}

// Client is the client that reaches a server NewInMemory made.
func (s *Server) Client() *http.Client { return s.srv.Client() }

// newServer is a server on the clock now, and the handler that serves it.
func newServer(t testing.TB, now func() time.Time) (*Server, http.Handler) {
	s := &Server{now: now, mailboxes: map[protocol.Address]*mailbox{}, held: map[protocol.Address]*held{}, keys: map[string]string{}, page: MaxPage, hold: MaxHold,
		policy: protocol.ServerDocument{Deprecations: []protocol.Scheduled{}, Sunsets: []protocol.Scheduled{}, Capabilities: []protocol.Capability{}, MaxCertificateLifetime: MaxCertificateLifetime}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+protocol.DocumentPath+"{$}", s.document)
	mux.HandleFunc("GET /v1/{addr}", s.getMailbox)
	mux.HandleFunc("PUT /v1/{addr}", s.register)
	mux.HandleFunc("POST /v1/{addr}/messages", s.send)
	mux.HandleFunc("PUT /v1/{addr}/prekey", s.newPrekey)
	mux.HandleFunc("PUT /v1/{addr}/revocations", s.revoke)
	mux.HandleFunc("GET /v1/{addr}/revocations", s.getRevocations)
	mux.HandleFunc("GET /v1/{addr}/messages", s.owner(s.list))
	mux.HandleFunc("GET /v1/{addr}/messages/{id}", s.owner(s.fetch))
	mux.HandleFunc("DELETE /v1/{addr}/messages/{id}", s.owner(s.ack))
	mux.HandleFunc("PUT /v1/{addr}/account", s.owner(s.adopt))
	mux.HandleFunc("DELETE /v1/{addr}/account", s.owner(s.leave))
	mux.HandleFunc("PUT /v1/{addr}/acl", s.owner(s.putACL))
	mux.HandleFunc("GET /v1/{addr}/acl", s.owner(s.getACL))
	// What the fake answers is held to the API's description, before a
	// test's middleware forges anything.
	api := apitest.Handler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", s.now().UTC().Format(http.TimeFormat))
		w.Header().Set("Cache-Control", "no-store")
		if s.versioned(w, r) {
			mux.ServeHTTP(w, r)
		}
	}))
	return s, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dated by the server's own clock, which a test sets: a client
		// compares an answer's Date with its clock when a pass is refused.
		w.Header().Set("Date", s.now().UTC().Format(http.TimeFormat))
		s.mu.Lock()
		s.log = append(s.log, Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Pass: r.Header.Get("Authorization") != "", Version: r.Header.Get(protocol.VersionHeader)})
		m := s.middle
		s.mu.Unlock()
		if m != nil {
			m(w, r, api)
			return
		}
		api.ServeHTTP(w, r)
	})
}

// SetPolicy sets the server's version policy, which GET /v1/ answers, and
// by which every answer under /v1/ carries Deprecation and Sunset for a
// request whose version a deprecation or a sunset covers, and a request whose version is retired is answered 410
// version_retired before anything else (PROTOCOL.md §11.17, §11.4 rule 0),
// as a server does. Until a test sets one, the policy is empty: no floor, no
// sunset, no latest version, and a certificate taken for up to
// MaxCertificateLifetime; a d that names no maximum keeps that one.
func (s *Server) SetPolicy(d protocol.ServerDocument) {
	if d.MaxCertificateLifetime == 0 {
		d.MaxCertificateLifetime = MaxCertificateLifetime
	}
	if d.Deprecations == nil {
		d.Deprecations = []protocol.Scheduled{}
	}
	if d.Sunsets == nil {
		d.Sunsets = []protocol.Scheduled{}
	}
	if d.Capabilities == nil {
		d.Capabilities = []protocol.Capability{}
	}
	s.mu.Lock()
	s.policy = d
	s.mu.Unlock()
}

// versioned puts what the policy says of the request's version on its
// answer: Deprecation where a deprecation covers it, Sunset where a sunset
// does, and 410 version_retired, with
// min_version where there is a floor, where it is retired at the server's
// clock, but on GET /v1/, which takes every version. It reports whether the
// request goes on.
func (s *Server) versioned(w http.ResponseWriter, r *http.Request) bool {
	s.mu.Lock()
	d := s.policy
	s.mu.Unlock()
	v := protocol.RequestVersion(r.Header.Get(protocol.VersionHeader))
	if at, ok := d.DeprecationFor(v); ok {
		w.Header().Set(protocol.DeprecationHeader, protocol.FormatDeprecation(at))
	}
	if at, ok := d.SunsetFor(v); ok {
		w.Header().Set(protocol.SunsetHeader, protocol.FormatSunset(at))
	}
	if r.URL.Path == protocol.DocumentPath || !d.Retired(v, s.now()) {
		return true
	}
	problem(w, protocol.CodeVersionRetired, "this server no longer takes this client's version: upgrade", func(p *protocol.Problem) { p.MinVersion = d.MinVersion })
	return false
}

// document answers GET /v1/: the server's version policy and the
// capabilities it serves (PROTOCOL.md §11.18).
func (s *Server) document(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	d := s.policy
	s.mu.Unlock()
	WriteJSON(w, http.StatusOK, d)
}

// MaxCertificateLifetime is the longest certificate the server takes until a
// test sets another (SetPolicy), in seconds: 45 days and an hour, a
// server's default.
const MaxCertificateLifetime = uint64((45*24*time.Hour + time.Hour) / time.Second)

// KeptUntil is the date the server keeps mailbox a until (PROTOCOL.md §13):
// the latest of its prekey's not_after plus the TTL and the end of any
// certificate it took, raised and never lowered; zero for none here.
func (s *Server) KeptUntil(a protocol.Address) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.mailboxes[a]; b != nil {
		return b.keep
	}
	return time.Time{}
}

// Close stops the server for good, as one that is gone: whoever calls it
// gets no answer at all.
func (s *Server) Close() { s.srv.Close() }

// SetMiddle puts m between the clients and the server, or removes it if m is
// nil. It sees every request, and calls next to let the server answer.
func (s *Server) SetMiddle(m func(w http.ResponseWriter, r *http.Request, next http.Handler)) {
	s.mu.Lock()
	s.middle = m
	s.mu.Unlock()
}

// Requests returns every call the server has been sent, oldest first.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.log)
}

// MaxPage is the most messages a list's page holds (PROTOCOL.md §11.11).
const MaxPage = 50

// SetPage sets the most messages a list's page holds, MaxPage until a test
// sets another.
func (s *Server) SetPage(n int) {
	s.mu.Lock()
	s.page = n
	s.mu.Unlock()
}

// Count returns how many messages a mailbox holds.
func (s *Server) Count(a protocol.Address) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.mailboxes[a]; b != nil {
		return len(b.messages)
	}
	return 0
}

// Forget forgets mailbox a, as a server does once its record's expiry has
// passed (PROTOCOL.md §13): what its identity revoked is kept, and nothing
// else.
func (s *Server) Forget(a protocol.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.mailboxes[a]
	if b == nil {
		return
	}
	delete(s.mailboxes, a)
	if b.revoked != nil || b.listed != nil {
		s.held[a] = &held{identity: b.identity, revocations: b.revocations}
	}
}

// Prekey returns a mailbox's current prekey statement and its signature, as
// served.
func (s *Server) Prekey(a protocol.Address) (statement, signature []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.mailboxes[a]
	return b.statement, b.signature
}

// Inject stores a message in a mailbox under id, as only the operator can: no
// check at all.
func (s *Server) Inject(to protocol.Address, id string, ciphertext []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.mailboxes[to]
	b.seq++
	b.messages[id] = &message{ciphertext: ciphertext, receivedAt: s.now(), seq: b.seq}
	b.changed()
}

// WriteJSON writes v as a JSON response, as the server does: a middleware
// forging an answer uses it.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// problem answers with an error body; each of with sets a member it carries.
func problem(w http.ResponseWriter, code protocol.Code, detail string, with ...func(*protocol.Problem)) {
	w.Header().Set("Content-Type", protocol.ProblemContentType)
	if code.Status() == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", protocol.PassScheme)
	}
	w.WriteHeader(code.Status())
	p := protocol.Problem{Type: code.TypeURI(), Title: code.Title(), Status: int64(code.Status()), Code: code, Detail: detail}
	for _, set := range with {
		set(&p)
	}
	_ = json.NewEncoder(w).Encode(p)
}

// revoked answers that an address is revoked, carrying the record the
// server holds of it, as every 410 revoked does (PROTOCOL.md §11.3).
func revoked(w http.ResponseWriter, identity []byte, k *revocations, detail string) {
	rec := &protocol.Revocations{Identity: identity, Revocation: k.revoked, RevokedCertificates: k.certList, RevokedCertificatesSignature: k.certListSig}
	problem(w, protocol.CodeRevoked, detail, func(p *protocol.Problem) { p.Record = rec })
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		problem(w, protocol.CodeBadRequest, err.Error())
		return false
	}
	return true
}

func pathAddr(w http.ResponseWriter, r *http.Request) (protocol.Address, bool) {
	a, err := protocol.ParseAddress(r.PathValue("addr"))
	if err != nil {
		problem(w, protocol.CodeBadAddress, "not an address")
		return a, false
	}
	return a, true
}

// verifyPrekey checks a statement against the mailbox's identity, and returns
// its signer, or the code its refusal is answered with, as dromas-server
// answers it (PROTOCOL.md §11.7, step 6): prekey_time where the refusal is
// for a time (a certificate that has not begun or has ended, at this clock,
// or a statement that has ended or ends too far ahead), and bad_key where it
// is not. A certificate that runs longer than the server's maximum is
// certificate_too_long, unless it is current's, the certificate of the
// mailbox's current statement: the maximum binds a certificate when it is
// first taken.
func (s *Server) verifyPrekey(identity, statement, signature []byte, current []byte) (*protocol.Prekey, *protocol.Signer, protocol.Code, error) {
	id, err := protocol.ParseIdentity(identity)
	if err != nil {
		return nil, nil, protocol.CodeBadKey, err
	}
	p, by, err := protocol.VerifyPrekey(id, statement, signature, s.now())
	switch {
	case errors.Is(err, protocol.ErrCertificateTime):
		return nil, nil, protocol.CodePrekeyTime, err
	case err != nil:
		return nil, nil, protocol.CodeBadKey, err
	}
	if err := p.CheckLifetime(s.now()); err != nil {
		return nil, nil, protocol.CodePrekeyTime, err
	}
	if c := by.Certificate(); c != nil && !bytes.Equal(c.Marshal(), current) {
		s.mu.Lock()
		most := s.policy.MaxCertificateLifetime
		s.mu.Unlock()
		if uint64(c.Lifetime()/time.Second) > most {
			return nil, nil, protocol.CodeCertificateTooLong, errors.New("the certificate runs longer than this server takes")
		}
	}
	return p, by, "", nil
}

// refuseStatement writes a statement's refusal, carrying the server's
// maximum on certificate_too_long.
func (s *Server) refuseStatement(w http.ResponseWriter, c protocol.Code, err error) {
	s.mu.Lock()
	most := s.policy.MaxCertificateLifetime
	s.mu.Unlock()
	problem(w, c, err.Error(), func(p *protocol.Problem) {
		if c == protocol.CodeCertificateTooLong {
			p.MaxCertificateLifetime = &most
		}
	})
}

// keyOf is the wire bytes of the key a signer of the identity signs with:
// the identity's key, or the certificate.
func keyOf(identity []byte, by *protocol.Signer) []byte {
	if c := by.Certificate(); c != nil {
		return c.Marshal()
	}
	id, err := protocol.ParseIdentity(identity)
	if err != nil {
		return nil
	}
	return id.PublicKey().Marshal()
}

// moded holds a statement's signer to the address's mode, by the revocation
// of its certificates listed, nil for none (PROTOCOL.md §5, §11.7 step 6):
// a certificate in identity mode is 409 identity_mode, and a signer at or
// below the revocation, the identity among them, 401 certificate_revoked.
// It writes the refusal and reports true if refused.
func moded(w http.ResponseWriter, listed *protocol.RevokedCertificates, by *protocol.Signer) bool {
	switch err := protocol.Admits(listed, by); {
	case errors.Is(err, protocol.ErrIdentityMode):
		problem(w, protocol.CodeIdentityMode, "this address is in identity mode: publish a revocation of certificates first")
		return true
	case err != nil:
		problem(w, protocol.CodeCertificateRevoked, "the statement's signer is one this address's identity revoked")
		return true
	}
	return false
}

// pass checks a call's pass: it is the pass of the mailbox whose identity
// document is given, made for this server as the caller named it, and signed
// by the key whose wire bytes are under, by the signer under is (PROTOCOL.md
// §8). It writes the refusal and reports false if not: an identity pass where
// the server holds a revocation of the address's certificates is
// certificate_revoked, and any other signer certificate_not_current, naming
// the certificate under where it is one.
func (s *Server) pass(w http.ResponseWriter, r *http.Request, identity []byte, under *protocol.Signer, listed *protocol.RevokedCertificates) bool {
	p, err := protocol.ParsePass(r.Header.Get("Authorization"))
	if err != nil {
		problem(w, protocol.CodeUnauthorized, "no pass, or not a pass")
		return false
	}
	id, err := protocol.ParseIdentity(identity)
	if err != nil {
		problem(w, protocol.CodeUnauthorized, "no identity to check the pass against")
		return false
	}
	// Run out, or running out too far ahead: either way the mailbox signs another.
	if p.NotAfter.After(s.now().Add(protocol.MaxPassLifetime)) {
		problem(w, protocol.CodePassExpired, "the pass runs out too far ahead")
		return false
	}
	by, err := p.Verify(id, r.Host, s.now())
	switch {
	case errors.Is(err, protocol.ErrPassExpired), errors.Is(err, protocol.ErrCertificateTime):
		problem(w, protocol.CodePassExpired, "the pass has run out, or its certificate is not valid now")
		return false
	case err != nil:
		problem(w, protocol.CodeUnauthorized, "not this mailbox's pass for this server")
		return false
	case bytes.Equal(keyOf(identity, by), keyOf(identity, under)):
		return true
	case by.Identity() && listed != nil:
		problem(w, protocol.CodeCertificateRevoked, "the pass is the identity's, and this address is in working-key mode")
		return false
	}
	problem(w, protocol.CodeCertificateNotCurrent, "the pass is not by the signer this call takes a pass by", func(p *protocol.Problem) {
		if c := under.Certificate(); c != nil {
			n := c.Serial()
			p.CertificateSerial = &n
		}
	})
	return false
}

// kept raises the date b is kept until (PROTOCOL.md §13) to its prekey's
// not_after plus the TTL, and to the end of the certificate its statement is
// under, where either is later: never lowered.
func (b *mailbox) kept() {
	until := b.prekey.NotAfter.Add(protocol.TTL)
	if c := b.signer.Certificate(); c != nil && c.NotAfter().After(until) {
		until = c.NotAfter()
	}
	if until.After(b.keep) {
		b.keep = until
	}
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	var req protocol.RegisterRequest
	if !ok || !decode(w, r, &req) {
		return
	}
	if protocol.AddressOf(req.Identity) != a {
		problem(w, protocol.CodeIdentityMismatch, "the identity does not hash to the address")
		return
	}
	s.mu.Lock()
	var current []byte
	if b := s.mailboxes[a]; b != nil {
		current = b.key
	}
	s.mu.Unlock()
	p, by, refusal, err := s.verifyPrekey(req.Identity, req.Prekey, req.PrekeySignature, current)
	if err != nil {
		s.refuseStatement(w, refusal, err)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.mailboxes[a]; b != nil {
		if b.revoked != nil {
			revoked(w, b.identity, &b.revocations, "this mailbox is revoked")
			return
		}
		if bytes.Equal(b.statement, req.Prekey) && bytes.Equal(b.signature, req.PrekeySignature) {
			if !b.current() { // nothing by a revoked signer is taken, an identical retry included
				problem(w, protocol.CodeCertificateRevoked, "the statement's signer is one this mailbox's identity revoked")
				return
			}
			if s.pass(w, r, req.Identity, b.signer, b.listed) {
				WriteJSON(w, http.StatusOK, struct{}{})
			}
			return
		}
		problem(w, protocol.CodeConflict, "registered with another prekey")
		return
	}
	// What the identity signed about the address before it had a mailbox here
	// holds the registration to it: none of a revoked address, and its mode,
	// which comes before the pass (PROTOCOL.md §11.4 rule 4).
	var kept revocations
	if h := s.held[a]; h != nil {
		if h.revoked != nil {
			revoked(w, h.identity, &h.revocations, "this address is revoked")
			return
		}
		kept = h.revocations
	}
	if moded(w, kept.listed, by) {
		return
	}
	// A registration carries a pass by the signer of the statement it brings:
	// that is what shows a live holder of the key.
	if !s.pass(w, r, req.Identity, by, kept.listed) {
		return
	}
	delete(s.held, a)
	b := &mailbox{identity: req.Identity, statement: req.Prekey, signature: req.PrekeySignature, prekey: p, signer: by, key: keyOf(req.Identity, by),
		senders: req.SenderKeyTypes, revocations: kept, messages: map[string]*message{}}
	b.kept()
	s.mailboxes[a] = b
	WriteJSON(w, http.StatusCreated, struct{}{})
}

// getMailbox is the one read of a mailbox: its identity, its current prekey
// statement, and the revocation of its certificates held; a revoked mailbox is
// 410 with its record.
func (s *Server) getMailbox(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.mailboxes[a]
	if h := s.held[a]; b == nil && h != nil && h.revoked != nil {
		// A revoked address is read as its record, mailbox or none.
		revoked(w, h.identity, &h.revocations, "this address is revoked")
		return
	}
	if b != nil && b.revoked != nil {
		revoked(w, b.identity, &b.revocations, "this mailbox is revoked")
		return
	}
	if b == nil {
		problem(w, protocol.CodeNoSuchMailbox, "no mailbox has this address")
		return
	}
	WriteJSON(w, http.StatusOK, protocol.MailboxResponse{
		Identity: b.identity, Prekey: b.statement, PrekeySignature: b.signature, SenderKeyTypes: b.senders,
		RevokedCertificates: b.certList, RevokedCertificatesSignature: b.certListSig,
	})
}

// revoke takes a revocation of an address, whether or not it has a mailbox here:
// the identity's own signature over the fixed statement, with no pass. A mailbox
// is gone for good and its messages with it. A second one changes nothing.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	var req protocol.Revocations
	if !ok || !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.mailboxes[a]
	h := s.held[a]
	var kept *revocations
	var identity []byte
	switch {
	case b != nil:
		kept, identity = &b.revocations, b.identity
	case h != nil:
		kept, identity = &h.revocations, h.identity
	default:
		h = &held{identity: req.Identity}
		kept = &h.revocations
	}
	// A revoked address takes nothing more, and nothing sent for it is
	// checked (PROTOCOL.md §11.15): it is answered with the record held.
	if kept.revoked != nil {
		revoked(w, identity, kept, "this address is revoked")
		return
	}
	// A revocation of certificates: the address goes on. The highest serial
	// it runs through stands. Beside a revocation of the address, a lower one
	// changes nothing, and the address's is kept (PROTOCOL.md §11.15).
	if len(req.RevokedCertificates) > 0 {
		certs, err := protocol.VerifyRevokedCertificates(a, req.Identity, req.RevokedCertificates, req.RevokedCertificatesSignature)
		switch {
		case err != nil:
			problem(w, protocol.CodeBadRevocation, "not a revocation of this address's certificates")
			return
		case kept.listed != nil && bytes.Equal(kept.certList, req.RevokedCertificates):
		case kept.listed != nil && certs.Through <= kept.listed.Through && len(req.Revocation) > 0:
		case kept.listed != nil && certs.Through <= kept.listed.Through:
			problem(w, protocol.CodeConflict, "a revocation through that serial or a higher one is held")
			return
		default:
			kept.certList, kept.certListSig, kept.listed = req.RevokedCertificates, req.RevokedCertificatesSignature, certs
		}
		if len(req.Revocation) == 0 {
			if b == nil {
				s.held[a] = h
			}
			WriteJSON(w, http.StatusOK, struct{}{})
			return
		}
	}
	if _, err := protocol.VerifyRevocation(a, req.Identity, req.Revocation); err != nil {
		problem(w, protocol.CodeBadRevocation, "not a revocation of this address")
		return
	}
	kept.revoked = req.Revocation
	if b != nil {
		b.messages = map[string]*message{}
	} else {
		s.held[a] = h
	}
	WriteJSON(w, http.StatusCreated, struct{}{})
}

// getRevocations is what the server keeps of the address, with or without a
// mailbox here, or not_revoked.
func (s *Server) getRevocations(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var identity []byte
	var kept *revocations
	if b := s.mailboxes[a]; b != nil {
		identity, kept = b.identity, &b.revocations
	} else if h := s.held[a]; h != nil {
		identity, kept = h.identity, &h.revocations
	}
	if kept == nil || kept.revoked == nil && kept.certList == nil {
		problem(w, protocol.CodeNotRevoked, "no revocation of this address is held here")
		return
	}
	WriteJSON(w, http.StatusOK, &protocol.Revocations{Identity: identity, Revocation: kept.revoked, RevokedCertificates: kept.certList, RevokedCertificatesSignature: kept.certListSig})
}

// current reports whether the mailbox's current signer is one its identity
// has not revoked: a certificate above its revocation of certificates, or the
// identity while there is none. A mailbox whose signer is revoked has no pass
// the server takes and no prekey a sender may use, until it publishes by a
// new one.
func (b *mailbox) current() bool { return protocol.Admits(b.listed, b.signer) == nil }

func (s *Server) newPrekey(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	var req protocol.PrekeyRequest
	if !ok || !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	b := s.mailboxes[a]
	s.mu.Unlock()
	if b == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if h := s.held[a]; h != nil && h.revoked != nil {
			revoked(w, h.identity, &h.revocations, "this address is revoked")
			return
		}
		problem(w, protocol.CodeNoSuchMailbox, "no mailbox has this address")
		return
	}
	s.mu.Lock()
	identity, current := b.identity, b.key
	s.mu.Unlock()
	p, by, refusal, err := s.verifyPrekey(identity, req.Prekey, req.PrekeySignature, current)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mailboxes[a] != b {
		problem(w, protocol.CodeMailboxChanged, "the mailbox changed while the request was handled")
		return
	}
	if b.revoked != nil {
		revoked(w, b.identity, &b.revocations, "this mailbox is revoked")
		return
	}
	if err != nil {
		s.refuseStatement(w, refusal, err)
		return
	}
	// The mode comes before the pass (PROTOCOL.md §11.4 rule 4).
	if moded(w, b.listed, by) || order(w, b, p, by) {
		return
	}
	// A prekey upload carries a pass by the signer of the statement it
	// brings: that is how a mailbox moves to a new signer.
	if !s.pass(w, r, b.identity, by, b.listed) {
		return
	}
	b.statement, b.signature, b.prekey, b.signer, b.key, b.senders = req.Prekey, req.PrekeySignature, p, by, keyOf(b.identity, by), req.SenderKeyTypes
	b.kept()
	WriteJSON(w, http.StatusOK, struct{}{})
}

// order holds a statement to mailbox b's record, as a renewal is held: later
// by (c, p), by a signer of a higher rank at any serial, or by the current
// signer at a higher serial (PROTOCOL.md §5.3, §11.9). It writes the refusal
// and reports true if not.
func order(w http.ResponseWriter, b *mailbox, p *protocol.Prekey, by *protocol.Signer) bool {
	switch {
	case by.Rank() < b.signer.Rank(), by.Rank() == b.signer.Rank() && !bytes.Equal(keyOf(b.identity, by), b.key):
		problem(w, protocol.CodeCertificateNotCurrent, "the signer is older than the mailbox's current one", func(pr *protocol.Problem) {
			if c := b.signer.Certificate(); c != nil {
				n := c.Serial()
				pr.CertificateSerial = &n
			}
		})
		return true
	case by.Rank() == b.signer.Rank() && p.Serial <= b.prekey.Serial:
		problem(w, protocol.CodeConflict, "the serial must be higher")
		return true
	}
	return false
}

// maxCiphertext is the most of a send's body the fake reads: the body is the
// ciphertext itself, at most protocol.MaxCiphertext, and no message a test
// sends comes near it.
const maxCiphertext = protocol.MaxCiphertext

// sendQuery reads a send's query: its statement, once, and nothing else.
// It writes the refusal, naming the parameter, and reports false if not.
func sendQuery(w http.ResponseWriter, r *http.Request) (protocol.SendQuery, bool) {
	q, err := protocol.ParseSendQuery(r.URL.RawQuery)
	if err != nil {
		var qe *protocol.QueryError
		param := ""
		if errors.As(err, &qe) {
			param = qe.Param
		}
		problem(w, protocol.CodeBadRequest, "not a send's query", func(p *protocol.Problem) { p.Member = param })
		return q, false
	}
	return q, true
}

func (s *Server) send(w http.ResponseWriter, r *http.Request) {
	to, ok := pathAddr(w, r)
	if !ok {
		return
	}
	q, ok := sendQuery(w, r)
	if !ok {
		return
	}
	// The body is the ciphertext, whatever its Content-Type says.
	ct, err := io.ReadAll(io.LimitReader(r.Body, maxCiphertext))
	if err != nil {
		problem(w, protocol.CodeBadRequest, "the body could not be read")
		return
	}
	// The sender is the mailbox the pass names. The message's signature is inside
	// the ciphertext, where this server cannot see it.
	p, err := protocol.ParsePass(r.Header.Get("Authorization"))
	if err != nil {
		problem(w, protocol.CodeUnauthorized, "no pass, or not a pass")
		return
	}
	from := p.Address
	s.mu.Lock()
	defer s.mu.Unlock()
	rcpt, sender := s.mailboxes[to], s.mailboxes[from]
	if sender == nil {
		problem(w, protocol.CodeUnknownSender, "the sender is not registered")
		return
	}
	if sender.revoked != nil {
		problem(w, protocol.CodeSenderRevoked, "the sending mailbox is revoked")
		return
	}
	if !sender.current() {
		problem(w, protocol.CodeCertificateRevoked, "the sender's signer is one its identity revoked")
		return
	}
	if !s.pass(w, r, sender.identity, sender.signer, sender.listed) {
		return
	}
	switch {
	case rcpt == nil:
		problem(w, protocol.CodeNoSuchMailbox, "no mailbox has this address")
		return
	case rcpt.revoked != nil:
		revoked(w, rcpt.identity, &rcpt.revocations, "this mailbox is revoked")
		return
	case !rcpt.current():
		problem(w, protocol.CodePrekeyExpired, "the mailbox must publish a new prekey: its current one is under a revoked certificate")
		return
	case q.Statement != protocol.StatementHash(rcpt.statement):
		problem(w, protocol.CodeStalePrekey, "the send names another statement than the mailbox's current one")
		return
	}
	// Dedupe while the message is live, from any sender: an ack leaves
	// nothing of it (PROTOCOL.md §11.10, step 6).
	h := sha256.Sum256(ct)
	key := hex.EncodeToString(h[:])
	if m := rcpt.messages[key]; m != nil {
		WriteJSON(w, http.StatusOK, receipt(key, m))
		return
	}
	if !rcpt.acl.Admits(from) {
		problem(w, protocol.CodeSenderNotAllowed, "the mailbox's ACL does not admit the sender")
		return
	}
	rcpt.seq++
	defer rcpt.changed()
	m := &message{ciphertext: ct, receivedAt: s.now(), seq: rcpt.seq}
	rcpt.messages[key] = m
	w.Header().Set("Location", r.URL.Path+"/"+key)
	WriteJSON(w, http.StatusCreated, receipt(key, m))
}

// Take answers a post as a server that kept it would, and keeps nothing: a
// receipt for the ciphertext posted. It is for a test that plays an
// operator who swallows messages, which a client cannot tell from a delivery.
func Take(w http.ResponseWriter, r *http.Request) { TakeAs(w, r, nil) }

// TakeAs is Take, with the receipt changed by edit before it is written.
func TakeAs(w http.ResponseWriter, r *http.Request, edit func(*protocol.Receipt)) {
	if _, ok := sendQuery(w, r); !ok {
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, maxCiphertext))
	h := sha256.Sum256(body)
	now := time.Now()
	rec := protocol.Receipt{ID: hex.EncodeToString(h[:]), ReceivedAt: formatTime(now), ExpiresAt: formatTime(now.Add(protocol.Retention))}
	if edit != nil {
		edit(&rec)
	}
	WriteJSON(w, http.StatusCreated, rec)
}

func receipt(id string, m *message) protocol.Receipt {
	return protocol.Receipt{ID: id, ReceivedAt: formatTime(m.receivedAt), ExpiresAt: formatTime(m.receivedAt.Add(protocol.Retention))}
}

func formatTime(t time.Time) string { return t.UTC().Format(protocol.TimeLayout) }

// owner authenticates an owner call: a pass of the mailbox, under its current
// certificate, or 401.
func (s *Server) owner(h func(http.ResponseWriter, *http.Request, *mailbox)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := pathAddr(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		b := s.mailboxes[a]
		if b != nil && b.revoked != nil {
			revoked(w, b.identity, &b.revocations, "this mailbox is revoked")
			return
		}
		if b == nil {
			problem(w, protocol.CodeNoSuchMailbox, "no mailbox has this address")
			return
		}
		if !b.current() {
			problem(w, protocol.CodeCertificateRevoked, "the pass is under a certificate the mailbox's identity revoked")
			return
		}
		if s.pass(w, r, b.identity, b.signer, b.listed) {
			h(w, r, b)
		}
	}
}

// listQuery reads a list's query: none, a cursor this server made, or a
// wait, each once and never both. It writes the refusal, naming the
// parameter, and reports false if not.
func listQuery(w http.ResponseWriter, r *http.Request) (after int, wait time.Duration, ok bool) {
	if r.URL.RawQuery == "" {
		return 0, 0, true
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	for name, v := range q {
		if name != "cursor" && name != "wait" || len(v) != 1 {
			problem(w, protocol.CodeBadRequest, "a list takes a cursor or a wait, once", func(p *protocol.Problem) { p.Member = name })
			return 0, 0, false
		}
	}
	if err != nil {
		problem(w, protocol.CodeBadRequest, "not a query", func(p *protocol.Problem) { p.Member = "cursor" })
		return 0, 0, false
	}
	if v, ok := q["wait"]; ok {
		n, err := protocol.Wait(v[0])
		if err != nil || len(q) > 1 {
			problem(w, protocol.CodeBadRequest, "a wait is digits, on the first page", func(p *protocol.Problem) { p.Member = "wait" })
			return 0, 0, false
		}
		held := MaxHold
		if n < uint64(MaxHold/time.Second) {
			held = time.Duration(n) * time.Second
		}
		return 0, held, true
	}
	c := q["cursor"]
	if protocol.CheckCursor(c[0]) != nil {
		problem(w, protocol.CodeBadRequest, "not a cursor", func(p *protocol.Problem) { p.Member = "cursor" })
		return 0, 0, false
	}
	after, err = strconv.Atoi(c[0])
	if err != nil || after < 1 || strconv.Itoa(after) != c[0] {
		problem(w, protocol.CodeBadRequest, "not a cursor this server made", func(p *protocol.Problem) { p.Member = "cursor" })
		return 0, 0, false
	}
	return after, 0, true
}

// MaxHold is the longest a fake server holds a list, unless SetHold says
// otherwise.
const MaxHold = 5 * time.Minute

// SetHold sets the longest this server holds a list (PROTOCOL.md §11.11).
func (s *Server) SetHold(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hold = d
}

// changed wakes every list held on the mailbox: its messages changed.
func (b *mailbox) changed() {
	if b.wake != nil {
		close(b.wake)
		b.wake = nil
	}
}

// woken is closed at the mailbox's next change (changed).
func (b *mailbox) woken() <-chan struct{} {
	if b.wake == nil {
		b.wake = make(chan struct{})
	}
	return b.wake
}

// list answers with a page of the messages after the cursor, oldest first
// (PROTOCOL.md §11.11). A first page has an ETag, the SHA-256 of its JSON, and
// is 412 to an If-Match that is false and 304 to an If-None-Match that names
// it, each read as a server reads one (protocol.IfMatch,
// protocol.IfNoneMatch); a page after it carries none, so only an If-Match
// of * is true of it, and it is never 304.
func (s *Server) list(w http.ResponseWriter, r *http.Request, b *mailbox) {
	after, wait, ok := listQuery(w, r)
	if !ok {
		return
	}
	until := time.Now().Add(min(wait, s.hold))
	again := true
	for again && r.Context().Err() == nil {
		again = s.listed(w, r, b, after, time.Until(until))
	}
}

// listed answers a list once, and reports true, writing nothing, where its
// page is the one If-None-Match names and left is time still to hold it:
// it has then waited for the mailbox's next change or for left to pass, with
// the server's lock let go meanwhile, and the list is to be answered again.
func (s *Server) listed(w http.ResponseWriter, r *http.Request, b *mailbox, after int, left time.Duration) bool {
	var ms []*message
	ids := map[*message]string{}
	for id, m := range b.messages {
		if m.seq > after {
			ms = append(ms, m)
			ids[m] = id
		}
	}
	slices.SortFunc(ms, func(x, y *message) int { return x.seq - y.seq })
	l := protocol.MessageList{Count: int64(len(b.messages)), Messages: []protocol.MessageInfo{}}
	for i, m := range ms {
		if i == s.page {
			c := strconv.Itoa(ms[i-1].seq)
			l.NextCursor = &c
			break
		}
		l.Messages = append(l.Messages, protocol.MessageInfo{ID: ids[m], Size: int64(len(m.ciphertext)),
			ReceivedAt: formatTime(m.receivedAt), ExpiresAt: formatTime(m.receivedAt.Add(protocol.Retention))})
	}
	if after > 0 {
		if !protocol.IfMatch(r.Header.Values("If-Match"), "") {
			problem(w, protocol.CodePreconditionFailed, "the If-Match is false")
			return false
		}
		WriteList(w, l)
		return false
	}
	body, _ := json.Marshal(l)
	sum := sha256.Sum256(body)
	tag := `"` + hex.EncodeToString(sum[:16]) + `"`
	if !protocol.IfMatch(r.Header.Values("If-Match"), tag) {
		problem(w, protocol.CodePreconditionFailed, "the If-Match is false")
		return false
	}
	if protocol.IfNoneMatch(r.Header.Values("If-None-Match"), tag) && left > 0 {
		woken := b.woken()
		s.mu.Unlock()
		t := time.NewTimer(left)
		select {
		case <-woken:
		case <-t.C:
		case <-r.Context().Done():
		}
		t.Stop()
		s.mu.Lock()
		return true
	}
	w.Header().Set("ETag", tag)
	if protocol.IfNoneMatch(r.Header.Values("If-None-Match"), tag) {
		w.Header().Set("Retry-After", PollInterval)
		w.WriteHeader(http.StatusNotModified)
		return false
	}
	WriteList(w, l)
	return false
}

// PollInterval is the Retry-After every list answer carries: the poll
// interval, in seconds.
const PollInterval = "60"

// WriteList writes a list answer as the server does, with its Retry-After:
// PollInterval, unless the caller set one. A middleware forging one uses it.
func WriteList(w http.ResponseWriter, l protocol.MessageList) {
	if w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", PollInterval)
	}
	WriteJSON(w, http.StatusOK, l)
}

// fetch answers a message's ciphertext, and nothing else: the list says
// when it came. A Range of one open-ended byte range that begins inside
// it is answered 206 with the bytes from there on, and any other with the
// whole body (PROTOCOL.md §11.12; protocol.RangeAsked), as dromas-server
// answers them.
func (s *Server) fetch(w http.ResponseWriter, r *http.Request, b *mailbox) {
	m := b.messages[r.PathValue("id")]
	if m == nil {
		problem(w, protocol.CodeNoSuchMessage, "acked or expired")
		return
	}
	if from, ok := protocol.RangeAsked(r.Header.Values("Range"), r.Header.Values("If-Range")); ok && from < int64(len(m.ciphertext)) {
		WritePartial(w, m.ciphertext, from)
		return
	}
	WriteCiphertext(w, m.ciphertext)
}

// WriteCiphertext writes a fetch's answer, as the server does: the
// ciphertext's bytes, with their length. A middleware forging one uses it.
func WriteCiphertext(w http.ResponseWriter, ct []byte) {
	w.Header().Set("Content-Type", protocol.CiphertextContentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(ct)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(ct)
}

// WritePartial writes a fetch's answer to a range that begins at byte from,
// below the ciphertext's length, as the server does: 206, the bytes from
// there to the end, their length, and a Content-Range that says which they
// are (protocol.ContentRange). A middleware forging one uses it.
func WritePartial(w http.ResponseWriter, ct []byte, from int64) {
	w.Header().Set("Content-Type", protocol.CiphertextContentType)
	w.Header().Set("Content-Length", strconv.FormatInt(int64(len(ct))-from, 10))
	w.Header().Set("Content-Range", protocol.ContentRange(from, int64(len(ct))))
	w.WriteHeader(http.StatusPartialContent)
	_, _ = w.Write(ct[from:])
}

// putACL replaces the mailbox's ACL whole, and deletes no messages. An If-Match is
// read as a server reads one (protocol.IfMatch), against the tag of the ACL
// held, a mailbox with none included, before the body: a false one is 412, and
// changes nothing. It answers the ACL as held, with no ETag (RFC 9110
// §9.3.4).
func (s *Server) putACL(w http.ResponseWriter, r *http.Request, b *mailbox) {
	if !protocol.IfMatch(r.Header.Values("If-Match"), aclTag(b.acl)) {
		problem(w, protocol.CodePreconditionFailed, "the If-Match is false")
		return
	}
	var d protocol.ACLDocument
	if !decode(w, r, &d) {
		return
	}
	acl, err := protocol.CheckACL(&d, 0)
	if err != nil {
		problem(w, protocol.CodeBadRequest, "not an ACL")
		return
	}
	b.acl = acl
	WriteJSON(w, http.StatusOK, acl.Document())
}

// getACL answers the ACL as held, nil for none, with its ETag, its If-Match
// and If-None-Match read as a list's (PROTOCOL.md §11.14): a false If-Match is
// 412, then an If-None-Match that names the tag is 304.
func (s *Server) getACL(w http.ResponseWriter, r *http.Request, b *mailbox) {
	tag := aclTag(b.acl)
	if !protocol.IfMatch(r.Header.Values("If-Match"), tag) {
		problem(w, protocol.CodePreconditionFailed, "the If-Match is false")
		return
	}
	w.Header().Set("ETag", tag)
	if protocol.IfNoneMatch(r.Header.Values("If-None-Match"), tag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	WriteJSON(w, http.StatusOK, b.acl.Document())
}

// aclTag is the ETag of an ACL as held, nil for none: the SHA-256 of its
// document's JSON, as a list's is of its page.
func aclTag(acl *protocol.ACL) string {
	body, _ := json.Marshal(acl.Document())
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:16]) + `"`
}

// PutACL replaces a mailbox's ACL as another writer of it does, another
// machine of the mailbox or whoever holds its pass: a test's way to change what
// the mailbox last sent.
func (s *Server) PutACL(a protocol.Address, acl *protocol.ACL) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.mailboxes[a]; b != nil {
		b.acl = acl
	}
}

// ACL returns a mailbox's sender ACL, nil if it has none.
func (s *Server) ACL(a protocol.Address) *protocol.ACL {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.mailboxes[a]; b != nil {
		return b.acl
	}
	return nil
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request, b *mailbox) {
	id := r.PathValue("id")
	if b.messages[id] == nil {
		problem(w, protocol.CodeNoSuchMessage, "acked or expired")
		return
	}
	delete(b.messages, id)
	b.changed()
	w.WriteHeader(http.StatusNoContent)
}

// AdoptKey mints an adopt key into account, good for one mailbox.
func (s *Server) AdoptKey(account string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	k := "dra1_" + hex.EncodeToString(b[:])
	s.mu.Lock()
	s.keys[k] = account
	s.mu.Unlock()
	return k
}

// Account is the account a mailbox is in, or "".
func (s *Server) Account(a protocol.Address) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.mailboxes[a]; b != nil {
		return b.account
	}
	return ""
}

func (s *Server) adopt(w http.ResponseWriter, r *http.Request, b *mailbox) {
	var req protocol.AdoptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		problem(w, protocol.CodeBadRequest, "not JSON")
		return
	}
	acc, ok := s.keys[req.Key]
	if !ok {
		problem(w, protocol.CodeAdoptKeyRefused, "not a key, or spent")
		return
	}
	delete(s.keys, req.Key)
	b.account = acc
	WriteJSON(w, http.StatusOK, protocol.AccountResponse{Account: acc})
}

func (s *Server) leave(w http.ResponseWriter, _ *http.Request, b *mailbox) {
	b.account = ""
	w.WriteHeader(http.StatusNoContent)
}
