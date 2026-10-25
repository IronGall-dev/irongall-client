// Package fakeserver is an in-memory dromas server for the client's tests:
// honest, and just enough of the API for a client to register, renew its
// prekey, send, list page by page, fetch and ack, each call carrying its
// box's pass. It is NOT the dromas.dev server, and checks little of what
// that server checks. Like every server it keeps and serves a revocation of
// any address, with a box here or none (PROTOCOL.md §11.15).
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

	srv    *httptest.Server
	now    func() time.Time
	mu     sync.Mutex
	boxes  map[protocol.Address]*box
	held   map[protocol.Address]*held // the revocations of addresses with no box here
	keys   map[string]string          // adopt key → account, each good once
	middle func(w http.ResponseWriter, r *http.Request, next http.Handler)
	page   int       // the most messages a list's page holds
	log    []Request // every call, oldest first
}

// Request is one call the server was sent, as the client sent it, before
// any middleware saw it.
type Request struct {
	Method, Path, Query string // the path and the raw query apart
	Pass                bool   // it carried an Authorization header
}

type box struct {
	identity  []byte
	statement []byte
	signature []byte
	prekey    *protocol.Prekey
	cert      *protocol.Certificate // the one the current statement is signed under: passes are taken under it only
	account   string                // the account it is in, or ""
	senders   []string              // the sender key types it declared with its current prekey
	revocations
	acl      *protocol.ACL // its sender ACL; nil: none, which admits everyone
	messages map[string]*message
	seq      int // the number of the last message stored, which orders them
}

// revocations are what an address's identity signed about it that the server
// keeps, whether or not the address has a box here.
type revocations struct {
	revoked []byte // the identity's revocation: the address is ended for good
	// The identity's revocation of its certificates, as put, and parsed.
	certList, certListSig []byte
	listed                *protocol.RevokedCertificates
}

// held is what the server keeps of an address with no box here: the
// identity's document and what it signed about the address. A registration
// of the address takes them on.
type held struct {
	identity []byte
	revocations
}

type message struct {
	from       protocol.Address
	ciphertext []byte
	receivedAt time.Time
	seq        int // its place in the box: a list's cursor is the last one it gave
}

// New starts a server on the clock now, stopped when the test ends.
func New(t testing.TB, now func() time.Time) *Server {
	s := &Server{now: now, boxes: map[protocol.Address]*box{}, held: map[protocol.Address]*held{}, keys: map[string]string{}, page: MaxPage}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/{addr}", s.getBox)
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
		mux.ServeHTTP(w, r)
	}))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dated by the server's own clock, which a test sets: a client
		// compares an answer's Date with its clock when a pass is refused.
		w.Header().Set("Date", s.now().UTC().Format(http.TimeFormat))
		s.mu.Lock()
		s.log = append(s.log, Request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Pass: r.Header.Get("Authorization") != ""})
		m := s.middle
		s.mu.Unlock()
		if m != nil {
			m(w, r, api)
			return
		}
		api.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	s.URL, s.srv = srv.URL, srv
	return s
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

// Count returns how many messages a box holds.
func (s *Server) Count(a protocol.Address) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.boxes[a]; b != nil {
		return len(b.messages)
	}
	return 0
}

// Forget forgets box a, as a server does once its record's expiry has
// passed (PROTOCOL.md §13): what its identity revoked is kept, and nothing
// else.
func (s *Server) Forget(a protocol.Address) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
	if b == nil {
		return
	}
	delete(s.boxes, a)
	if b.revoked != nil || b.listed != nil {
		s.held[a] = &held{identity: b.identity, revocations: b.revocations}
	}
}

// Prekey returns a box's current prekey statement and its signature, as
// served.
func (s *Server) Prekey(a protocol.Address) (statement, signature []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
	return b.statement, b.signature
}

// Inject stores a message in a box under id, as only the operator can: no
// check at all.
func (s *Server) Inject(to protocol.Address, id string, from protocol.Address, ciphertext []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[to]
	b.seq++
	b.messages[id] = &message{from: from, ciphertext: ciphertext, receivedAt: s.now(), seq: b.seq}
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

// verifyPrekey checks a statement against the box's identity, and returns
// the certificate it is signed under.
func (s *Server) verifyPrekey(identity, statement, signature []byte) (*protocol.Prekey, *protocol.Certificate, error) {
	id, err := protocol.ParseIdentity(identity)
	if err != nil {
		return nil, nil, err
	}
	p, cert, err := protocol.VerifyPrekey(id, statement, signature, s.now())
	if err != nil {
		return nil, nil, err
	}
	if err := p.CheckLifetime(s.now()); err != nil {
		return nil, nil, err
	}
	return p, cert, nil
}

// pass checks a call's pass: it is the pass of the box whose identity
// document is given, made for this server as the caller named it, and signed
// under the certificate under. It writes the refusal and reports false if not.
func (s *Server) pass(w http.ResponseWriter, r *http.Request, identity []byte, under *protocol.Certificate) bool {
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
	// Run out, or running out too far ahead: either way the box signs another.
	if p.NotAfter.After(s.now().Add(protocol.MaxPassLifetime)) {
		problem(w, protocol.CodePassExpired, "the pass runs out too far ahead")
		return false
	}
	cert, err := p.Verify(id, r.Host, s.now())
	switch {
	case errors.Is(err, protocol.ErrPassExpired):
		problem(w, protocol.CodePassExpired, "the pass has run out")
		return false
	case err != nil:
		problem(w, protocol.CodeUnauthorized, "not this box's pass for this server")
		return false
	case !bytes.Equal(cert.Marshal(), under.Marshal()):
		n := under.Serial()
		problem(w, protocol.CodeCertificateNotCurrent, "the pass is not under the certificate this call takes a pass under", func(p *protocol.Problem) { p.CertificateSerial = &n })
		return false
	}
	return true
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	var req protocol.RegisterRequest
	if !ok || !decode(w, r, &req) {
		return
	}
	if protocol.Address(sha256.Sum256(req.Identity)) != a {
		problem(w, protocol.CodeIdentityMismatch, "the identity does not hash to the address")
		return
	}
	p, cert, err := s.verifyPrekey(req.Identity, req.Prekey, req.PrekeySignature)
	if err != nil {
		problem(w, protocol.CodeBadKey, err.Error())
		return
	}
	// A registration carries a pass under the certificate of the statement
	// it brings: that is what shows a live holder of the working key.
	if !s.pass(w, r, req.Identity, cert) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.boxes[a]; b != nil {
		if b.revoked != nil {
			revoked(w, b.identity, &b.revocations, "this box is revoked")
			return
		}
		if bytes.Equal(b.statement, req.Prekey) && bytes.Equal(b.signature, req.PrekeySignature) {
			if !b.current() { // nothing under a revoked certificate is taken, an identical retry included
				problem(w, protocol.CodeCertificateRevoked, "the statement is signed under a certificate this box's identity revoked")
				return
			}
			WriteJSON(w, http.StatusOK, struct{}{})
			return
		}
		problem(w, protocol.CodeConflict, "registered with another prekey")
		return
	}
	// What the identity signed about the address before it had a box here
	// holds the registration to it: none of a revoked address, and none
	// under a certificate it revoked.
	var kept revocations
	if h := s.held[a]; h != nil {
		if h.revoked != nil {
			revoked(w, h.identity, &h.revocations, "this address is revoked")
			return
		}
		if h.listed != nil && h.listed.Revokes(cert.Serial()) {
			problem(w, protocol.CodeCertificateRevoked, "the statement is signed under a certificate this address's identity revoked")
			return
		}
		kept = h.revocations
		delete(s.held, a)
	}
	s.boxes[a] = &box{identity: req.Identity, statement: req.Prekey, signature: req.PrekeySignature, prekey: p, cert: cert,
		senders: req.SenderKeyTypes, revocations: kept, messages: map[string]*message{}}
	WriteJSON(w, http.StatusCreated, struct{}{})
}

// getBox is the one read of a box: its identity, its current prekey
// statement, and the revocation of its certificates held; a revoked box is
// 410 with its record.
func (s *Server) getBox(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
	if h := s.held[a]; b == nil && h != nil && h.revoked != nil {
		// A revoked address is read as its record, box or none.
		revoked(w, h.identity, &h.revocations, "this address is revoked")
		return
	}
	if b != nil && b.revoked != nil {
		revoked(w, b.identity, &b.revocations, "this box is revoked")
		return
	}
	if b == nil {
		problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
		return
	}
	WriteJSON(w, http.StatusOK, protocol.BoxResponse{
		Identity: b.identity, Prekey: b.statement, PrekeySignature: b.signature, SenderKeyTypes: b.senders,
		RevokedCertificates: b.certList, RevokedCertificatesSignature: b.certListSig,
	})
}

// revoke takes a revocation of an address, whether or not it has a box here:
// the identity's own signature over the fixed statement, with no pass. A box
// is gone for good and its mail with it. A second one changes nothing.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	var req protocol.Revocations
	if !ok || !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
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
// box here, or not_revoked.
func (s *Server) getRevocations(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var identity []byte
	var kept *revocations
	if b := s.boxes[a]; b != nil {
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

// current reports whether the box's current certificate is one its identity
// has not revoked: a box whose certificate is revoked has no pass the server
// takes and no prekey a sender may use, until it publishes under a new one.
func (b *box) current() bool { return b.listed == nil || !b.listed.Revokes(b.cert.Serial()) }

func (s *Server) newPrekey(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	var req protocol.PrekeyRequest
	if !ok || !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
	if b != nil && b.revoked != nil {
		revoked(w, b.identity, &b.revocations, "this box is revoked")
		return
	}
	if b == nil {
		problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
		return
	}
	p, cert, err := s.verifyPrekey(b.identity, req.Prekey, req.PrekeySignature)
	if err != nil {
		problem(w, protocol.CodeBadKey, err.Error())
		return
	}
	if refused := order(w, b, p, cert); refused {
		return
	}
	// A prekey upload carries a pass under the certificate of the statement
	// it brings: that is how a box moves to a new certificate.
	if !s.pass(w, r, b.identity, cert) {
		return
	}
	b.statement, b.signature, b.prekey, b.cert, b.senders = req.Prekey, req.PrekeySignature, p, cert, req.SenderKeyTypes
	WriteJSON(w, http.StatusOK, struct{}{})
}

// order holds a statement to box b's record, as a renewal is held: ordered by
// certificate first, a later one at any serial or the current one at a higher
// serial, and under no certificate the identity revoked. It writes the
// refusal and reports true if not.
func order(w http.ResponseWriter, b *box, p *protocol.Prekey, cert *protocol.Certificate) bool {
	switch {
	case cert.Serial() < b.cert.Serial(), cert.Serial() == b.cert.Serial() && !bytes.Equal(cert.Marshal(), b.cert.Marshal()):
		problem(w, protocol.CodeCertificateNotCurrent, "the certificate is older than the box's current one")
		return true
	case cert.Serial() == b.cert.Serial() && p.Serial <= b.prekey.Serial:
		problem(w, protocol.CodeConflict, "the serial must be higher")
		return true
	case b.listed != nil && b.listed.Revokes(cert.Serial()):
		problem(w, protocol.CodeCertificateRevoked, "the certificate is one the identity revoked")
		return true
	}
	return false
}

// maxCiphertext is the most of a send's body the fake reads: the body is the
// ciphertext itself, at most protocol.MaxCiphertext, and no message a test
// sends comes near it.
const maxCiphertext = protocol.MaxCiphertext

// sendQuery reads a send's query: both serials, once each, and nothing else.
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
	// The sender is the box the pass names. The message's signature is inside
	// the ciphertext, where this server cannot see it.
	p, err := protocol.ParsePass(r.Header.Get("Authorization"))
	if err != nil {
		problem(w, protocol.CodeUnauthorized, "no pass, or not a pass")
		return
	}
	from := p.Address
	s.mu.Lock()
	defer s.mu.Unlock()
	rcpt, sender := s.boxes[to], s.boxes[from]
	if sender == nil {
		problem(w, protocol.CodeUnknownSender, "the sender is not registered")
		return
	}
	if sender.revoked != nil {
		problem(w, protocol.CodeSenderRevoked, "the sending box is revoked")
		return
	}
	if !sender.current() {
		problem(w, protocol.CodeCertificateRevoked, "the pass is under a certificate the box's identity revoked")
		return
	}
	if !s.pass(w, r, sender.identity, sender.cert) {
		return
	}
	switch {
	case rcpt == nil:
		problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
		return
	case rcpt.revoked != nil:
		revoked(w, rcpt.identity, &rcpt.revocations, "this box is revoked")
		return
	case !rcpt.current():
		problem(w, protocol.CodePrekeyExpired, "the box must publish a new prekey: its current one is under a revoked certificate")
		return
	case q.PrekeySerial != rcpt.prekey.Serial, q.CertificateSerial != rcpt.cert.Serial():
		prekey, cert := rcpt.prekey.Serial, rcpt.cert.Serial()
		problem(w, protocol.CodeStalePrekey, "a newer prekey exists", func(p *protocol.Problem) {
			p.PrekeySerial, p.CertificateSerial = &prekey, &cert
		})
		return
	}
	h := sha256.Sum256(ct)
	key := hex.EncodeToString(h[:])
	if m := rcpt.messages[key]; m != nil {
		WriteJSON(w, http.StatusOK, receipt(key, m))
		return
	}
	if !rcpt.acl.Admits(from) {
		problem(w, protocol.CodeSenderNotAllowed, "the box's ACL does not admit the sender")
		return
	}
	rcpt.seq++
	m := &message{from: from, ciphertext: ct, receivedAt: s.now(), seq: rcpt.seq}
	rcpt.messages[key] = m
	w.Header().Set("Location", r.URL.Path+"/"+key)
	WriteJSON(w, http.StatusCreated, receipt(key, m))
}

// Take answers a post as a server that kept it would, and keeps nothing: a
// receipt for the ciphertext posted. It is for a test that plays an
// operator who swallows mail, which a client cannot tell from a delivery.
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

// owner authenticates an owner call: a pass of the box, under its current
// certificate, or 401.
func (s *Server) owner(h func(http.ResponseWriter, *http.Request, *box)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a, ok := pathAddr(w, r)
		if !ok {
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		b := s.boxes[a]
		if b != nil && b.revoked != nil {
			revoked(w, b.identity, &b.revocations, "this box is revoked")
			return
		}
		if b == nil {
			problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
			return
		}
		if !b.current() {
			problem(w, protocol.CodeCertificateRevoked, "the pass is under a certificate the box's identity revoked")
			return
		}
		if s.pass(w, r, b.identity, b.cert) {
			h(w, r, b)
		}
	}
}

// listQuery reads a list's query: none, or a cursor this server made, once.
// It writes the refusal, naming the parameter, and reports false if not.
func listQuery(w http.ResponseWriter, r *http.Request) (after int, ok bool) {
	if r.URL.RawQuery == "" {
		return 0, true
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	for name := range q {
		if name != "cursor" {
			problem(w, protocol.CodeBadRequest, "a list takes a cursor alone", func(p *protocol.Problem) { p.Member = name })
			return 0, false
		}
	}
	c := q["cursor"]
	if err != nil || len(c) != 1 || protocol.CheckCursor(c[0]) != nil {
		problem(w, protocol.CodeBadRequest, "not a cursor", func(p *protocol.Problem) { p.Member = "cursor" })
		return 0, false
	}
	after, err = strconv.Atoi(c[0])
	if err != nil || after < 1 || strconv.Itoa(after) != c[0] {
		problem(w, protocol.CodeBadRequest, "not a cursor this server made", func(p *protocol.Problem) { p.Member = "cursor" })
		return 0, false
	}
	return after, true
}

// list answers with a page of the messages after the cursor, oldest first
// (PROTOCOL.md §11.11). A first page has an ETag, the SHA-256 of its JSON, and
// is 412 to an If-Match that is false and 304 to an If-None-Match that names
// it, each read as a server reads one (protocol.IfMatch,
// protocol.IfNoneMatch); a page after it carries none, so only an If-Match
// of * is true of it, and it is never 304.
func (s *Server) list(w http.ResponseWriter, r *http.Request, b *box) {
	after, ok := listQuery(w, r)
	if !ok {
		return
	}
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
		l.Messages = append(l.Messages, protocol.MessageInfo{ID: ids[m], From: m.from.String(), Size: int64(len(m.ciphertext)),
			ReceivedAt: formatTime(m.receivedAt), ExpiresAt: formatTime(m.receivedAt.Add(protocol.Retention))})
	}
	if after > 0 {
		if !protocol.IfMatch(r.Header.Values("If-Match"), "") {
			problem(w, protocol.CodePreconditionFailed, "the If-Match is false")
			return
		}
		WriteList(w, l)
		return
	}
	body, _ := json.Marshal(l)
	sum := sha256.Sum256(body)
	tag := `"` + hex.EncodeToString(sum[:16]) + `"`
	if !protocol.IfMatch(r.Header.Values("If-Match"), tag) {
		problem(w, protocol.CodePreconditionFailed, "the If-Match is false")
		return
	}
	w.Header().Set("ETag", tag)
	if protocol.IfNoneMatch(r.Header.Values("If-None-Match"), tag) {
		w.Header().Set("Retry-After", PollInterval)
		w.WriteHeader(http.StatusNotModified)
		return
	}
	WriteList(w, l)
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

// fetch answers a message's ciphertext, and nothing else: the list says who
// sent it and when. A Range of one open-ended byte range that begins inside
// it is answered 206 with the bytes from there on, and any other with the
// whole body (PROTOCOL.md §11.12; protocol.RangeAsked), as dromas-server
// answers them.
func (s *Server) fetch(w http.ResponseWriter, r *http.Request, b *box) {
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

// putACL replaces the box's ACL whole, and deletes what is waiting from
// every sender its deny list matches. An If-Match is read as a server reads
// one (protocol.IfMatch), against the tag of the ACL held, a box with none
// included, before the body: a false one is 412, and changes nothing. It
// answers the ACL as held, with no ETag (RFC 9110 §9.3.4).
func (s *Server) putACL(w http.ResponseWriter, r *http.Request, b *box) {
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
	for id, m := range b.messages {
		if acl.Deny.Has(m.from) {
			delete(b.messages, id)
		}
	}
	WriteJSON(w, http.StatusOK, acl.Document())
}

// getACL answers the ACL as held, nil for none, with its ETag, its If-Match
// and If-None-Match read as a list's (PROTOCOL.md §11.14): a false If-Match is
// 412, then an If-None-Match that names the tag is 304.
func (s *Server) getACL(w http.ResponseWriter, r *http.Request, b *box) {
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

// PutACL replaces a box's ACL as another writer of it does, another
// machine of the box or whoever holds its pass, with nothing deleted: a
// test's way to change what the box last sent.
func (s *Server) PutACL(a protocol.Address, acl *protocol.ACL) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.boxes[a]; b != nil {
		b.acl = acl
	}
}

// ACL returns a box's sender ACL, nil if it has none.
func (s *Server) ACL(a protocol.Address) *protocol.ACL {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.boxes[a]; b != nil {
		return b.acl
	}
	return nil
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request, b *box) {
	id := r.PathValue("id")
	if b.messages[id] == nil {
		problem(w, protocol.CodeNoSuchMessage, "acked or expired")
		return
	}
	delete(b.messages, id)
	w.WriteHeader(http.StatusNoContent)
}

// AdoptKey mints an adopt key into account, good for one box.
func (s *Server) AdoptKey(account string) string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	k := "dra1_" + hex.EncodeToString(b[:])
	s.mu.Lock()
	s.keys[k] = account
	s.mu.Unlock()
	return k
}

// Account is the account a box is in, or "".
func (s *Server) Account(a protocol.Address) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.boxes[a]; b != nil {
		return b.account
	}
	return ""
}

func (s *Server) adopt(w http.ResponseWriter, r *http.Request, b *box) {
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

func (s *Server) leave(w http.ResponseWriter, _ *http.Request, b *box) {
	b.account = ""
	w.WriteHeader(http.StatusNoContent)
}
