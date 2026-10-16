// Package fakeserver is an in-memory irongall server for the client's tests:
// honest, and just enough of the API for a client to register, renew its
// prekey, send, list, fetch and ack, each call carrying its box's pass. It is NOT the irongall.dev server, and
// checks little of what that server checks.
//
// A test plays the hostile operator two ways: with SetMiddle, a function that
// sees every request and can rewrite it, answer it or forge the reply; and
// with the operator's own powers over storage (Inject, Count, Prekey).
// Nothing the client is told to trust comes from here: every forgery a test
// makes is one a real operator could make.
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
	"sync"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// Server is a running fake server.
type Server struct {
	URL string

	now    func() time.Time
	mu     sync.Mutex
	boxes  map[protocol.Address]*box
	keys   map[string]string // adopt key → account, each good once
	middle func(w http.ResponseWriter, r *http.Request, next http.Handler)
}

type box struct {
	identity  []byte
	statement []byte
	signature []byte
	prekey    *protocol.Prekey
	cert      *protocol.Certificate // the one the current statement is signed under: passes are taken under it only
	account   string                // the account it is in, or ""
	senders   []string              // the sender key types it declared with its current prekey
	revoked   []byte                // the identity's revocation, once the box is revoked: it is gone for good
	// The identity's revocation of its certificates, as put, and parsed.
	certList, certListSig []byte
	listed                *protocol.RevokedCertificates
	acl                   *protocol.ACL // its sender ACL; nil: none, which admits everyone
	messages              map[string]*message
	order                 []string // ids, oldest first
}

type message struct {
	from       protocol.Address
	ciphertext []byte
	receivedAt time.Time
}

// New starts a server on the clock now, stopped when the test ends.
func New(t testing.TB, now func() time.Time) *Server {
	s := &Server{now: now, boxes: map[protocol.Address]*box{}, keys: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /v1/{addr}", s.register)
	mux.HandleFunc("POST /v1/{addr}", s.send)
	mux.HandleFunc("GET /v1/{addr}/identity", s.identity)
	mux.HandleFunc("PUT /v1/{addr}/prekey", s.newPrekey)
	mux.HandleFunc("PUT /v1/{addr}/revocations", s.revoke)
	mux.HandleFunc("GET /v1/{addr}/revocations", s.revocations)
	mux.HandleFunc("GET /v1/{addr}/messages", s.owner(s.list))
	mux.HandleFunc("GET /v1/{addr}/messages/{id}", s.owner(s.fetch))
	mux.HandleFunc("DELETE /v1/{addr}/messages/{id}", s.owner(s.ack))
	mux.HandleFunc("PUT /v1/{addr}/account", s.owner(s.adopt))
	mux.HandleFunc("DELETE /v1/{addr}/account", s.owner(s.leave))
	mux.HandleFunc("PUT /v1/{addr}/acl", s.owner(s.putACL))
	mux.HandleFunc("GET /v1/{addr}/acl", s.owner(s.getACL))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Dated by the server's own clock, which a test sets: a client
		// compares an answer's Date with its clock when a pass is refused.
		w.Header().Set("Date", s.now().UTC().Format(http.TimeFormat))
		s.mu.Lock()
		m := s.middle
		s.mu.Unlock()
		if m != nil {
			m(w, r, mux)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	s.URL = srv.URL
	return s
}

// SetMiddle puts m between the clients and the server, or removes it if m is
// nil. It sees every request, and calls next to let the server answer.
func (s *Server) SetMiddle(m func(w http.ResponseWriter, r *http.Request, next http.Handler)) {
	s.mu.Lock()
	s.middle = m
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
	b.messages[id] = &message{from: from, ciphertext: ciphertext, receivedAt: s.now()}
	b.order = append(b.order, id)
}

// WriteJSON writes v as a JSON response, as the server does: a middleware
// forging an answer uses it.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func problem(w http.ResponseWriter, code protocol.Code, detail string) {
	w.Header().Set("Content-Type", protocol.ProblemContentType)
	w.WriteHeader(code.Status())
	_ = json.NewEncoder(w).Encode(protocol.Problem{Type: code.TypeURI(), Status: int64(code.Status()), Code: code, Detail: detail})
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
		problem(w, protocol.CodeCertificateNotCurrent, "the pass is not under the box's current certificate")
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
			problem(w, protocol.CodeRevoked, "this box is revoked")
			return
		}
		if bytes.Equal(b.statement, req.Prekey) && bytes.Equal(b.signature, req.PrekeySignature) {
			WriteJSON(w, http.StatusOK, struct{}{})
			return
		}
		problem(w, protocol.CodeConflict, "registered with another prekey")
		return
	}
	s.boxes[a] = &box{identity: req.Identity, statement: req.Prekey, signature: req.PrekeySignature, prekey: p, cert: cert,
		senders: req.SenderKeyTypes, messages: map[string]*message{}}
	WriteJSON(w, http.StatusCreated, struct{}{})
}

func (s *Server) identity(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
	if b == nil {
		problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
		return
	}
	if b.revoked != nil {
		problem(w, protocol.CodeRevoked, "this box is revoked")
		return
	}
	WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.identity, Prekey: b.statement, PrekeySignature: b.signature, SenderKeyTypes: b.senders})
}

// revoke takes a revocation of a box this server has: the identity's own
// signature over the fixed statement, with no pass. The box is gone for good
// and its mail with it. A second one changes nothing.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	var req protocol.Revocations
	if !ok || !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
	if b == nil {
		problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
		return
	}
	// A revoked box takes nothing more, and nothing sent for it is checked
	// (PROTOCOL.md §6.3).
	if b.revoked != nil {
		problem(w, protocol.CodeRevoked, "this box is revoked")
		return
	}
	// A revocation of certificates: the address goes on. The highest serial
	// it runs through stands.
	if len(req.RevokedCertificates) > 0 {
		certs, err := protocol.VerifyRevokedCertificates(a, req.Identity, req.RevokedCertificates, req.RevokedCertificatesSignature)
		switch {
		case err != nil:
			problem(w, protocol.CodeBadRevocation, "not a revocation of this address's certificates")
			return
		case b.listed != nil && bytes.Equal(b.certList, req.RevokedCertificates):
		case b.listed != nil && certs.Through <= b.listed.Through:
			problem(w, protocol.CodeConflict, "a revocation through that serial or a higher one is held")
			return
		default:
			b.certList, b.certListSig, b.listed = req.RevokedCertificates, req.RevokedCertificatesSignature, certs
		}
		if len(req.Revocation) == 0 {
			WriteJSON(w, http.StatusOK, struct{}{})
			return
		}
	}
	if _, err := protocol.VerifyRevocation(a, req.Identity, req.Revocation); err != nil {
		problem(w, protocol.CodeBadRevocation, "not a revocation of this address")
		return
	}
	b.revoked, b.messages, b.order = req.Revocation, map[string]*message{}, nil
	WriteJSON(w, http.StatusCreated, struct{}{})
}

// current reports whether the box's current certificate is one its identity
// has not revoked: a box whose certificate is revoked has no pass the server
// takes and no prekey a sender may use, until it publishes under a new one.
func (b *box) current() bool { return b.listed == nil || !b.listed.Revokes(b.cert.Serial()) }

// revocations answers with what is held about an address: its revocation,
// which proves itself, or not_revoked.
func (s *Server) revocations(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
	switch {
	case b == nil:
		problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
	case b.revoked == nil && b.listed == nil:
		problem(w, protocol.CodeNotRevoked, "no revocation of this address is held here")
	default:
		WriteJSON(w, http.StatusOK, protocol.Revocations{Identity: b.identity, Revocation: b.revoked, RevokedCertificates: b.certList, RevokedCertificatesSignature: b.certListSig})
	}
}

func (s *Server) newPrekey(w http.ResponseWriter, r *http.Request) {
	a, ok := pathAddr(w, r)
	var req protocol.PrekeyRequest
	if !ok || !decode(w, r, &req) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[a]
	if b == nil {
		problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
		return
	}
	if b.revoked != nil {
		problem(w, protocol.CodeRevoked, "this box is revoked")
		return
	}
	p, cert, err := s.verifyPrekey(b.identity, req.Prekey, req.PrekeySignature)
	if err != nil {
		problem(w, protocol.CodeBadKey, err.Error())
		return
	}
	// Ordered by certificate first: a later one at any serial, or the
	// current one at a higher serial.
	switch {
	case cert.Serial() < b.cert.Serial(), cert.Serial() == b.cert.Serial() && !bytes.Equal(cert.Marshal(), b.cert.Marshal()):
		problem(w, protocol.CodeCertificateNotCurrent, "the certificate is older than the box's current one")
		return
	case cert.Serial() == b.cert.Serial() && p.Serial <= b.prekey.Serial:
		problem(w, protocol.CodeConflict, "the serial must be higher")
		return
	case b.listed != nil && b.listed.Revokes(cert.Serial()):
		problem(w, protocol.CodeCertificateRevoked, "the certificate is one the identity revoked")
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

func (s *Server) send(w http.ResponseWriter, r *http.Request) {
	to, ok := pathAddr(w, r)
	var req protocol.SendRequest
	if !ok || !decode(w, r, &req) {
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
		problem(w, protocol.CodeRevoked, "this box is revoked")
		return
	case !rcpt.current():
		problem(w, protocol.CodePrekeyExpired, "the box must publish a new prekey: its current one is under a revoked certificate")
		return
	case req.PrekeySerial != nil && *req.PrekeySerial != rcpt.prekey.Serial, req.CertificateSerial != nil && *req.CertificateSerial != rcpt.cert.Serial():
		problem(w, protocol.CodeStalePrekey, "a newer prekey exists")
		return
	}
	h := sha256.Sum256(req.Ciphertext)
	key := hex.EncodeToString(h[:])
	if m := rcpt.messages[key]; m != nil {
		WriteJSON(w, http.StatusOK, receipt(key, m))
		return
	}
	if !rcpt.acl.Admits(from) {
		problem(w, protocol.CodeSenderNotAllowed, "the box's ACL does not admit the sender")
		return
	}
	m := &message{from: from, ciphertext: req.Ciphertext, receivedAt: s.now()}
	rcpt.messages[key] = m
	rcpt.order = append(rcpt.order, key)
	WriteJSON(w, http.StatusCreated, receipt(key, m))
}

// Take answers a post as a server that kept it would, and keeps nothing: a
// receipt for the ciphertext posted. It is for a test that plays an
// operator who swallows mail, which a client cannot tell from a delivery.
func Take(w http.ResponseWriter, r *http.Request) { TakeAs(w, r, nil) }

// TakeAs is Take, with the receipt changed by edit before it is written.
func TakeAs(w http.ResponseWriter, r *http.Request, edit func(*protocol.Receipt)) {
	var req protocol.SendRequest
	body, _ := io.ReadAll(r.Body)
	if protocol.Unmarshal(body, &req) != nil {
		problem(w, protocol.CodeBadRequest, "not a send")
		return
	}
	h := sha256.Sum256(req.Ciphertext)
	now := time.Now()
	rec := protocol.Receipt{ID: hex.EncodeToString(h[:]), ReceivedAt: formatTime(now), ExpiresAt: formatTime(now.Add(protocol.TTL))}
	if edit != nil {
		edit(&rec)
	}
	WriteJSON(w, http.StatusCreated, rec)
}

func receipt(id string, m *message) protocol.Receipt {
	return protocol.Receipt{ID: id, ReceivedAt: formatTime(m.receivedAt), ExpiresAt: formatTime(m.receivedAt.Add(protocol.TTL))}
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
		if b == nil {
			problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
			return
		}
		if b.revoked != nil {
			problem(w, protocol.CodeRevoked, "this box is revoked")
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

// list answers with every message, and an ETag that changes whenever the
// set of messages does; a matching If-None-Match gets 304.
func (s *Server) list(w http.ResponseWriter, r *http.Request, b *box) {
	l := protocol.MessageList{Messages: []protocol.MessageInfo{}, PollAfter: 60}
	var version [8]byte
	for _, id := range b.order {
		if m := b.messages[id]; m != nil {
			l.Messages = append(l.Messages, protocol.MessageInfo{ID: id, From: m.from.String(), Size: int64(len(m.ciphertext)),
				ReceivedAt: formatTime(m.receivedAt), ExpiresAt: formatTime(m.receivedAt.Add(protocol.TTL))})
			h := sha256.Sum256([]byte(id))
			for i := range version {
				version[i] ^= h[i]
			}
		}
	}
	l.Count = int64(len(l.Messages))
	etag := `"` + hex.EncodeToString(version[:]) + `"`
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	WriteJSON(w, http.StatusOK, l)
}

func (s *Server) fetch(w http.ResponseWriter, r *http.Request, b *box) {
	id := r.PathValue("id")
	m := b.messages[id]
	if m == nil {
		problem(w, protocol.CodeNoSuchMessage, "acked or expired")
		return
	}
	WriteJSON(w, http.StatusOK, protocol.Message{ID: id, From: m.from.String(), ReceivedAt: formatTime(m.receivedAt),
		ExpiresAt: formatTime(m.receivedAt.Add(protocol.TTL)), Ciphertext: m.ciphertext})
}

// putACL replaces the box's ACL with one of a higher version, and deletes
// what is waiting from every sender its deny list matches.
func (s *Server) putACL(w http.ResponseWriter, r *http.Request, b *box) {
	var d protocol.ACLDocument
	if !decode(w, r, &d) {
		return
	}
	acl, err := protocol.CheckACL(&d, 0)
	switch {
	case err != nil:
		problem(w, protocol.CodeBadRequest, "not an ACL")
		return
	case b.acl != nil && acl.Version <= b.acl.Version:
		problem(w, protocol.CodeConflict, "a version that is not above the one held")
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

func (s *Server) getACL(w http.ResponseWriter, _ *http.Request, b *box) {
	WriteJSON(w, http.StatusOK, b.acl.Document())
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
	k := "iga1_" + hex.EncodeToString(b[:])
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
