// Package fakeserver is an in-memory crossbot server for the client's tests:
// honest, and just enough of the API for a client to register, renew its
// prekey, send, list, fetch and ack. It is NOT the crossbot.dev server, and
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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/drewstreib/crossbot-client/protocol"
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
	token     string          // the current owner token
	account   string          // the account it is in, or ""
	stale     map[string]bool // earlier tokens: token_stale
	messages  map[string]*message
	order     []string // ids, oldest first
}

type message struct {
	from       protocol.Address
	ciphertext []byte
	signature  []byte
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
	mux.HandleFunc("POST /v1/{addr}/token", s.tokenCall)
	mux.HandleFunc("GET /v1/{addr}/messages", s.owner(s.list))
	mux.HandleFunc("GET /v1/{addr}/messages/{id}", s.owner(s.fetch))
	mux.HandleFunc("DELETE /v1/{addr}/messages/{id}", s.owner(s.ack))
	mux.HandleFunc("PUT /v1/{addr}/account", s.owner(s.adopt))
	mux.HandleFunc("DELETE /v1/{addr}/account", s.owner(s.leave))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
func (s *Server) Inject(to protocol.Address, id string, from protocol.Address, ciphertext, signature []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.boxes[to]
	b.messages[id] = &message{from: from, ciphertext: ciphertext, signature: signature, receivedAt: s.now()}
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
	_ = json.NewEncoder(w).Encode(protocol.Problem{Type: code.TypeURI(), Status: code.Status(), Code: code, Detail: detail})
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

// verifyPrekey checks a statement against the box's identity.
func verifyPrekey(identity, statement, signature []byte) (*protocol.Prekey, error) {
	id, err := protocol.ParseIdentity(identity)
	if err != nil {
		return nil, err
	}
	return protocol.VerifyPrekey(id, statement, signature)
}

// newToken mints a new owner token; the one it replaces turns stale.
func (b *box) newToken() {
	if b.token != "" {
		b.stale[b.token] = true
	}
	t := make([]byte, 16)
	_, _ = rand.Read(t)
	b.token = "fake_" + hex.EncodeToString(t)
}

// writeToken answers with the current token, encrypted to the current prekey.
func writeToken(w http.ResponseWriter, status int, b *box) {
	r, err := b.prekey.Recipient()
	if err != nil {
		problem(w, protocol.CodeBadKey, err.Error())
		return
	}
	var ct bytes.Buffer
	enc, err := age.Encrypt(&ct, r)
	if err != nil {
		problem(w, protocol.CodeBadKey, err.Error())
		return
	}
	_, _ = io.WriteString(enc, b.token)
	_ = enc.Close()
	WriteJSON(w, status, protocol.TokenResponse{Token: ct.Bytes()})
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
	p, err := verifyPrekey(req.Identity, req.Prekey, req.PrekeySignature)
	if err != nil {
		problem(w, protocol.CodeBadKey, err.Error())
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if b := s.boxes[a]; b != nil {
		if bytes.Equal(b.statement, req.Prekey) && bytes.Equal(b.signature, req.PrekeySignature) {
			writeToken(w, http.StatusOK, b)
			return
		}
		problem(w, protocol.CodeConflict, "registered with another prekey")
		return
	}
	b := &box{identity: req.Identity, statement: req.Prekey, signature: req.PrekeySignature, prekey: p,
		stale: map[string]bool{}, messages: map[string]*message{}}
	b.newToken()
	s.boxes[a] = b
	writeToken(w, http.StatusCreated, b)
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
	WriteJSON(w, http.StatusOK, protocol.IdentityResponse{Identity: b.identity, Prekey: b.statement, PrekeySignature: b.signature})
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
	p, err := verifyPrekey(b.identity, req.Prekey, req.PrekeySignature)
	if err != nil {
		problem(w, protocol.CodeBadKey, err.Error())
		return
	}
	if p.Serial <= b.prekey.Serial {
		problem(w, protocol.CodeConflict, "the serial must be higher")
		return
	}
	b.statement, b.signature, b.prekey = req.Prekey, req.PrekeySignature, p
	b.newToken()
	writeToken(w, http.StatusOK, b)
}

func (s *Server) tokenCall(w http.ResponseWriter, r *http.Request) {
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
	writeToken(w, http.StatusOK, b)
}

func (s *Server) send(w http.ResponseWriter, r *http.Request) {
	to, ok := pathAddr(w, r)
	var req protocol.SendRequest
	if !ok || !decode(w, r, &req) {
		return
	}
	from, err := protocol.ParseAddress(req.From)
	if err != nil {
		problem(w, protocol.CodeBadAddress, "from is not an address")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rcpt, sender := s.boxes[to], s.boxes[from]
	switch {
	case rcpt == nil:
		problem(w, protocol.CodeNoSuchMailbox, "no box has this address")
		return
	case sender == nil:
		problem(w, protocol.CodeUnknownSender, "the sender is not registered")
		return
	case req.PrekeySerial != nil && *req.PrekeySerial != rcpt.prekey.Serial:
		problem(w, protocol.CodeStalePrekey, "a newer prekey exists")
		return
	}
	id, _ := protocol.ParseIdentity(sender.identity)
	if err := protocol.Verify(id, req.Ciphertext, req.Signature, protocol.MessageNamespace(to)); err != nil {
		problem(w, protocol.CodeBadSignature, "the signature does not verify for the sender")
		return
	}
	h := sha256.Sum256(req.Ciphertext)
	key := hex.EncodeToString(h[:])
	if m := rcpt.messages[key]; m != nil {
		WriteJSON(w, http.StatusOK, receipt(key, m))
		return
	}
	m := &message{from: from, ciphertext: req.Ciphertext, signature: req.Signature, receivedAt: s.now()}
	rcpt.messages[key] = m
	rcpt.order = append(rcpt.order, key)
	WriteJSON(w, http.StatusCreated, receipt(key, m))
}

func receipt(id string, m *message) protocol.Receipt {
	return protocol.Receipt{ID: id, ReceivedAt: formatTime(m.receivedAt), ExpiresAt: formatTime(m.receivedAt.Add(protocol.TTL))}
}

func formatTime(t time.Time) string { return t.UTC().Format(protocol.TimeLayout) }

// owner authenticates an owner call: the current token, or 401.
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
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case tok == b.token:
			h(w, r, b)
		case b.stale[tok]:
			problem(w, protocol.CodeTokenStale, "the token has moved on")
		default:
			problem(w, protocol.CodeUnauthorized, "not this box's token")
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
			l.Messages = append(l.Messages, protocol.MessageInfo{ID: id, From: m.from.String(), Size: len(m.ciphertext),
				ReceivedAt: formatTime(m.receivedAt), ExpiresAt: formatTime(m.receivedAt.Add(protocol.TTL))})
			h := sha256.Sum256([]byte(id))
			for i := range version {
				version[i] ^= h[i]
			}
		}
	}
	l.Count = len(l.Messages)
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
		ExpiresAt: formatTime(m.receivedAt.Add(protocol.TTL)), Ciphertext: m.ciphertext, Signature: m.signature})
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
	k := "cba1_" + hex.EncodeToString(b[:])
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
