package protocol

import (
	"bytes"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// What is encrypted to a recipient's prekey is three parts, one after the
// other (PROTOCOL.md §4.3):
//
//	the envelope, one line of JSON ending in a line feed
//	the signature over that line, as "ssh-keygen -Y sign" writes it
//	padding, to the end
//
// It is git's layout for a signed tag: the signed bytes as they are, then the
// signature block. Nothing is encoded a second time, and what the layout adds
// is the same number of bytes whatever the message's size.
//
// Three rules for a reader come from what went wrong in verifiers of that
// layout elsewhere. The signature is checked over the first line exactly as
// decrypted, and the envelope's members are read from those same bytes, never
// from anything rebuilt. Each part has one place and nothing is searched for:
// line 1 is the envelope, line 2 begins the signature, the block ends at the
// first END line, and what follows is never read. And there is one signature,
// checked against one identity, the one the envelope carries.

// padFiller is one byte of padding.
const padFiller = '.'

// SignEnvelope returns the envelope's line and the signature over it for its
// recipient, by signer: a working key under its certificate
// (Certificate.Signer). The namespace names the recipient, so the signature
// holds for that box only.
func SignEnvelope(e *Envelope, signer ssh.Signer) (line, signature []byte, err error) {
	if line, err = e.Line(); err != nil {
		return nil, nil, err
	}
	if signature, err = Sign(signer, line, MessageNamespace(e.To)); err != nil {
		return nil, nil, err
	}
	return line, signature, nil
}

// Plaintext returns what to encrypt to one key of type t: the envelope's
// line, its signature, and the padding that makes the age file a whole number
// of blocks (pad.go); and that file's size. The caller encrypts what it
// returns and checks the file is that size.
func Plaintext(line, signature []byte, t KeyType) (plaintext []byte, sealed int) {
	sealed, filler := padTo(t, len(line)+len(signature))
	plaintext = make([]byte, 0, len(line)+len(signature)+filler)
	plaintext = append(plaintext, line...)
	plaintext = append(plaintext, signature...)
	return append(plaintext, bytes.Repeat([]byte{padFiller}, filler)...), sealed
}

// splitPlaintext returns the envelope's line, its line feed included, and the
// signature block. The line is everything up to the first line feed. The
// block starts at once after it, with the BEGIN line, and ends with the first
// END line. Whatever follows is padding and is not looked at.
func splitPlaintext(p []byte) (line, signature []byte, ok bool) {
	i := bytes.IndexByte(p, '\n')
	if i < 0 {
		return nil, nil, false
	}
	line, rest := p[:i+1], p[i+1:]
	if !bytes.HasPrefix(rest, []byte(armorBegin)) {
		return nil, nil, false
	}
	end := []byte("\n" + armorEnd + "\n")
	j := bytes.Index(rest, end)
	if j < 0 {
		return nil, nil, false
	}
	return line, rest[:j+len(end)], true
}

// Signed is a message that passed OpenSigned.
type Signed struct {
	Envelope *Envelope
	// Line is the envelope exactly as it was signed: the sender's bytes.
	Line []byte
	// Signature is the signature block exactly as it arrived.
	Signature []byte
	// Sender is the identity the envelope carries, whose address is From.
	Sender *Identity
	// Certificate is the one the signature was made under.
	Certificate *Certificate
}

// OpenSigned checks what a recipient decrypted, in this order, and returns
// the message only if every check passes. A failure is an *EnvelopeError with
// one of the Refused codes.
//
//  1. It is an envelope line and then a signature block.
//  2. The line is UTF-8 JSON, one object with no key twice.
//  3. It carries an identity document: the exact format, a key that passes
//     the key checks.
//  4. Its from is that document's hash.
//  5. The signature over the line, as decrypted, verifies in this box's
//     message namespace, by a working key that identity certified, under a
//     certificate valid at now.
//  6. The envelope: version 1, to is this box, a body, a msg_id, and a
//     sent_at no older than TTL.
//
// The identity document is read from the envelope before the signature is
// checked. That is sound: the document proves itself, since its hash is the
// address, and the signature must then verify under it.
func OpenSigned(plaintext []byte, me Address, now time.Time) (*Signed, error) {
	line, signature, ok := splitPlaintext(plaintext)
	if !ok {
		return nil, &EnvelopeError{RefusedMessage, "what was decrypted is not an envelope line and then a signature block"}
	}
	doc, from, err := envelopeSender(line)
	if err != nil {
		return nil, err
	}
	if len(doc) == 0 {
		return nil, &EnvelopeError{RefusedIdentity, "the envelope carries no identity document"}
	}
	id, err := ParseIdentity(doc)
	if err != nil {
		return nil, &EnvelopeError{RefusedIdentity, "the envelope's identity document breaks its format or its key checks"}
	}
	if from != id.Address().String() {
		return nil, &EnvelopeError{RefusedAttribution, "the envelope's from is not the address of the identity it carries"}
	}
	cert, err := VerifyCertified(id, line, signature, MessageNamespace(me), now)
	switch {
	case errors.Is(err, ErrCertificateTime):
		return nil, &EnvelopeError{RefusedSignature, "the certificate of the key that signed it has ended, or has not begun"}
	case errors.Is(err, ErrCertificate):
		return nil, &EnvelopeError{RefusedSignature, "it is not signed under a certificate of the sender's identity"}
	case err != nil:
		return nil, &EnvelopeError{RefusedSignature, "the signature does not verify for its sender and this box"}
	}
	env, err := OpenEnvelope(line, id.Address(), me, now)
	if err != nil {
		return nil, err
	}
	return &Signed{Envelope: env, Line: line, Signature: signature, Sender: id, Certificate: cert}, nil
}

// envelopeSender reads the two members of an envelope's line that say who
// sent it, before anything is verified: the identity document and from, as
// the exact string it holds.
func envelopeSender(line []byte) (doc []byte, from string, err error) {
	if !utf8Valid(line) {
		return nil, "", badEnvelope("the envelope is not UTF-8")
	}
	fields, err := objectFields(line)
	if err != nil {
		return nil, "", err
	}
	var w struct {
		Identity Bytes
		From     string
	}
	if raw, ok := fields["identity"]; ok {
		if err := w.Identity.UnmarshalJSON(raw); err != nil {
			return nil, "", &EnvelopeError{RefusedIdentity, "the envelope's identity is not base64 of an identity document"}
		}
	}
	if raw, ok := fields["from"]; ok {
		if err := unmarshalString(raw, &w.From); err != nil {
			return nil, "", badEnvelope("the envelope is malformed: its from is not what that field holds")
		}
	}
	return w.Identity, w.From, nil
}
