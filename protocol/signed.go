package protocol

import (
	"bytes"
	"encoding/base64"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// What is encrypted to a recipient's prekey is three parts, one after the
// other (PROTOCOL.md §9.2):
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
// recipient, by signer: the identity in identity mode, or a working key under
// its certificate (Certificate.Signer) in working-key mode. The namespace names the recipient, so the signature
// holds for that mailbox only.
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
// END line, which a line feed must follow: anything else there, and the
// message is no message. Whatever follows is padding and is not looked at.
func splitPlaintext(p []byte) (line, signature []byte, ok bool) {
	i := bytes.IndexByte(p, '\n')
	if i < 0 {
		return nil, nil, false
	}
	line, rest := p[:i+1], p[i+1:]
	if !bytes.HasPrefix(rest, []byte(armorBegin)) {
		return nil, nil, false
	}
	end := []byte("\n" + armorEnd)
	j := bytes.Index(rest, end) + len(end)
	if j < len(end) || j >= len(rest) || rest[j] != '\n' {
		return nil, nil, false
	}
	return line, rest[:j+1], true
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
	// Signer is the key the signature was made by: the identity, or a working
	// key under a certificate. Holding it to the sender's mode is the reader's
	// (PROTOCOL.md §12.3 check 7, Admits).
	Signer *Signer
}

// OpenSigned checks what a recipient decrypted, in this order, and returns
// the message only if every check passes. A failure is an *EnvelopeError with
// one of the Refused codes.
//
//  1. It is an envelope line and then a signature block.
//  2. The line is UTF-8 JSON, one object with no key twice.
//  3. It carries an identity document: the exact format, a key that passes
//     the key checks.
//  4. Its from is that document's hash. A well-formed document of a key type
//     this client does not verify is refused here, after its hash: with its
//     own code, since nothing is wrong with it.
//  5. The signature over the line, as decrypted, verifies in this mailbox's
//     message namespace, by that identity or a working key it certified,
//     under a certificate valid at now. The sender's mode is not applied
//     here: the reader learns it at check 7 (PROTOCOL.md §12.3).
//  6. The envelope, in OpenEnvelope's order: a body and every member of its
//     type, version 1, to is this mailbox, a msg_id, and a sent_at no older than
//     TTL and no more than MaxSkew ahead.
//
// The identity document is read from the envelope before the signature is
// checked. That is sound: the document proves itself, since its hash is the
// address, and the signature must then verify under it.
func OpenSigned(plaintext []byte, me Address, now time.Time) (*Signed, error) {
	signed, _, err := Examine(plaintext, me, now)
	return signed, err
}

// Findings is what Examine established about a message on the way to its
// verdict, kept with a refused one so that its owner can judge it later. Each
// is a value whose form was checked, or one computed here: nothing the sender
// wrote as text.
type Findings struct {
	// At is this machine's clock when it judged the message.
	At time.Time
	// Identity is the address the identity document the envelope carries
	// hashes to. Anyone can copy a document into an envelope, so it is who
	// signed only when Signed is true.
	Identity *Address
	// Signed reports that the signature over the line verifies, by Identity
	// or a working key it certified, checked at that certificate's own start:
	// so it holds of a certificate that has not begun, or has ended, by At. It
	// says who made the message, not that it is good now.
	Signed bool
	// What follows is kept only when Signed, since before that it is
	// anyone's numbers: the signer's rank (0 for the identity), the moments
	// its certificate begins and ends (zero for the identity), and the
	// envelope's sent_at and msg_id when each has its form.
	Rank        uint64
	Began, Ends time.Time
	SentAt      time.Time
	MsgID       string
}

// Examine is OpenSigned, and returns what it established about the message
// whether or not it passes: Findings, never nil.
func Examine(plaintext []byte, me Address, now time.Time) (*Signed, *Findings, error) {
	f := &Findings{At: now}
	line, signature, ok := splitPlaintext(plaintext)
	if !ok {
		return nil, f, &EnvelopeError{RefusedMessage, "what was decrypted is not an envelope line and then a signature block"}
	}
	doc, from, err := envelopeSender(line)
	if err != nil {
		return nil, f, err
	}
	if len(doc) == 0 {
		return nil, f, &EnvelopeError{RefusedIdentity, "the envelope carries no identity document"}
	}
	a := AddressOf(doc)
	f.Identity = &a
	id, err := ParseIdentity(doc)
	notTheSenders := &EnvelopeError{RefusedAttribution, "the envelope's from is not the address of the identity it carries"}
	switch {
	case errors.Is(err, ErrIdentityType):
		if from != a.String() {
			return nil, f, notTheSenders
		}
		return nil, f, &EnvelopeError{RefusedKeyType, "the sender's identity is of a key type this client does not verify"}
	case err != nil:
		return nil, f, &EnvelopeError{RefusedIdentity, "the envelope's identity document breaks its format or its key checks"}
	case from != id.Address().String():
		return nil, f, notTheSenders
	}
	signer, err := VerifySigned(id, line, signature, MessageNamespace(me), now)
	switch {
	case err == nil:
		f.signed(signer, line)
	case errors.Is(err, ErrCertificateTime):
		f.whoMade(id, line, signature, MessageNamespace(me))
	}
	switch {
	case errors.Is(err, ErrCertificateTime):
		if errors.Is(err, ErrCertificateNotBegun) {
			return nil, f, &EnvelopeError{RefusedSignature, "the certificate of the key that signed it has not begun, by this machine's clock"}
		}
		return nil, f, &EnvelopeError{RefusedSignature, "the certificate of the key that signed it has ended"}
	case errors.Is(err, ErrCertificate):
		return nil, f, &EnvelopeError{RefusedSignature, "it is not signed under a certificate of the sender's identity"}
	case err != nil:
		return nil, f, &EnvelopeError{RefusedSignature, "the signature does not verify for its sender and this mailbox"}
	}
	env, err := OpenEnvelope(line, id.Address(), me, now)
	if err != nil {
		return nil, f, err
	}
	return &Signed{Envelope: env, Line: line, Signature: signature, Sender: id, Signer: signer}, f, nil
}

// whoMade is for a signature refused for its certificate's time: it is
// verified again at that certificate's own start, so a certificate that is
// not valid now still says whether id made the message.
func (f *Findings) whoMade(id *Identity, line, signature []byte, namespace string) {
	began, err := CertificateBegan(signature)
	if err != nil {
		return
	}
	if signer, err := VerifySigned(id, line, signature, namespace, began); err == nil {
		f.signed(signer, line)
	}
}

// signed fills in Signed and what goes with it, for a signature that
// verified by signer.
func (f *Findings) signed(signer *Signer, line []byte) {
	f.Signed, f.Rank = true, signer.Rank()
	if c := signer.Certificate(); c != nil {
		f.Began, f.Ends = c.NotBefore(), c.NotAfter()
	}
	fields, err := objectFields(line)
	if err != nil {
		return
	}
	var s string
	if unmarshalString(fields["sent_at"], &s) == nil {
		if t, err := ParseTime(s); err == nil {
			f.SentAt = t
		}
	}
	s = ""
	if unmarshalString(fields["msg_id"], &s) == nil && msgIDGrammar.MatchString(s) {
		f.MsgID = s
	}
}

// envelopeSender reads the two members of an envelope's line that say who
// sent it, before anything is verified: from, as the exact string it holds,
// and the identity document. The document travels as canonical standard
// base64, the one encoding of its bytes, so no two readers decode it two ways.
func envelopeSender(line []byte) (doc []byte, from string, err error) {
	if !utf8Valid(line) {
		return nil, "", badEnvelope("the envelope is not UTF-8")
	}
	fields, err := objectFields(line)
	if err != nil {
		return nil, "", err
	}
	if raw, ok := fields["from"]; ok {
		if err := unmarshalString(raw, &from); err != nil {
			return nil, "", badEnvelope("the envelope is malformed: its from is not what that field holds")
		}
	}
	raw, ok := fields["identity"]
	if !ok {
		return nil, from, nil
	}
	notDoc := &EnvelopeError{RefusedIdentity, "the envelope's identity is not base64 of an identity document"}
	var b64 string
	if err := unmarshalString(raw, &b64); err != nil {
		return nil, "", notDoc
	}
	doc, err = base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(doc) == 0 || base64.StdEncoding.EncodeToString(doc) != b64 {
		return nil, "", notDoc
	}
	return doc, from, nil
}
