package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"github.com/IronGall-dev/irongall-client/sshsig"
	"golang.org/x/crypto/ssh"
)

// Signatures travel exactly as "ssh-keygen -Y sign" writes them: an armored
// SSHSIG blob. These are the armor's lines.
const (
	armorBegin = "-----BEGIN SSH SIGNATURE-----\n"
	armorEnd   = "-----END SSH SIGNATURE-----"
	armorWidth = 70 // ssh-keygen's line length
)

// MaxSignature is the most bytes an armored signature may be (PROTOCOL.md
// §3). A field that carries one counts every byte it holds; in a message it is
// the block from the BEGIN line through the END line. Dearmor refuses a longer
// one before reading it, so every verifier here does. It is several times the
// largest signature a key type here makes, and it rises only with a new key
// type, whose signatures a client without that type cannot verify anyway.
const MaxSignature = 4096

// Sign signs message in namespace and returns the signature armored
// byte-for-byte as "ssh-keygen -Y sign" writes it.
func Sign(s ssh.Signer, message []byte, namespace string) ([]byte, error) {
	blob, err := sshsig.Sign(s, rand.Reader, message, namespace)
	if err != nil {
		return nil, err
	}
	return Armor(blob), nil
}

// Verify verifies an armored signature by id over message, in namespace.
func Verify(id *Identity, message, signature []byte, namespace string) error {
	blob, err := Dearmor(signature)
	if err != nil {
		return err
	}
	return sshsig.Verify(id.PublicKey(), message, blob, namespace)
}

// Armor armors an SSHSIG blob as ssh-keygen does: base64 in lines of 70
// characters between the BEGIN and END lines, ending in LF.
func Armor(blob []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(blob)
	var b bytes.Buffer
	b.WriteString(armorBegin)
	for len(enc) > armorWidth {
		b.WriteString(enc[:armorWidth])
		b.WriteByte('\n')
		enc = enc[armorWidth:]
	}
	b.WriteString(enc)
	b.WriteString("\n" + armorEnd + "\n")
	return b.Bytes()
}

// Dearmor returns the SSHSIG blob inside an armored signature of at most
// MaxSignature bytes, as OpenSSH reads it (opensshReading). It reads the
// armor as "ssh-keygen -Y verify" does (OpenSSH's sshsig_dearmor): the BEGIN
// line first, ending in LF or CRLF, then base64 with any whitespace, then LF
// and the END line. One NUL may be the last byte before that LF, as
// sshbuf_dup_string takes it; a NUL anywhere else is refused. Anything after
// the END line is ignored; it is not part of the signature, but it counts
// toward the bound.
func Dearmor(armored []byte) ([]byte, error) {
	blob, err := dearmor(armored)
	if err != nil {
		return nil, err
	}
	return opensshReading(blob)
}

// dearmor is Dearmor's reading of the armor alone.
func dearmor(armored []byte) ([]byte, error) {
	if len(armored) > MaxSignature {
		return nil, errors.New("a signature is longer than the most a signature may be")
	}
	rest, ok := bytes.CutPrefix(armored, []byte(armorBegin[:len(armorBegin)-1]))
	if ok {
		if r, crlf := bytes.CutPrefix(rest, []byte("\r\n")); crlf {
			rest = r
		} else {
			rest, ok = bytes.CutPrefix(rest, []byte("\n"))
		}
	}
	if !ok {
		return nil, errors.New("a signature starts with " + armorBegin[:len(armorBegin)-1])
	}
	end := bytes.Index(rest, []byte("\n"+armorEnd))
	if end < 0 {
		return nil, errors.New("a signature ends with " + armorEnd)
	}
	text := bytes.TrimSuffix(rest[:end], []byte{0})
	b64 := bytes.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			return -1
		}
		return r
	}, text)
	// Strict, as OpenSSH's decoder is: the unused bits of the last character are zero.
	blob, err := base64.StdEncoding.Strict().DecodeString(string(b64))
	if err != nil {
		return nil, errors.New("the signature is not valid base64")
	}
	return blob, nil
}

// maxMPInt is the longest an mpint may be where OpenSSH reads one with
// sshbuf_get_bignum2: SSHBUF_MAX_BIGNUM bytes, and one zero byte before them.
const maxMPInt = 16384/8 + 1

// opensshReading returns an SSHSIG blob as OpenSSH reads it (sshsig.c,
// sshkey.c, ssh-ed25519.c, ssh-ecdsa.c and sshbuf-getput-basic.c at
// V_10_6_P1), written again in the one form the checks after it take. Every
// OpenSSH build reads these the same way (PROTOCOL.md §3):
//   - the version: 0 or 1, written as 1. sshsig_parse_preamble refuses only
//     a higher one, and the version is not signed;
//   - a string OpenSSH reads with sshbuf_get_cstring, where nothing signs
//     it, may end in one NUL, which is dropped; a NUL before its last byte
//     is refused. Those are the namespace, the hash name, each signature's
//     type, and a bare key's type and curve. OpenSSH builds the data a
//     signature covers from the strings without it, so a signature is good
//     with the NUL or without;
//   - an ECDSA signature's r or s longer than maxMPInt bytes is refused, as
//     sshbuf_get_bignum2 refuses it.
//
// What an identity signed in a certificate is left as it is, a NUL and all:
// its form is §2b's, and the checks after this refuse any other. A blob that
// does not parse is refused, as OpenSSH refuses it.
func opensshReading(blob []byte) ([]byte, error) {
	bad := errors.New("the signature is not an SSH signature as OpenSSH reads one")
	r := wireReader(blob)
	magic, ok := r.take(6)
	if !ok || string(magic) != "SSHSIG" {
		return nil, bad
	}
	if v, ok := r.uint32(); !ok || v > 1 {
		return nil, bad
	}
	key, ok1 := r.string()
	namespace, ok2 := r.string()
	reserved, ok3 := r.string()
	hash, ok4 := r.string()
	sig, ok5 := r.string()
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return nil, bad
	}
	var err1, err2, err3, err4 error
	key, err1 = keyAsRead(key)
	namespace, err2 = cstring(namespace)
	hash, err3 = cstring(hash)
	sig, err4 = signatureAsRead(sig)
	if err := errors.Join(err1, err2, err3, err4); err != nil {
		return nil, bad
	}
	out := append([]byte("SSHSIG"), 0, 0, 0, 1)
	for _, s := range [][]byte{key, namespace, reserved, hash, sig} {
		out = appendWireString(out, s)
	}
	// What follows the five fields is kept, for the verifier to refuse.
	return append(out, r...), nil
}

// cstring is a string as sshbuf_get_cstring reads it: one NUL may end it,
// and is dropped; a NUL before its last byte is refused.
func cstring(s []byte) ([]byte, error) {
	if i := bytes.IndexByte(s, 0); i >= 0 {
		if i != len(s)-1 {
			return nil, errors.New("a NUL inside a string")
		}
		return s[:i], nil
	}
	return s, nil
}

// keyAsRead is a signing key, in SSH wire form, as OpenSSH reads it: a bare
// key's type, and an ECDSA key's curve, are cstrings. A certificate is left
// as its identity signed it, but for its own signature, which nothing
// signs: an Ed25519 working key's certificate is the one kind a box has.
// OpenSSH checks the identity's signature over a certificate's bytes as they
// came, its type among them, so a NUL added to that type is refused there,
// and it is left here for the checks after this to refuse.
func keyAsRead(key []byte) ([]byte, error) {
	r := wireReader(key)
	t, ok := r.string()
	if !ok {
		return nil, errors.New("a key with no type")
	}
	if bytes.Contains(t, []byte("-cert-v01@openssh.com")) {
		if string(t) == ssh.CertAlgoED25519v01 {
			return certificateAsRead(key)
		}
		return key, nil
	}
	t, err := cstring(t)
	if err != nil {
		return nil, err
	}
	out := appendWireString(nil, t)
	if bytes.HasPrefix(t, []byte("ecdsa-sha2-")) {
		curve, ok := r.string()
		if !ok {
			return nil, errors.New("an ECDSA key with no curve")
		}
		if curve, err = cstring(curve); err != nil {
			return nil, err
		}
		out = appendWireString(out, curve)
	}
	return append(out, r...), nil
}

// certificateAsRead is an Ed25519 key's certificate with its own signature as
// OpenSSH reads it (signatureAsRead), and every field the identity signed as
// it is. Its fields, in order (PROTOCOL.certkeys): the type, a nonce, the key,
// the serial, the certificate's type, the key id, the principals, the two
// times, the critical options, the extensions, reserved, the signing key, and
// the signature. One that does not parse so is left for the checks after
// this to refuse.
func certificateAsRead(cert []byte) ([]byte, error) {
	r := wireReader(cert)
	for _, field := range []int{0, 0, 0, 8, 4, 0, 0, 8, 8, 0, 0, 0, 0} { // 0: a string; otherwise its fixed size
		var ok bool
		if field == 0 {
			_, ok = r.string()
		} else {
			_, ok = r.take(field)
		}
		if !ok {
			return cert, nil
		}
	}
	signed := cert[:len(cert)-len(r)]
	sig, ok := r.string()
	if !ok {
		return cert, nil
	}
	sig, err := signatureAsRead(sig)
	if err != nil {
		return nil, err
	}
	return append(appendWireString(bytes.Clone(signed), sig), r...), nil
}

// signatureAsRead is a signature in SSH wire form, as OpenSSH's verifiers
// read it: its type is a cstring, and an ECDSA signature's r and s are each at
// most maxMPInt bytes.
func signatureAsRead(sig []byte) ([]byte, error) {
	r := wireReader(sig)
	t, ok := r.string()
	if !ok {
		return nil, errors.New("a signature with no type")
	}
	t, err := cstring(t)
	if err != nil {
		return nil, err
	}
	if bytes.HasPrefix(t, []byte("ecdsa-sha2-")) {
		rs := r
		if inner, ok := rs.string(); ok {
			if err := ecdsaNumbersAsRead(inner); err != nil {
				return nil, err
			}
		}
	}
	return append(appendWireString(nil, t), r...), nil
}

// ecdsaNumbersAsRead refuses an ECDSA signature's r and s, the blob inside
// its type, when either is longer than OpenSSH's sshbuf_get_bignum2 reads.
// One that does not parse is left for the verifier to refuse.
func ecdsaNumbersAsRead(inner []byte) error {
	n := wireReader(inner)
	for range 2 {
		m, ok := n.string()
		if ok && (len(m) > maxMPInt || len(m) == maxMPInt && m[0] != 0) {
			return errors.New("an ECDSA signature's number is longer than OpenSSH reads")
		}
	}
	return nil
}

// wireReader reads SSH wire form: RFC 4251's uint32 and string.
type wireReader []byte

func (r *wireReader) take(n int) ([]byte, bool) {
	if n < 0 || len(*r) < n {
		return nil, false
	}
	v := (*r)[:n]
	*r = (*r)[n:]
	return v, true
}

func (r *wireReader) uint32() (uint32, bool) {
	v, ok := r.take(4)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint32(v), true
}

func (r *wireReader) string() ([]byte, bool) {
	n, ok := r.uint32()
	if !ok || uint64(n) > uint64(len(*r)) {
		return nil, false
	}
	return r.take(int(n))
}

// appendWireString appends an RFC 4251 string. Every string here came out of
// a signature of at most MaxSignature bytes, so its length fits.
func appendWireString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(s))) //nolint:gosec // bounded by MaxSignature
	return append(b, s...)
}
