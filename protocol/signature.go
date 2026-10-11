package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
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

// Dearmor returns the SSHSIG blob inside an armored signature. It accepts what
// "ssh-keygen -Y verify" accepts (OpenSSH's sshsig_dearmor): the BEGIN line
// first, ending in LF or CRLF, then base64 with any whitespace, then LF and
// the END line. Anything after the END line is ignored; it is not part of the
// signature.
func Dearmor(armored []byte) ([]byte, error) {
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
	b64 := bytes.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\v', '\f', '\r':
			return -1
		}
		return r
	}, rest[:end])
	// Strict, as OpenSSH's decoder is: the unused bits of the last character are zero.
	blob, err := base64.StdEncoding.Strict().DecodeString(string(b64))
	if err != nil {
		return nil, errors.New("the signature is not valid base64")
	}
	return blob, nil
}
