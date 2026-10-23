package protocol

import (
	"bytes"
	"errors"
	"regexp"

	"filippo.io/age"
)

// Stanzas is how an age file's recipient stanzas stand to the protocol
// (PROTOCOL.md §4.5 step 7, §5 check 1). A server takes a send with exactly
// one native stanza, of the recipient's current prekey's type, beside
// grease, and refuses one with none, with two or more, or with a stanza of
// another type; a reader may refuse a file without exactly one native
// stanza, before any key agreement.
type Stanzas struct {
	// Native are the types of its native stanzas, those of a type a prekey
	// has (PostQuantum, Classic), in the header's order.
	Native []KeyType
	// Other is set when it has a stanza that is neither native nor grease.
	Other bool
}

// grease is a grease stanza's type: rage, the Rust age crate and pyrage add
// one to every file, which age ignores. One with more than maxGreaseArgs
// arguments is no grease (PROTOCOL.md §4.5 step 7).
var grease = regexp.MustCompile(`\A[!-~]{1,8}-grease\z`)

const maxGreaseArgs = 4

// ReadStanzas reads the recipient stanzas of the age file ciphertext, and
// sorts each once, before anything is decrypted: the one reading of them a
// reader and a server make (irongall-client's oneNative, and a server's
// check of a send). The header is read by age itself, once (age.Decrypt,
// given only an identity that keeps the stanzas it is given and matches
// none, which ends at the header), so they are the stanzas age would try. A
// file whose header age does not read is an error, with no Stanzas beside
// it.
func ReadStanzas(ciphertext []byte) (Stanzas, error) {
	rec := &stanzaRecorder{}
	_, err := age.Decrypt(bytes.NewReader(ciphertext), rec)
	var noMatch *age.NoIdentityMatchError
	if !errors.As(err, &noMatch) || rec.stanzas == nil {
		return Stanzas{}, errors.New("the age header did not parse")
	}
	var st Stanzas
	for _, s := range rec.stanzas {
		switch {
		case s.Type == string(PostQuantum) || s.Type == string(Classic):
			st.Native = append(st.Native, KeyType(s.Type))
		case grease.MatchString(s.Type) && len(s.Args) <= maxGreaseArgs:
		default:
			st.Other = true
		}
	}
	return st, nil
}

// stanzaRecorder is an age identity that keeps the stanzas it is given and
// matches none: age parses the header, and nothing here parses it again.
type stanzaRecorder struct{ stanzas []*age.Stanza }

func (r *stanzaRecorder) Unwrap(stanzas []*age.Stanza) ([]byte, error) {
	r.stanzas = stanzas
	return nil, age.ErrIncorrectIdentity
}
