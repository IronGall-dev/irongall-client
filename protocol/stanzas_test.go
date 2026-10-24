package protocol

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"filippo.io/age"
)

// beside is an age recipient that writes r's stanzas, under r's labels, with
// more after them: grease or a stanza of another type beside a native one,
// as a file a server or a reader may meet holds. With no r it writes more
// alone.
type beside struct {
	r    age.Recipient
	more []*age.Stanza
}

func (x beside) Wrap(k []byte) ([]*age.Stanza, error) {
	s, _, err := x.WrapWithLabels(k)
	return s, err
}

func (x beside) WrapWithLabels(k []byte) ([]*age.Stanza, []string, error) {
	var s []*age.Stanza
	var labels []string
	var err error
	switch r := x.r.(type) {
	case nil:
	case age.RecipientWithLabels:
		s, labels, err = r.WrapWithLabels(k)
	default:
		s, err = r.Wrap(k)
	}
	return append(s, x.more...), labels, err
}

// sealedTo is an age file of a few bytes to rs.
func sealedTo(t *testing.T, rs ...age.Recipient) []byte {
	t.Helper()
	var ct bytes.Buffer
	w, err := age.Encrypt(&ct, rs...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return ct.Bytes()
}

// ReadStanzas sorts each stanza of a file as PROTOCOL.md §11.10 step 7 does:
// native by its type, grease of at most four arguments ignored, and anything
// else another type; a file with no native stanza is one of its cases (#417
// items 1 and 4). What is no age file is an error with nothing beside it.
func TestReadStanzasSortsEachStanzaOnce(t *testing.T) {
	x1, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	x2, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	p1, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	grease := &age.Stanza{Type: "x-grease", Args: []string{"a", "b"}, Body: []byte("grease")}
	long := &age.Stanza{Type: "x-grease", Args: strings.Fields("a b c d e"), Body: []byte("grease")}
	other := &age.Stanza{Type: "piv-p256", Args: []string{"a"}, Body: []byte("other")}
	for _, c := range []struct {
		name   string
		to     []age.Recipient
		native []KeyType
		other  bool
	}{
		{"one X25519 stanza", []age.Recipient{x1.Recipient()}, []KeyType{Classic}, false},
		{"one post-quantum stanza", []age.Recipient{p1.Recipient()}, []KeyType{PostQuantum}, false},
		{"two X25519 stanzas", []age.Recipient{x1.Recipient(), x2.Recipient()}, []KeyType{Classic, Classic}, false},
		{"two post-quantum stanzas", []age.Recipient{p1.Recipient(), p2.Recipient()}, []KeyType{PostQuantum, PostQuantum}, false},
		{"X25519 and grease", []age.Recipient{beside{x1.Recipient(), []*age.Stanza{grease}}}, []KeyType{Classic}, false},
		{"two post-quantum stanzas, grease after the second", []age.Recipient{beside{p1.Recipient(), nil}, beside{p2.Recipient(), []*age.Stanza{grease}}}, []KeyType{PostQuantum, PostQuantum}, false},
		{"post-quantum and grease", []age.Recipient{beside{p1.Recipient(), []*age.Stanza{grease}}}, []KeyType{PostQuantum}, false},
		{"grease alone", []age.Recipient{beside{nil, []*age.Stanza{grease}}}, nil, false},
		{"X25519 and grease of five arguments", []age.Recipient{beside{x1.Recipient(), []*age.Stanza{long}}}, []KeyType{Classic}, true},
		{"X25519 and another type", []age.Recipient{beside{x1.Recipient(), []*age.Stanza{other}}}, []KeyType{Classic}, true},
		{"another type alone", []age.Recipient{beside{nil, []*age.Stanza{other}}}, nil, true},
	} {
		st, err := ReadStanzas(sealedTo(t, c.to...))
		if err != nil || !slices.Equal(st.Native, c.native) || st.Other != c.other {
			t.Errorf("%s: %+v, %v; want native %v, other %v", c.name, st, err, c.native, c.other)
		}
	}
	for _, bad := range [][]byte{nil, []byte("not an age file"), sealedTo(t, x1.Recipient())[:30]} {
		if st, err := ReadStanzas(bad); err == nil || st.Native != nil || st.Other {
			t.Errorf("%q: %+v, %v", bad, st, err)
		}
	}
}
