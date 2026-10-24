package client

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
	"github.com/IronGall-dev/irongall-client/protocol"
)

// With no HTTP client given, requests are bounded by requestTimeout (stall),
// so a server that stops answering cannot hold the box's lock for ever, and
// the client has no Timeout of its own, which would cut a ciphertext's body
// on a slow link whatever moved (#381). A client given is used as it is,
// its own timeouts its choice.
func TestOnlyTheDefaultClientIsBoundedByTheBox(t *testing.T) {
	t.Parallel()
	if b, err := newBox(t.TempDir(), Options{}); err != nil || !b.stall || b.http.Timeout != 0 {
		t.Fatalf("the default HTTP client: bounded by the box %v, Timeout %v", b.stall, b.http.Timeout)
	}
	if b, err := newBox(t.TempDir(), Options{HTTPClient: &http.Client{Timeout: time.Second}}); err != nil || b.stall || b.http.Timeout != time.Second {
		t.Fatalf("a client given: bounded by the box %v, Timeout %v", b.stall, b.http.Timeout)
	}
}

// A pass names the server as an origin is written: its host, lowercase, with
// no user before it, and its port as a number only when that is not the
// scheme's default, so https://irongall.dev:443 and https://irongall.dev name
// one server, as the server reads its Host (PROTOCOL.md §8).
func TestAPassNamesTheServerAsAnOrigin(t *testing.T) {
	t.Parallel()
	for base, want := range map[string]string{
		"https://irongall.dev":              "irongall.dev",
		"https://irongall.dev:443":          "irongall.dev",
		"https://IronGall.dev:0443/":        "irongall.dev",
		"https://someone@irongall.dev:8443": "irongall.dev:8443",
		"https://irongall.dev:80":           "irongall.dev:80",
		"http://irongall:8080":              "irongall:8080",
		"http://irongall:80":                "irongall",
		"http://irongall:":                  "irongall",
		"http://[::1]:8080":                 "[::1]:8080",
		"https://[::1]:443":                 "[::1]",
	} {
		if got, err := (&Box{base: strings.TrimRight(base, "/")}).serverName(); err != nil || got != want {
			t.Errorf("%s: the pass names %q, %v; want %q", base, got, err, want)
		}
	}
	if got, err := (&Box{base: "https://irongall.dev:65536"}).serverName(); err == nil {
		t.Errorf("a port that is no port: named %q", got)
	}
	// A host is lowercased in ASCII alone: one whose K is the Kelvin sign,
	// which Unicode's rules lower to k, names no server, never key.example
	// (#405).
	if got, err := (&Box{base: "https://\u212aey.example"}).serverName(); err == nil {
		t.Errorf("a host that is not ASCII: named %q", got)
	}
}

// Init with an identity type this client does not make writes nothing: the
// type is held where every box is made, before any directory is (#223).
func TestAnIdentityTypeIsHeldBeforeAnythingIsWritten(t *testing.T) {
	t.Parallel()
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := Init(context.Background(), dir, Options{Base: "https://irongall.dev", IdentityType: "ssh-rsa"}, protocol.Classic); err == nil {
		t.Fatal("a box was made with an identity type this client does not make")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the box's directory was made: %v", err)
	}
}

// counting is an age identity that counts the calls reaching its own Unwrap,
// where a key agreement begins.
type counting struct {
	age.Identity
	n *int
}

func (c counting) Unwrap(s []*age.Stanza) ([]byte, error) { *c.n++; return c.Identity.Unwrap(s) }

// greaseOnly is an age recipient that writes stanzas of grease alone, under
// labels, so that it sits beside a recipient of any type.
type greaseOnly struct{ labels []string }

func (g greaseOnly) Wrap(k []byte) ([]*age.Stanza, error) {
	s, _, err := g.WrapWithLabels(k)
	return s, err
}

func (g greaseOnly) WrapWithLabels([]byte) ([]*age.Stanza, []string, error) {
	return []*age.Stanza{{Type: "x-grease", Args: []string{"x"}, Body: []byte("grease")}}, g.labels, nil
}

// A file without exactly one native recipient stanza reaches no key
// agreement: the stanzas are counted before age is given any prekey
// (decrypt, oneNative; PROTOCOL.md §12.3 check 1), whatever its native stanzas'
// type and order, and a file with one is decrypted, one key agreement for
// the one prekey given (#417 item 1). One with none is its own case (item 4).
func TestNoKeyAgreementBeforeTheStanzasAreCounted(t *testing.T) {
	t.Parallel()
	x, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	pq, err := age.GenerateHybridIdentity()
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []struct {
		name  string
		own   age.Identity
		to    age.Recipient
		other func() age.Recipient
		label []string
	}{
		{"X25519", x, x.Recipient(), func() age.Recipient { s, _ := age.GenerateX25519Identity(); return s.Recipient() }, nil},
		{"post-quantum", pq, pq.Recipient(), func() age.Recipient { s, _ := age.GenerateHybridIdentity(); return s.Recipient() }, []string{"postquantum"}},
	} {
		for _, c := range []struct {
			name string
			to   []age.Recipient
			want error
		}{
			{"a stranger's stanza, then the box's", []age.Recipient{kind.other(), kind.to}, errNotOneNative},
			{"the box's stanza, then a stranger's", []age.Recipient{kind.to, kind.other()}, errNotOneNative},
			{"the box's stanza twice", []age.Recipient{kind.to, kind.to}, errNotOneNative},
			{"strangers' stanzas around the box's", []age.Recipient{kind.other(), kind.other(), kind.to, kind.other()}, errNotOneNative},
			{"grease alone", []age.Recipient{greaseOnly{kind.label}}, errNoNative},
			{"the box's stanza between grease", []age.Recipient{greaseOnly{kind.label}, kind.to, greaseOnly{kind.label}}, nil},
		} {
			var ct bytes.Buffer
			w, err := age.Encrypt(&ct, c.to...)
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			n := 0
			_, err = decrypt(ct.Bytes(), []age.Identity{counting{kind.own, &n}})
			want := 1
			if c.want != nil {
				want = 0
			}
			if !errors.Is(err, c.want) || c.want == nil && err != nil || n != want {
				t.Errorf("%s, %s: %v; the prekey's own Unwrap was reached %d times, want %d", kind.name, c.name, err, n, want)
			}
		}
	}
}
