package client

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// With no HTTP client given, requests are bounded by requestTimeout (stall),
// so a server that stops answering cannot hold the box's lock for ever, and
// the client has no Timeout of its own, which would cut a ciphertext's body
// on a slow link whatever moved (#381). A client given is used as it is,
// its own timeouts its choice.
func TestOnlyTheDefaultClientIsBoundedByTheBox(t *testing.T) {
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
// one server, as the server reads its Host (PROTOCOL.md §6.1b).
func TestAPassNamesTheServerAsAnOrigin(t *testing.T) {
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
	dir := filepath.Join(t.TempDir(), "box")
	if _, err := Init(context.Background(), dir, Options{Base: "https://irongall.dev", IdentityType: "ssh-rsa"}, protocol.Classic); err == nil {
		t.Fatal("a box was made with an identity type this client does not make")
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the box's directory was made: %v", err)
	}
}
