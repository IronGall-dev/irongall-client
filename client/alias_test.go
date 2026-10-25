package client_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

// An alias is the box's own name for a peer: Destination takes it where it
// takes an address, and a send to it reaches that peer.
func TestAliasNamesAPeer(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	for name, to := range map[string]*client.Box{"zed": c, "bob": b} {
		if err := a.SetAlias(t.Context(), name, to.Address()); err != nil {
			t.Fatal(err)
		}
	}
	as, err := a.Aliases()
	if err != nil || len(as) != 2 || as[0] != (client.Alias{Name: "bob", Address: b.Address()}) || as[1] != (client.Alias{Name: "zed", Address: c.Address()}) {
		t.Fatalf("aliases, sorted by name: %+v, %v", as, err)
	}
	if err := ownerOnly(filepath.Join(a.Dir(), "aliases")); err != nil {
		t.Fatalf("the aliases file: %v", err)
	}
	to, err := a.Destination("bob")
	if err != nil || to != b.Address() {
		t.Fatalf("bob is %s, %v", to, err)
	}
	if _, err := a.Send(context.Background(), to, "to bob"); err != nil {
		t.Fatal(err)
	}
	if res := receive(t, b); len(res.Delivered) != 1 || bodyOf(t, res.Delivered[0]) != "to bob" {
		t.Fatalf("bob received %+v", res)
	}
	if res := receive(t, c); len(res.Delivered) != 0 {
		t.Fatalf("zed received %+v", res)
	}

	if err := a.RemoveAlias(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Destination("bob"); err == nil || !strings.Contains(err.Error(), "no alias named bob") {
		t.Fatalf("a removed alias: %v", err)
	}
	if err := a.RemoveAlias(t.Context(), "bob"); err == nil {
		t.Fatal("removed an alias that is not there")
	}
	if to, err := a.Destination("zed"); err != nil || to != c.Address() {
		t.Fatalf("zed after bob went: %s, %v", to, err)
	}
}

// A name is never moved: it keeps the address it was given until it is
// removed, so no send goes to another peer under an old name.
func TestAliasIsNeverMoved(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	if err := a.SetAlias(t.Context(), "bob", b.Address()); err != nil {
		t.Fatal(err)
	}
	var refused *client.RefusedError
	if err := a.SetAlias(t.Context(), "bob", c.Address()); !errors.As(err, &refused) || !strings.Contains(refused.Reason, "already names "+b.Address().String()) {
		t.Fatalf("moving bob: %v", err)
	}
	if err := a.SetAlias(t.Context(), "bob", b.Address()); err != nil {
		t.Fatalf("naming the same address again: %v", err)
	}
	if data, _ := os.ReadFile(filepath.Join(a.Dir(), "aliases")); string(data) != "bob "+b.Address().String()+"\n" {
		t.Fatalf("the aliases file: %q", data)
	}
	if to, _ := a.Destination("bob"); to != b.Address() {
		t.Fatalf("bob is now %s", to)
	}
}

// An alias is 1 to 32 of a-z, 0-9, '.', '_' and '-', starting with a letter
// or a digit: never an address, and never a link.
func TestAliasGrammar(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b := e.box(protocol.Classic), e.box(protocol.Classic)
	for _, name := range []string{"", "Bob", "-x", ".x", "a b", "a/b", "é", b.Address().String(), b.Link(), strings.Repeat("a", 33), "bob\n"} {
		var refused *client.RefusedError
		if err := a.SetAlias(t.Context(), name, b.Address()); !errors.As(err, &refused) || !strings.Contains(refused.Reason, "not an alias") {
			t.Errorf("%q: %v", name, err)
		}
	}
	if exists(filepath.Join(a.Dir(), "aliases")) {
		t.Fatal("a refused name made the aliases file")
	}
	for _, name := range []string{"b", "b2", "box.example.org", "the_bot-2", strings.Repeat("a", 32)} {
		if err := a.SetAlias(t.Context(), name, b.Address()); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
	// An address or a link is still what it was: no alias can shadow one.
	for _, s := range []string{b.Address().String(), b.Link()} {
		if to, err := a.Destination(s); err != nil || to != b.Address() {
			t.Errorf("%s: %s, %v", s, to, err)
		}
	}
}

// The aliases file is plain text that a person or the stock script may edit:
// a line that is not "<name> <address>" names nothing and is kept, and a name
// with two addresses names neither.
func TestAliasFileEditedByHand(t *testing.T) {
	t.Parallel()
	e := newEnv(t)
	a, b, c := e.box(protocol.Classic), e.box(protocol.Classic), e.box(protocol.Classic)
	file := filepath.Join(a.Dir(), "aliases")
	hand := "# my peers\nbob " + b.Address().String() + "\nBad " + c.Address().String() + "\ncarol not-an-address\n"
	if err := os.WriteFile(file, []byte(hand), 0o600); err != nil {
		t.Fatal(err)
	}
	if as, err := a.Aliases(); err != nil || len(as) != 1 || as[0].Name != "bob" {
		t.Fatalf("aliases: %+v, %v", as, err)
	}
	if _, err := a.Destination("carol"); err == nil {
		t.Fatal("a name with no address was resolved")
	}
	if err := a.SetAlias(t.Context(), "dan", c.Address()); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(file); string(data) != hand+"dan "+c.Address().String()+"\n" { //nolint:gosec // a test's own directory
		t.Fatalf("the file after SetAlias: %q", data)
	}
	if err := os.WriteFile(file, []byte(hand+"bob "+c.Address().String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var refused *client.RefusedError
	if _, err := a.Destination("bob"); !errors.As(err, &refused) || !strings.Contains(refused.Reason, "names 2 addresses") {
		t.Fatalf("a name with two addresses: %v", err)
	}
	if err := a.RemoveAlias(t.Context(), "bob"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(file); string(data) != "# my peers\nBad "+c.Address().String()+"\ncarol not-an-address\n" { //nolint:gosec // a test's own directory
		t.Fatalf("the file after RemoveAlias: %q", data)
	}
}
