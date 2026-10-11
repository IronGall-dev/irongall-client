package client

import (
	"errors"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/IronGall-dev/irongall-client/protocol"
)

// aliasGrammar is an alias: 1 to 32 of a-z, 0-9, '.', '_' and '-', starting
// with a letter or a digit. So an alias is never an address (64 hex
// characters) and never a link.
var aliasGrammar = regexp.MustCompile(`\A[a-z0-9][a-z0-9._-]{0,31}\z`)

// Alias is this box's own name for a peer's address: a word to send to in
// place of 64 hex characters. Aliases live in the box's aliases file, one
// "<name> <address>" line each, and never leave the box: neither the server
// nor the peer sees them. An alias is only as good as where its address came
// from.
type Alias struct {
	Name    string
	Address protocol.Address
}

// ValidAlias returns nil if name can be an alias, and otherwise why not.
func ValidAlias(name string) error {
	if !aliasGrammar.MatchString(name) {
		return refuse("not an alias: %s (1 to 32 of a-z, 0-9, '.', '_' and '-', starting with a letter or a digit)", name)
	}
	return nil
}

// Aliases returns the box's aliases, sorted by name. A line of the aliases
// file that is not "<name> <address>" names nothing and is skipped.
func (b *Box) Aliases() ([]Alias, error) {
	lines, err := b.aliasLines()
	if err != nil {
		return nil, err
	}
	var as []Alias
	for _, l := range lines {
		if a, ok := parseAlias(l); ok {
			as = append(as, a)
		}
	}
	slices.SortStableFunc(as, func(x, y Alias) int { return strings.Compare(x.Name, y.Name) })
	return as, nil
}

// SetAlias names a peer's address. A name that already names another address
// is refused, never moved: remove it first, so no send goes to a peer other
// than the one the name meant when it was learned.
func (b *Box) SetAlias(name string, a protocol.Address) error {
	if err := ValidAlias(name); err != nil {
		return err
	}
	switch have, err := b.aliased(name); {
	case err != nil:
		return err
	case len(have) == 1 && have[0] == a:
		return nil
	case len(have) > 0:
		return refuse("alias %s already names %s: remove it first (irongall alias --rm %s)", name, have[0], name)
	}
	lines, err := b.aliasLines()
	if err != nil {
		return err
	}
	return b.writeAliases(append(lines, name+" "+a.String()))
}

// RemoveAlias removes a name. The peer's pinned identity and mail stay.
func (b *Box) RemoveAlias(name string) error {
	lines, err := b.aliasLines()
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(slices.Clone(lines), func(l string) bool {
		a, ok := parseAlias(l)
		return ok && a.Name == name
	})
	if len(kept) == len(lines) {
		return refuse("no alias named %s", name)
	}
	return b.writeAliases(kept)
}

// alias returns the address a name names. A name on two lines with two
// addresses names neither.
func (b *Box) alias(name string) (protocol.Address, error) {
	found, err := b.aliased(name)
	switch {
	case err != nil:
		return protocol.Address{}, err
	case len(found) == 1:
		return found[0], nil
	case len(found) == 0:
		return protocol.Address{}, refuse("no alias named %s: irongall alias lists them, and names one", name)
	}
	return protocol.Address{}, refuse("alias %s names %d addresses in %s: keep one line", name, len(found), b.path("aliases"))
}

// aliased returns every distinct address the aliases file gives a name.
func (b *Box) aliased(name string) ([]protocol.Address, error) {
	as, err := b.Aliases()
	if err != nil {
		return nil, err
	}
	var found []protocol.Address
	for _, a := range as {
		if a.Name == name && !slices.Contains(found, a.Address) {
			found = append(found, a.Address)
		}
	}
	return found, nil
}

func parseAlias(line string) (Alias, bool) {
	f := strings.Fields(line)
	if len(f) != 2 || !aliasGrammar.MatchString(f[0]) {
		return Alias{}, false
	}
	a, err := protocol.ParseAddress(f[1])
	return Alias{Name: f[0], Address: a}, err == nil
}

func (b *Box) aliasLines() ([]string, error) {
	data, err := os.ReadFile(b.path("aliases"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lines []string
	for l := range strings.Lines(string(data)) {
		lines = append(lines, strings.TrimRight(l, "\r\n"))
	}
	return lines, nil
}

func (b *Box) writeAliases(lines []string) error {
	var out strings.Builder
	for _, l := range lines {
		out.WriteString(l + "\n")
	}
	return writeFile(b.path("aliases"), []byte(out.String()))
}
