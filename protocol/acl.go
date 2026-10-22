package protocol

import (
	"bytes"
	"errors"
	"slices"
)

// AnyAddress is the ACL entry that matches every address, as "*" does in a
// Matrix room's server ACL. It is the only pattern: an entry is an address
// or this.
const AnyAddress = "*"

// ACLDocument is a box's sender ACL as it travels (PROTOCOL.md §6.2): the
// body of PUT /v1/<address>/acl, which replaces the box's ACL whole, and
// the answer to GET. It carries no version: the server's ETag of it is what
// a writer that read it names in If-Match. Allow is required, so that an ACL
// always says whom it lets in: a document with none is refused, where Matrix
// reads one as letting in nobody. Deny may be left out, for none. Write both
// lists, empty or not: an empty Allow that is left out is not "nobody" but a
// refusal.
type ACLDocument struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// ACL is a sender ACL in its checked form: who may send to a box. Deny is
// read first and then allow, as Matrix reads a room's server ACL, and a
// sender neither matches is refused. A box with no ACL takes mail from
// everyone: a nil *ACL is that.
type ACL struct {
	Allow ACLList
	Deny  ACLList
}

// ACLList is one of an ACL's lists: AnyAddress, addresses, or both, the
// addresses sorted and each once.
type ACLList struct {
	Any   bool
	Addrs []Address
}

// Has reports whether the list matches a.
func (l ACLList) Has(a Address) bool {
	if l.Any {
		return true
	}
	_, ok := slices.BinarySearchFunc(l.Addrs, a, compareAddresses)
	return ok
}

// Len is the list's number of entries, AnyAddress being one.
func (l ACLList) Len() int {
	if l.Any {
		return len(l.Addrs) + 1
	}
	return len(l.Addrs)
}

// Entries is the list as it travels: AnyAddress first if it is there, then
// the addresses in order. It is never nil, so an empty list is written as
// one.
func (l ACLList) Entries() []string {
	out := make([]string, 0, l.Len())
	if l.Any {
		out = append(out, AnyAddress)
	}
	for _, a := range l.Addrs {
		out = append(out, a.String())
	}
	return out
}

// Equal reports whether two lists match the same addresses.
func (l ACLList) Equal(m ACLList) bool {
	return l.Any == m.Any && slices.Equal(l.Addrs, m.Addrs)
}

// NewACLList is the list of the given entries: AnyAddress or addresses, in
// any order and with repeats, which it drops.
func NewACLList(all bool, addrs []Address) ACLList {
	sorted := slices.Clone(addrs)
	slices.SortFunc(sorted, compareAddresses)
	return ACLList{Any: all, Addrs: slices.Compact(sorted)}
}

func compareAddresses(x, y Address) int { return bytes.Compare(x[:], y[:]) }

// Admits reports whether a box whose ACL is a takes mail from a sender:
// with no ACL, everyone; with one, a sender its deny list does not match and
// its allow list does.
func (a *ACL) Admits(from Address) bool {
	return a == nil || (!a.Deny.Has(from) && a.Allow.Has(from))
}

// SameLists reports whether two ACLs admit the same senders by the same
// lists. No ACL is the same as one that allows AnyAddress and denies
// nothing.
func (a *ACL) SameLists(b *ACL) bool {
	x, y := a.orOpen(), b.orOpen()
	return x.Allow.Equal(y.Allow) && x.Deny.Equal(y.Deny)
}

// orOpen is a, or the ACL a box with none has: allowing AnyAddress and
// denying nothing.
func (a *ACL) orOpen() *ACL {
	if a == nil {
		return &ACL{Allow: ACLList{Any: true}}
	}
	return a
}

// Document is the ACL as it travels, in its one form: each list as Entries
// writes it. A box with none answers GET with this of nil: allowing
// AnyAddress and denying nothing.
func (a *ACL) Document() ACLDocument {
	o := a.orOpen()
	return ACLDocument{Allow: o.Allow.Entries(), Deny: o.Deny.Entries()}
}

// Errors of an ACL document.
var (
	// ErrACL is a document that is not an ACL: no allow list, or an entry
	// that is neither an address nor AnyAddress.
	ErrACL = errors.New("not an ACL: an allow list, and entries that are each an address or *")
	// ErrACLTooLarge is an ACL with more entries in its two lists together
	// than the server takes.
	ErrACLTooLarge = errors.New("the ACL has more entries than this server takes")
)

// CheckACL checks an ACL document as a server takes one, and returns it in
// its checked form. maxEntries bounds the entries of both lists together,
// AnyAddress counting as one and a repeat counting as often as it is
// written; 0 sets no bound.
func CheckACL(d *ACLDocument, maxEntries int) (*ACL, error) {
	if d.Allow == nil {
		return nil, ErrACL
	}
	if maxEntries > 0 && len(d.Allow)+len(d.Deny) > maxEntries {
		return nil, ErrACLTooLarge
	}
	allow, err := parseACLList(d.Allow)
	if err != nil {
		return nil, err
	}
	deny, err := parseACLList(d.Deny)
	if err != nil {
		return nil, err
	}
	return &ACL{Allow: allow, Deny: deny}, nil
}

func parseACLList(entries []string) (ACLList, error) {
	all := false
	addrs := make([]Address, 0, len(entries))
	for _, e := range entries {
		if e == AnyAddress {
			all = true
			continue
		}
		a, err := ParseAddress(e)
		if err != nil {
			return ACLList{}, ErrACL
		}
		addrs = append(addrs, a)
	}
	return NewACLList(all, addrs), nil
}
