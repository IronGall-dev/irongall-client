package protocol

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func aclAddr(c byte) Address {
	var a Address
	for i := range a {
		a[i] = c
	}
	return a
}

func aclDoc(t *testing.T, text string) *ACLDocument {
	t.Helper()
	var d ACLDocument
	if err := UnmarshalRequest([]byte(text), &d); err != nil {
		t.Fatalf("%s: %v", text, err)
	}
	return &d
}

// An ACL reads deny first and then allow, as Matrix reads a room's server
// ACL, and a box with none takes mail from everyone.
func TestACLAdmits(t *testing.T) {
	a, b, c := aclAddr(0xaa), aclAddr(0xbb), aclAddr(0xcc)
	var none *ACL
	if !none.Admits(a) {
		t.Fatal("no ACL refuses a sender")
	}
	for _, tc := range []struct {
		name    string
		acl     ACL
		admits  []Address
		refuses []Address
	}{
		{"allow everyone", ACL{Allow: ACLList{Any: true}}, []Address{a, b, c}, nil},
		{"allow nobody", ACL{}, nil, []Address{a, b, c}},
		{"allow two", ACL{Allow: NewACLList(false, []Address{b, a})}, []Address{a, b}, []Address{c}},
		{"deny wins over allow everyone", ACL{Allow: ACLList{Any: true}, Deny: NewACLList(false, []Address{b})}, []Address{a, c}, []Address{b}},
		{"deny wins over allow listed", ACL{Allow: NewACLList(false, []Address{a, b}), Deny: NewACLList(false, []Address{b})}, []Address{a}, []Address{b, c}},
		{"deny everyone", ACL{Allow: ACLList{Any: true}, Deny: ACLList{Any: true}}, nil, []Address{a, b, c}},
	} {
		for _, x := range tc.admits {
			if !tc.acl.Admits(x) {
				t.Errorf("%s: refuses %x", tc.name, x[:1])
			}
		}
		for _, x := range tc.refuses {
			if tc.acl.Admits(x) {
				t.Errorf("%s: admits %x", tc.name, x[:1])
			}
		}
	}
}

// A document says its version and whom it allows; deny may be left out. A
// document with no allow list is refused, never read as allowing nobody or
// everybody.
func TestCheckACL(t *testing.T) {
	a, b := aclAddr(0xaa).String(), aclAddr(0xbb).String()
	ok := func(text string) *ACL {
		t.Helper()
		acl, err := CheckACL(aclDoc(t, text), 0)
		if err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		return acl
	}
	if acl := ok(`{"version":1,"allow":["*"]}`); !acl.Allow.Any || acl.Deny.Len() != 0 || acl.Version != 1 {
		t.Errorf("allow everyone, deny left out: %+v", acl)
	}
	if acl := ok(`{"version":2,"allow":[],"deny":[]}`); acl.Allow.Len() != 0 || acl.Admits(aclAddr(0xaa)) {
		t.Errorf("an empty allow list: %+v", acl)
	}
	acl := ok(`{"version":3,"allow":["` + b + `","` + a + `","` + b + `"],"deny":["` + a + `"]}`)
	if acl.Allow.Len() != 2 || acl.Allow.Addrs[0] != aclAddr(0xaa) || !acl.Deny.Has(aclAddr(0xaa)) || acl.Admits(aclAddr(0xaa)) || !acl.Admits(aclAddr(0xbb)) {
		t.Errorf("sorted, each once, deny first: %+v", acl)
	}
	for _, text := range []string{
		`{"allow":["*"]}`,                            // no version
		`{"version":0,"allow":["*"]}`,                // not a version
		`{"version":9007199254740992,"allow":["*"]}`, // above MaxSerial: the JSON rules refuse it first
		`{"version":1}`,                              // no allow list
		`{"version":1,"allow":null}`,                 // null is left out
		`{"version":1,"allow":["*"],"deny":["` + strings.ToUpper(a) + `"]}`,
		`{"version":1,"allow":["` + a[:63] + `"]}`,
		`{"version":1,"allow":["*` + a[1:] + `"]}`, // no partial pattern
		`{"version":1,"allow":["**"]}`,
	} {
		var d ACLDocument
		if err := UnmarshalRequest([]byte(text), &d); err != nil {
			continue // refused as JSON, which is as good
		}
		if acl, err := CheckACL(&d, 0); !errors.Is(err, ErrACL) {
			t.Errorf("%s: %+v, %v", text, acl, err)
		}
	}
	var d ACLDocument
	if err := UnmarshalRequest([]byte(`{"version":1,"allow":["*"],"block":[]}`), &d); err == nil {
		t.Error("a request with a member an ACL does not have was taken")
	}
	if _, err := CheckACL(aclDoc(t, `{"version":1,"allow":["*","`+a+`"],"deny":["`+b+`"]}`), 2); !errors.Is(err, ErrACLTooLarge) {
		t.Errorf("three entries under a bound of two: %v", err)
	}
}

// What travels names every list, an empty one as [], and no ACL is version
// 0 allowing everyone: so a writer cannot drop an empty allow list and turn
// nobody into everybody.
func TestACLDocument(t *testing.T) {
	var none *ACL
	got, err := json.Marshal(none.Document())
	if err != nil || string(got) != `{"version":0,"allow":["*"],"deny":[]}` {
		t.Fatalf("no ACL: %s, %v", got, err)
	}
	nobody := &ACL{Version: 4}
	if got, _ := json.Marshal(nobody.Document()); string(got) != `{"version":4,"allow":[],"deny":[]}` {
		t.Fatalf("allow nobody: %s", got)
	}
	a := aclAddr(0xaa)
	some := &ACL{Version: 5, Allow: NewACLList(true, []Address{a}), Deny: NewACLList(false, []Address{a})}
	back, err := CheckACL(aclDoc(t, mustJSON(t, some.Document())), 0)
	if err != nil || !back.SameLists(some) || back.Version != 5 {
		t.Fatalf("a round trip: %+v, %v", back, err)
	}
	if !none.SameLists(&ACL{Version: 9, Allow: ACLList{Any: true}}) || none.SameLists(nobody) {
		t.Error("no ACL is the same as allowing everyone and denying nobody, and only that")
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
