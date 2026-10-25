package api_test

import (
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/api"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/pb33f/libopenapi"
	v3 "github.com/pb33f/libopenapi/datamodel/high/v3"
)

func model(t *testing.T) *v3.Document {
	t.Helper()
	doc, err := libopenapi.NewDocument(api.OpenAPI)
	if err != nil {
		t.Fatal(err)
	}
	m, err := doc.BuildV3Model()
	if err != nil {
		t.Fatal(err)
	}
	return &m.Model
}

// Each error status's codes are the ones protocol gives that status, no more
// and no fewer, so a code added to protocol/errors.go and not here fails.
func TestEachStatusHasProtocolsCodes(t *testing.T) {
	m := model(t)
	want := map[int][]string{}
	for _, c := range protocol.Codes() {
		want[c.Status()] = append(want[c.Status()], string(c))
	}
	got := map[int][]string{}
	for name, r := range m.Components.Responses.FromOldest() {
		if r.Content == nil {
			continue
		}
		mt, ok := r.Content.Get(protocol.ProblemContentType)
		if !ok {
			continue
		}
		var status int
		var codes []string
		for _, part := range mt.Schema.Schema().AllOf {
			s := part.Schema()
			if s.Properties == nil {
				continue
			}
			if p, ok := s.Properties.Get("status"); ok && p.Schema().Const != nil {
				status, _ = strconv.Atoi(p.Schema().Const.Value)
			}
			if p, ok := s.Properties.Get("code"); ok {
				cs := p.Schema()
				if cs.Const != nil {
					codes = append(codes, cs.Const.Value)
				}
				for _, n := range cs.Enum {
					codes = append(codes, n.Value)
				}
			}
		}
		if status == 0 {
			t.Errorf("response %s: an error body with no status", name)
			continue
		}
		got[status] = append(got[status], codes...)
	}
	for status, codes := range want {
		slices.Sort(codes)
		g := got[status]
		slices.Sort(g)
		if !slices.Equal(g, codes) {
			t.Errorf("status %d: the description has %v, protocol has %v", status, g, codes)
		}
	}
	for status := range got {
		if _, ok := want[status]; !ok {
			t.Errorf("status %d: in the description, and protocol gives no code that status", status)
		}
	}
}

// Each body's members are its Go type's JSON members, so a member renamed or
// added on one side and not the other fails.
func TestEachBodyHasItsTypesMembers(t *testing.T) {
	m := model(t)
	for name, typ := range map[string]any{
		"RegisterRequest":  protocol.RegisterRequest{},
		"PrekeyRequest":    protocol.PrekeyRequest{},
		"BoxResponse":      protocol.BoxResponse{},
		"Receipt":          protocol.Receipt{},
		"MessageList":      protocol.MessageList{},
		"MessageInfo":      protocol.MessageInfo{},
		"RevocationRecord": protocol.Revocations{},
		"RevokedRecord":    protocol.Revocations{},
		"ACLRequest":       protocol.ACLDocument{},
		"ACL":              protocol.ACLDocument{},
		"AdoptRequest":     protocol.AdoptRequest{},
		"AccountResponse":  protocol.AccountResponse{},
		"Problem":          protocol.Problem{},
	} {
		sp, ok := m.Components.Schemas.Get(name)
		if !ok {
			t.Errorf("no schema %s", name)
			continue
		}
		var got []string
		for p := range sp.Schema().Properties.KeysFromOldest() {
			got = append(got, p)
		}
		want := members(reflect.TypeOf(typ))
		slices.Sort(got)
		slices.Sort(want)
		if !slices.Equal(got, want) {
			t.Errorf("%s: the description has %v, the Go type %v", name, got, want)
		}
	}
}

func members(t reflect.Type) []string {
	var names []string
	for f := range t.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name != "" && name != "-" {
			names = append(names, name)
		}
	}
	return names
}

// Every path that has a GET has a HEAD that is that GET without content
// (RFC 9110 §9.3.2; PROTOCOL.md §11.2): the same parameters, security and
// statuses, each with the same header fields and no content, but the GET's
// 206, since a HEAD's Range is ignored (§14.2). The paths are the
// description's own, so a GET added without its HEAD fails.
func TestEveryGetHasItsHead(t *testing.T) {
	m := model(t)
	for path, item := range m.Paths.PathItems.FromOldest() {
		get, head := item.Get, item.Head
		switch {
		case get == nil && head == nil:
			continue
		case get == nil:
			t.Errorf("%s: a HEAD with no GET", path)
			continue
		case head == nil:
			t.Errorf("%s: a GET with no HEAD", path)
			continue
		}
		params := func(op *v3.Operation) []string {
			var names []string
			for _, p := range op.Parameters {
				names = append(names, p.In+" "+p.Name)
			}
			slices.Sort(names)
			return names
		}
		if g, h := params(get), params(head); !slices.Equal(g, h) {
			t.Errorf("%s: the GET takes %v, the HEAD %v", path, g, h)
		}
		if (get.Security == nil) != (head.Security == nil) || len(get.Security) != len(head.Security) {
			t.Errorf("%s: the GET's security is %v, the HEAD's %v", path, get.Security, head.Security)
		}
		var getCodes, headCodes []string
		for code := range get.Responses.Codes.KeysFromOldest() {
			if code != "206" {
				getCodes = append(getCodes, code)
			}
		}
		for code, r := range head.Responses.Codes.FromOldest() {
			headCodes = append(headCodes, code)
			if r.Content != nil && r.Content.Len() > 0 {
				t.Errorf("%s: the HEAD's %s has content", path, code)
			}
			g, ok := get.Responses.Codes.Get(code)
			if !ok {
				continue
			}
			names := func(r *v3.Response) []string {
				var n []string
				if r.Headers != nil {
					for name := range r.Headers.KeysFromOldest() {
						n = append(n, name)
					}
				}
				slices.Sort(n)
				return n
			}
			if gn, hn := names(g), names(r); !slices.Equal(gn, hn) {
				t.Errorf("%s: the GET's %s carries %v, the HEAD's %v", path, code, gn, hn)
			}
		}
		slices.Sort(getCodes)
		slices.Sort(headCodes)
		if !slices.Equal(getCodes, headCodes) {
			t.Errorf("%s: the GET answers %v, the HEAD %v", path, getCodes, headCodes)
		}
	}
}
