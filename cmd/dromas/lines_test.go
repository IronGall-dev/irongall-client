package main

import (
	"encoding/json"
	"go/ast"
	"go/constant"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/protocol"
)

// A line that carries the envelope carries none of its members beside it
// (PRECEDENTS.md, Part 2, § 3e; #441 item 3): the envelope may gain members
// inside v1, and one beside the line's own could take a name the line has.
// The lines are read from this package's source: every call of line and
// object, with the names it writes, and every typed line, with the JSON
// members of the type marshalled into it. A line that carries no envelope may
// carry one of its checked values as a member of its own, as held's from and
// sent's to do.
func TestNoLineCarriesAnEnvelopeMemberBesideTheEnvelope(t *testing.T) {
	t.Parallel()
	// The envelope's members, as protocol writes them, each optional one
	// given a value.
	full, err := (&protocol.Envelope{Body: json.RawMessage(`"b"`), Subject: "s", InReplyTo: "r", Supersedes: "p", Identity: []byte("i")}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(full, &members); err != nil {
		t.Fatal(err)
	}
	envelope := slices.Sorted(maps.Keys(members))
	if !slices.Contains(envelope, "from") || !slices.Contains(envelope, "msg_id") {
		t.Fatalf("the envelope's members, read from protocol.Envelope: %q", envelope)
	}
	beside := func(names []string) []string {
		var met []string
		if slices.Contains(names, "envelope") {
			for _, n := range names {
				if slices.Contains(envelope, n) {
					met = append(met, n)
				}
			}
		}
		return met
	}

	fset, files, info := typeChecked(t)
	var lines, withEnvelope int
	for _, f := range files {
		// The value of an "envelope" member is the envelope itself, whose
		// members are its own: the object that builds it is not a line.
		inside := map[ast.Expr]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok || inside[call] {
				return true
			}
			at := fset.Position(call.Pos())
			switch fn.Name {
			case "line", "object":
				if fn.Name == "line" && strings.HasSuffix(at.Filename, "output.go") && funcAt(f, call.Pos()) == "typed" {
					return true // typed's own: its members are its object's, read below
				}
				kv := call.Args
				if fn.Name == "line" {
					kv = kv[1:]
				}
				names, spread := []string{}, call.Ellipsis.IsValid()
				for i := 0; i+1 < len(kv); i += 2 {
					v := info.Types[kv[i]].Value
					if v == nil || v.Kind() != constant.String {
						t.Errorf("%s: a member named by no constant", at)
						continue
					}
					name := constant.StringVal(v)
					names = append(names, name)
					if name == "envelope" {
						ast.Inspect(kv[i+1], func(n ast.Node) bool {
							if e, ok := n.(ast.Expr); ok {
								inside[e] = true
							}
							return true
						})
					}
				}
				if fn.Name == "line" {
					lines++
				}
				if slices.Contains(names, "envelope") {
					withEnvelope++
					if spread {
						t.Errorf("%s: a line that carries the envelope and members whose names this test cannot read", at)
					}
				}
				if met := beside(names); len(met) > 0 {
					t.Errorf("%s: %q beside the envelope", at, met)
				}
			case "typed":
				lines++
				typ := marshalled(t, fset, info, f, call.Args[1])
				if typ == nil {
					return true
				}
				eachObject(typ, func(where string, names []string, own bool) {
					if own {
						t.Errorf("%s: %s writes its own JSON, whose members this test cannot read", at, where)
					}
					if slices.Contains(names, "envelope") {
						withEnvelope++
					}
					if met := beside(names); len(met) > 0 {
						t.Errorf("%s: %s: %q beside the envelope", at, where, met)
					}
				})
			}
			return true
		})
	}
	// Control: the reading found the lines, and the two that carry the
	// envelope, mail and mail_headers.
	if lines < 30 || withEnvelope < 2 {
		t.Errorf("read %d lines, %d carrying the envelope: the reading of the source missed them", lines, withEnvelope)
	}
}

// typeChecked is this package's source, without its tests, type-checked.
func typeChecked(t *testing.T) (*token.FileSet, []*ast.File, *types.Info) {
	t.Helper()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) //nolint:gosec // this package's own source
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}, Defs: map[*ast.Ident]types.Object{}, Uses: map[*ast.Ident]types.Object{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	if _, err := conf.Check("github.com/dromas-dev/dromas-client/cmd/dromas", fset, files, info); err != nil {
		t.Fatal(err)
	}
	return fset, files, info
}

// funcAt is the name of the function in f whose body holds pos.
func funcAt(f *ast.File, pos token.Pos) string {
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Pos() <= pos && pos < fd.End() {
			return fd.Name.Name
		}
	}
	return ""
}

// marshalled is the type of the value that obj, a typed line's object, was
// marshalled from: obj is a variable assigned json.Marshal(value) in the
// function that calls typed. Any other object fails the test.
func marshalled(t *testing.T, fset *token.FileSet, info *types.Info, f *ast.File, obj ast.Expr) types.Type {
	t.Helper()
	id, ok := obj.(*ast.Ident)
	if !ok {
		t.Errorf("%s: a typed line whose object is not a variable", fset.Position(obj.Pos()))
		return nil
	}
	v := info.Uses[id]
	var typ types.Type
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 || len(as.Lhs) == 0 {
			return true
		}
		lhs, ok := as.Lhs[0].(*ast.Ident)
		if !ok || info.Defs[lhs] != v {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if sel, isSel := callee(call); ok && isSel && sel == "json.Marshal" && len(call.Args) == 1 {
			typ = info.TypeOf(call.Args[0])
		}
		return false
	})
	if typ == nil {
		t.Errorf("%s: a typed line whose object is not json.Marshal of a value", fset.Position(obj.Pos()))
	}
	return typ
}

// callee is a call's function as pkg.Name, when it is a selector.
func callee(call *ast.CallExpr) (string, bool) {
	if call == nil {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	x, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	return x.Name + "." + sel.Sel.Name, true
}

// eachObject calls fn with the JSON member names of every struct that typ
// marshals as, typ's own and each nested one, an embedded struct's members
// among its parent's, as encoding/json writes them; and with own set, and no
// names, for a struct that writes itself (a MarshalJSON method), whose fields
// do not say what it writes.
func eachObject(typ types.Type, fn func(where string, names []string, own bool)) {
	seen := map[types.Type]bool{}
	var walk func(types.Type)
	walk = func(typ types.Type) {
		for {
			switch u := typ.(type) {
			case *types.Pointer:
				typ = u.Elem()
				continue
			case *types.Slice:
				typ = u.Elem()
				continue
			case *types.Array:
				typ = u.Elem()
				continue
			case *types.Map:
				typ = u.Elem()
				continue
			}
			break
		}
		if seen[typ] {
			return
		}
		seen[typ] = true
		s, ok := typ.Underlying().(*types.Struct)
		if !ok {
			return
		}
		if marshals(typ) {
			fn(typ.String(), nil, true)
			return
		}
		var names []string
		var members func(*types.Struct)
		members = func(s *types.Struct) {
			for i := range s.NumFields() {
				f := s.Field(i)
				name, _, _ := strings.Cut(reflect.StructTag(s.Tag(i)).Get("json"), ",")
				if name == "-" || !f.Exported() {
					continue
				}
				if f.Embedded() && name == "" {
					if es, ok := f.Type().Underlying().(*types.Struct); ok {
						members(es)
						continue
					}
				}
				if name == "" {
					name = f.Name()
				}
				names = append(names, name)
				walk(f.Type())
			}
		}
		members(s)
		fn(typ.String(), names, false)
	}
	walk(typ)
}

// marshals reports whether typ, or a pointer to it, has a MarshalJSON method.
func marshals(typ types.Type) bool {
	for _, t := range []types.Type{typ, types.NewPointer(typ)} {
		if m, _, _ := types.LookupFieldOrMethod(t, true, nil, "MarshalJSON"); m != nil {
			if _, ok := m.(*types.Func); ok {
				return true
			}
		}
	}
	return false
}
