package protocol

import (
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every integer the protocol carries as JSON has one width on every platform,
// and is read by integers (json.go), which fills a uint64 or an int64 and no
// other type: a JSON member of a struct here that is a number of any kind is
// exactly uint64 or int64. Not int, uint or uintptr, whose width is the
// build's; not an int32 or a float, which encoding/json/v2 reads by its own
// rules (-5, 1e0); not a type declared on uint64, which integers does not
// match. The package is type-checked, so a declared type, an alias or a type
// from another package is seen as the compiler sees it, through pointers,
// slices, arrays and both sides of a map.
func TestWireIntegersHaveAFixedWidth(t *testing.T) {
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
	info := &types.Info{Types: map[ast.Expr]types.TypeAndValue{}}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	if _, err := conf.Check("github.com/IronGall-dev/irongall-client/protocol", fset, files, info); err != nil {
		t.Fatal(err)
	}
	members := 0
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok || field.Tag == nil {
				return true
			}
			tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
			if name, ok := tag.Lookup("json"); !ok || name == "-" {
				return true
			}
			members++
			for _, typ := range numbers(info.TypeOf(field.Type)) {
				t.Errorf("%s: a JSON member of type %s, which integers does not read: use uint64 or int64", fset.Position(field.Pos()), typ)
			}
			return true
		})
	}
	if members == 0 {
		t.Fatal("no JSON member found: the test reads nothing")
	}
}

// numbers returns each numeric type in typ, through pointers, slices, arrays
// and a map's key and value, that is not exactly uint64 or int64. A []byte
// or [N]byte is a string of base64 in JSON, not numbers.
func numbers(typ types.Type) []types.Type {
	switch x := types.Unalias(typ).(type) {
	case *types.Pointer:
		return numbers(x.Elem())
	case *types.Slice:
		if types.Identical(x.Elem(), types.Typ[types.Byte]) {
			return nil
		}
		return numbers(x.Elem())
	case *types.Array:
		if types.Identical(x.Elem(), types.Typ[types.Byte]) {
			return nil
		}
		return numbers(x.Elem())
	case *types.Map:
		return append(numbers(x.Key()), numbers(x.Elem())...)
	}
	if b, ok := typ.Underlying().(*types.Basic); ok && b.Info()&types.IsNumeric != 0 &&
		!types.Identical(typ, types.Typ[types.Uint64]) && !types.Identical(typ, types.Typ[types.Int64]) {
		return []types.Type{typ}
	}
	return nil
}
