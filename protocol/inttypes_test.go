package protocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every integer the protocol carries as JSON has one width on every platform:
// a member of a struct here is int64 or uint64, never int, uint or uintptr,
// whose width is the build's. A value read on one machine is then the value
// read on any other, and integers (json.go) reads each member it fills.
func TestWireIntegersHaveAFixedWidth(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	members := 0
	for _, name := range files {
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
		ast.Inspect(f, func(n ast.Node) bool {
			field, ok := n.(*ast.Field)
			if !ok || field.Tag == nil {
				return true
			}
			tag := reflect.StructTag(strings.Trim(field.Tag.Value, "`"))
			if _, ok := tag.Lookup("json"); !ok {
				return true
			}
			members++
			typ := field.Type
			for unwrapped := false; !unwrapped; {
				switch x := typ.(type) {
				case *ast.StarExpr:
					typ = x.X
				case *ast.ArrayType:
					typ = x.Elt
				default:
					unwrapped = true
				}
			}
			if id, ok := typ.(*ast.Ident); ok && (id.Name == "int" || id.Name == "uint" || id.Name == "uintptr") {
				t.Errorf("%s: a JSON member of type %s, whose width is the build's: use int64 or uint64", fset.Position(field.Pos()), id.Name)
			}
			return true
		})
	}
	if members == 0 {
		t.Fatal("no JSON member found: the test reads nothing")
	}
}
