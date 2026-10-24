package client

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Every step steps lists is marked once in the code, by a step call that
// names it as written there, and every step marked is listed: so the crash
// tests, which kill a process at each listed step, kill one at every step
// there is.
func TestStepsAreTheCode(t *testing.T) {
	t.Parallel()
	listed := map[string]bool{}
	for _, names := range steps {
		for _, n := range names {
			if listed[n] {
				t.Errorf("step %q is listed twice", n)
			}
			listed[n] = true
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	marked := map[string]int{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if fn, ok := c.Fun.(*ast.Ident); !ok || fn.Name != "step" {
				return true
			}
			lit, ok := c.Args[0].(*ast.BasicLit)
			if len(c.Args) != 1 || !ok || lit.Kind != token.STRING {
				t.Errorf("%s: a step not named as written", name)
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			marked[s]++
			return true
		})
	}
	for n := range listed {
		if marked[n] != 1 {
			t.Errorf("step %q is marked %d times in the code", n, marked[n])
		}
	}
	for n := range marked {
		if !listed[n] {
			t.Errorf("step %q is marked in the code and not listed", n)
		}
	}
}
