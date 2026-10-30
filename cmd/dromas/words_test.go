package main

import (
	"go/ast"
	"go/constant"
	"regexp"
	"testing"

	"github.com/spf13/cobra"
)

// oldWords matches "mail" and "box" as words of their own, or as a part of a
// name between underscores or hyphens: what a mailbox holds is a message, and
// where it lands is a mailbox (inbox and outbox are its folders).
var oldWords = regexp.MustCompile(`(?i)(^|[^a-z])(mail|mails|box|boxes)([^a-z]|$)`)

// Every help, every line's type and every member a line names say message
// and mailbox, never mail or box. The lines are read from this package's
// source, as TestNoLineCarriesAnEnvelopeMemberBesideTheEnvelope reads them.
func TestTheClientSaysMessageAndMailbox(t *testing.T) {
	t.Setenv("DROMAS_HOME", t.TempDir())
	for _, s := range []string{"held mail", "a box", "box_unread", "mail_headers"} {
		if !oldWords.MatchString(s) {
			t.Fatalf("the reading misses %q", s)
		}
	}
	for _, s := range []string{"mailbox_unread", "inbox", "outbox", "message_headers"} {
		if oldWords.MatchString(s) {
			t.Fatalf("the reading matches %q", s)
		}
	}

	var helps int
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		helps++
		if m := oldWords.FindString(helpText(c)); m != "" {
			t.Errorf("the help of %s says %q:\n%s", c.CommandPath(), m, helpText(c))
		}
		for _, s := range c.Commands() {
			walk(s)
		}
	}
	walk((&cli{}).tree())

	fset, files, info := typeChecked(t)
	var names int
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fn, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			var named []ast.Expr
			switch fn.Name {
			case "line":
				named = append(named, call.Args[0])
				for i := 1; i+1 < len(call.Args); i += 2 {
					named = append(named, call.Args[i])
				}
			case "object":
				for i := 0; i+1 < len(call.Args); i += 2 {
					named = append(named, call.Args[i])
				}
			case "typed":
				named = append(named, call.Args[0])
			}
			for _, e := range named {
				if v := info.Types[e].Value; v != nil && v.Kind() == constant.String {
					names++
					if s := constant.StringVal(v); oldWords.MatchString(s) {
						t.Errorf("%s: a line names %q", fset.Position(e.Pos()), s)
					}
				}
			}
			return true
		})
	}
	if helps < 20 || names < 100 {
		t.Fatalf("read %d helps and %d names", helps, names)
	}
}
