package sign

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/dromas-dev/dromas-client/protocol"
)

// Nothing in the module signs but this package: no other file outside
// protocol and sshsig, which make signatures for whoever holds a key, calls
// one of their signing functions, or a method that signs (an ssh.Signer's
// Sign or SignWithAlgorithm, a certificate's SignCert). So a mailbox's keys sign
// only through Identity and Work, and every signature is refused once the
// mailbox is finished, however a new path reaches one. internal/forge signs as a
// test's operator does, as a _test.go file may, so it is read as one: no
// file but a test imports it.
func TestOnlySignSigns(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	signing := map[string][]string{
		"protocol": {"Sign", "NewCertificate", "SignRevocation", "SignRevokedCertificates", "NewPass", "SignEnvelope"},
		"sshsig":   {"Sign"},
	}
	methods := []string{"Sign", "SignWithAlgorithm", "SignCert"}
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if slices.Contains([]string{".git", "testdata", "protocol", "sshsig", filepath.Join("client", "internal", "sign"), filepath.Join("internal", "forge")}, rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		files++
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, im := range f.Imports {
			if im.Path.Value == `"github.com/dromas-dev/dromas-client/internal/forge"` {
				t.Errorf("%s: imports internal/forge, which only a test may", rel)
			}
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && slices.Contains(signing[pkg.Name], sel.Sel.Name) {
				t.Errorf("%s: calls %s.%s: a mailbox signs only through package sign", rel, pkg.Name, sel.Sel.Name)
			} else if slices.Contains(methods, sel.Sel.Name) {
				t.Errorf("%s: calls a method %s: a mailbox signs only through package sign", rel, sel.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 20 {
		t.Fatalf("read %d files: the walk found too few to have read the module", files)
	}
}

// Every way Identity and Work sign is refused once the mailbox is finished,
// before anything is signed.
func TestAFinishedMailboxSignsNothing(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	gone := errors.New("finished")
	id, work := NewIdentity(key, func() error { return gone }), NewWork(key, func() error { return gone })
	var a protocol.Address
	tried := map[string]func() error{
		"Certify":             func() error { _, err := id.Certify(nil, key.PublicKey(), 1, time.Now()); return err },
		"Revocation":          func() error { _, err := id.Revocation(a); return err },
		"RevokedCertificates": func() error { _, err := id.RevokedCertificates(nil); return err },
		"Signature":           func() error { _, err := work.Signature([]byte("x"), "dromas-test"); return err },
		"Pass":                func() error { _, _, err := work.Pass(a, "example.org", time.Now()); return err },
	}
	for name, f := range tried {
		if err := f(); !errors.Is(err, gone) {
			t.Errorf("%s on a finished mailbox: %v", name, err)
		}
	}
	// Every method but PublicKey signs, and is tried above.
	for _, typ := range []reflect.Type{reflect.TypeOf(id), reflect.TypeOf(work)} {
		for i := range typ.NumMethod() {
			if m := typ.Method(i).Name; m != "PublicKey" && tried[m] == nil {
				t.Errorf("%s.%s is not tried on a finished mailbox", typ.Elem().Name(), m)
			}
		}
	}
}
