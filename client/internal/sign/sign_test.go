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
// only through Certifier, Identity and Work, and every signature is refused once the
// mailbox is finished, however a new path reaches one. internal/forge signs as a
// test's operator does, as a _test.go file may, so it is read as one: no
// file but a test imports it.
func TestOnlySignSigns(t *testing.T) {
	t.Parallel()
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

// signers is every signer this package gives, made while the mailbox is in
// mode and then answering checks, and every method of each that signs, by
// name: a method not listed here fails TestEverySignatureAsksTheMailbox.
func signers(t *testing.T, checks Checks, mode Mode) map[string]func() error {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	// The signers are made while the mailbox is in mode, and the checks then
	// changed: every signature asks again.
	made := Checks{Finished: func() error { return nil }, Mode: func() (Mode, error) { return mode, nil }}
	cert := NewCertifier(key, made)
	var id *Identity
	var work *Work
	if mode == IdentityMode {
		if id, err = cert.Identity(); err != nil {
			t.Fatal(err)
		}
		id.checks = checks
	} else {
		if work, err = NewWork(key, made); err != nil {
			t.Fatal(err)
		}
		work.checks = checks
	}
	cert.checks = checks
	pid, err := protocol.IdentityOf(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	a := pid.Address()
	p := &protocol.Prekey{Address: a, Serial: 1}
	_, wpriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wkey, err := ssh.NewPublicKey(wpriv.Public())
	if err != nil {
		t.Fatal(err)
	}
	r, err := protocol.NewRevokedCertificates(a, 1)
	if err != nil {
		t.Fatal(err)
	}
	tried := map[string]func() error{
		"Certifier.Certify":             func() error { _, err := cert.Certify(pid, wkey, 2, time.Now(), 2*time.Hour); return err },
		"Certifier.Revocation":          func() error { _, err := cert.Revocation(a); return err },
		"Certifier.RevokedCertificates": func() error { _, err := cert.RevokedCertificates(r); return err },
		"Certifier.Identity":            func() error { _, err := cert.Identity(); return err },
	}
	if id != nil {
		tried["Identity.Statement"] = func() error { _, err := id.Statement(p); return err }
		tried["Identity.Message"] = func() error { _, err := id.Message([]byte("x"), a); return err }
		tried["Identity.Pass"] = func() error { _, _, err := id.Pass(a, "example.org", time.Now()); return err }
	}
	if work != nil {
		tried["Work.Statement"] = func() error { _, err := work.Statement(p); return err }
		tried["Work.Message"] = func() error { _, err := work.Message([]byte("x"), a); return err }
		tried["Work.Pass"] = func() error { _, _, err := work.Pass(a, "example.org", time.Now()); return err }
	}
	return tried
}

// Every method of the three signers that signs is tried by the tests below:
// read from the types, so a new one is tried too.
func TestEverySignatureAsksTheMailbox(t *testing.T) {
	t.Parallel()
	none := Checks{Finished: func() error { return nil }, Mode: func() (Mode, error) { return IdentityMode, nil }}
	tried := signers(t, none, IdentityMode)
	for k, f := range signers(t, none, WorkingKeyMode) {
		tried[k] = f
	}
	for _, typ := range []reflect.Type{reflect.TypeFor[*Certifier](), reflect.TypeFor[*Identity](), reflect.TypeFor[*Work]()} {
		for i := range typ.NumMethod() {
			m := typ.Elem().Name() + "." + typ.Method(i).Name
			if typ.Method(i).Name != "PublicKey" && tried[m] == nil {
				t.Errorf("%s is not tried", m)
			}
		}
	}
}

// Every signature is refused once the mailbox is finished, before anything
// is signed, by a signer made before it was.
func TestAFinishedMailboxSignsNothing(t *testing.T) {
	t.Parallel()
	gone := errors.New("finished")
	for _, mode := range []Mode{IdentityMode, WorkingKeyMode} {
		checks := Checks{Finished: func() error { return gone }, Mode: func() (Mode, error) { return mode, nil }}
		for name, f := range signers(t, checks, mode) {
			if err := f(); !errors.Is(err, gone) {
				t.Errorf("mode %d: %s on a finished mailbox: %v", mode, name, err)
			}
		}
	}
}

// A mailbox that holds a trip it did not make signs nothing but its
// address's revocation, by a signer made before it held it.
func TestAForeignTripLeavesOnlyTheAddresssRevocation(t *testing.T) {
	t.Parallel()
	foreign := errors.New("a trip this mailbox did not make")
	for _, mode := range []Mode{IdentityMode, WorkingKeyMode} {
		checks := Checks{Finished: func() error { return nil }, Mode: func() (Mode, error) { return WorkingKeyMode, foreign }}
		for name, f := range signers(t, checks, mode) {
			err := f()
			switch {
			case name == "Certifier.Revocation" && err != nil:
				t.Errorf("mode %d: the address's revocation is refused: %v", mode, err)
			case name != "Certifier.Revocation" && !errors.Is(err, foreign):
				t.Errorf("mode %d: %s with a foreign trip held: %v", mode, name, err)
			}
		}
	}
}

// A signer of one mode signs nothing once the mailbox holds the other, and
// neither is made in the other: the mode is asked at every signature, so a
// trip kept part way through a command stops the identity's next signature.
func TestASignerSignsOnlyInItsMode(t *testing.T) {
	t.Parallel()
	for _, mode := range []Mode{IdentityMode, WorkingKeyMode} {
		other := WorkingKeyMode - mode
		checks := Checks{Finished: func() error { return nil }, Mode: func() (Mode, error) { return other, nil }}
		for name, f := range signers(t, checks, mode) {
			err := f()
			switch {
			case name == "Certifier.Identity" && (other == IdentityMode) != (err == nil):
				t.Errorf("Certifier.Identity in mode %d: %v", other, err)
			case strings.HasPrefix(name, "Certifier."):
				if name != "Certifier.Identity" && err != nil {
					t.Errorf("%s refused in mode %d: %v", name, other, err)
				}
			case other == WorkingKeyMode && !errors.Is(err, ErrNotIdentityMode),
				other == IdentityMode && !errors.Is(err, ErrNotWorkingKeyMode):
				t.Errorf("made in mode %d, %s in mode %d: %v", mode, name, other, err)
			}
		}
	}
}
