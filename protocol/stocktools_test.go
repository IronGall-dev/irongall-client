package protocol

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/IronGall-dev/irongall-client/internal/agetool"
)

// TestVectorsByToolsNotOurs checks the crypto and container vectors with
// tools this project did not write, so that each is the standard's format and
// not this code's reading of it (testdata/vectors/README.md, PROTOCOL.md §11):
// age decrypts each message with its prekey's published test identity to
// exactly its plaintext; head and sed split that plaintext into the line and
// its signature; ssh-keygen reads each certificate and verifies each signature
// under it, at the vectors' time; and sha256sum gives each address. Nothing
// from this package reads a vector here: the namespaces are the spec's.
func TestVectorsByToolsNotOurs(t *testing.T) {
	dir, err := filepath.Abs(vectors)
	if err != nil {
		t.Fatal(err)
	}
	tool := func(t *testing.T, name string) {
		t.Helper()
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not installed", name)
		}
	}
	run := func(t *testing.T, stdin []byte, name string, args ...string) ([]byte, error) {
		t.Helper()
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK=", "LC_ALL=C")
		cmd.Stdin = bytes.NewReader(stdin)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			return out.Bytes(), errors.New(strings.TrimSpace(errb.String() + " " + err.Error()))
		}
		return out.Bytes(), nil
	}
	file := func(t *testing.T, name string) []byte {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	address := func(t *testing.T, box string) string {
		t.Helper()
		return strings.TrimSpace(string(file(t, box+"/address")))
	}
	// The key line of an identity document, as an authorized_keys line.
	key := func(t *testing.T, box string) string {
		t.Helper()
		lines := strings.Split(string(file(t, box+"/identity.doc")), "\n")
		if len(lines) < 2 {
			t.Fatalf("%s/identity.doc has no key line", box)
		}
		return lines[1]
	}
	// The vectors' time, as ssh-keygen's verify-time takes one.
	at := strings.NewReplacer("-", "", "T", "", ":", "").Replace(strings.TrimSpace(string(file(t, "now"))))

	t.Run("sha256sum", func(t *testing.T) {
		tool(t, "sha256sum")
		for _, box := range []string{"a", "b", "c"} {
			out, err := run(t, file(t, box+"/identity.doc"), "sha256sum")
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Fields(string(out))[0]; got != address(t, box) {
				t.Errorf("%s: sha256sum of identity.doc is %s, the address is %s", box, got, address(t, box))
			}
		}
	})

	t.Run("age", func(t *testing.T) {
		path, err := agetool.Path()
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("PATH", path)
		v, _ := run(t, nil, "age", "--version")
		t.Logf("age %s", strings.TrimSpace(string(v)))
		for _, m := range []struct{ msg, key string }{{"a-to-b", "b-1.pq"}, {"a-to-c", "c-1.classic"}} {
			out, err := run(t, nil, "age", "-d", "-i", "input/"+m.key+".key", "message/"+m.msg+".age")
			if err != nil {
				t.Errorf("%s: age -d: %v", m.msg, err)
				continue
			}
			if !bytes.Equal(out, file(t, "message/"+m.msg+".plain")) {
				t.Errorf("%s: age decrypts it to other bytes than its .plain", m.msg)
			}
		}
	})

	t.Run("split", func(t *testing.T) {
		tool(t, "head")
		tool(t, "sed")
		for _, m := range []string{"a-to-b", "a-to-c"} {
			line, err := run(t, nil, "head", "-n", "1", "message/"+m+".plain")
			if err != nil {
				t.Fatal(err)
			}
			sig, err := run(t, nil, "sed", "-n", "2,/^-----END SSH SIGNATURE-----$/p", "message/"+m+".plain")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(line, file(t, "message/"+m+".line")) || !bytes.Equal(sig, file(t, "message/"+m+".sig")) {
				t.Errorf("%s: head and sed do not split its plaintext into its .line and .sig", m)
			}
		}
	})

	t.Run("ssh-keygen", func(t *testing.T) {
		tool(t, "ssh-keygen")
		work := t.TempDir()
		signers := func(name, box string, ca bool) string {
			line := address(t, box) + " "
			if ca {
				line += "cert-authority "
			}
			p := filepath.Join(work, name)
			if err := os.WriteFile(p, []byte(line+key(t, box)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}
		verify := func(t *testing.T, signersFile, box, ns, msg, sig string) {
			t.Helper()
			if _, err := run(t, file(t, msg), "ssh-keygen", "-Y", "verify", "-f", signersFile, "-I", address(t, box), "-n", ns, "-s", sig, "-O", "verify-time="+at); err != nil {
				t.Errorf("%s over %s: %v", sig, msg, err)
			}
		}
		for _, c := range []string{"a/work-cert.pub", "b/work-cert.pub", "c/work-cert.pub"} {
			if _, err := run(t, nil, "ssh-keygen", "-L", "-f", c); err != nil {
				t.Errorf("ssh-keygen -L %s: %v", c, err)
			}
		}
		ns := func(tag, box string) string { return tag + ":" + address(t, box) }
		for _, box := range []string{"a", "b", "c"} {
			under := signers(box+"-ca", box, true)
			verify(t, under, box, ns("irongall-prekey-v1", box), box+"/prekey-1.txt", box+"/prekey-1.txt.sig")
		}
		underA := signers("a-ca", "a", true)
		verify(t, underA, "a", ns("irongall-prekey-v1", "a"), "a/prekey-2.txt", "a/prekey-2.txt.sig")
		verify(t, underA, "a", ns("irongall-prekey-v1", "a"), "a/prekey-1.txt", "a/prekey-1.txt.sha256.sig")
		verify(t, underA, "a", ns("irongall-pass-v1", "a"), "a/pass.txt", "a/pass.sig")
		verify(t, underA, "a", ns("irongall-msg-v1", "b"), "message/a-to-b.line", "message/a-to-b.sig")
		verify(t, underA, "a", ns("irongall-msg-v1", "c"), "message/a-to-c.line", "message/a-to-c.sig")
		for _, c := range globIn(t, dir, "cert/ok-*.pub") {
			if _, err := run(t, nil, "ssh-keygen", "-L", "-f", c); err != nil {
				t.Errorf("ssh-keygen -L %s: %v", c, err)
			}
			verify(t, underA, "a", ns("irongall-prekey-v1", "a"), "a/prekey-1.txt", strings.TrimSuffix(c, ".pub")+".sig")
		}
		// What the identity signs itself is verified under its bare key.
		for _, box := range []string{"a", "c"} {
			bare := signers(box+"-bare", box, false)
			verify(t, bare, box, ns("irongall-revoke-v1", box), box+"/revoke.txt", box+"/revoke.sig")
		}
		bareA := signers("a-bare", "a", false)
		verify(t, bareA, "a", ns("irongall-revoke-v1", "a"), "a/revoke.txt", "a/revoke.sha256.sig")
		for _, s := range globIn(t, dir, "revoked/ok-*.sig") {
			verify(t, bareA, "a", ns("irongall-revoke-certs-v1", "a"), strings.TrimSuffix(strings.TrimSuffix(s, ".sig"), ".sha256")+".txt", s)
		}
	})
}

// TestTheStockToolNamespacesAreTheSpecs holds the namespaces written out in
// TestVectorsByToolsNotOurs to this package's, so that test reads nothing of
// ours and still tests what the protocol signs.
func TestTheStockToolNamespacesAreTheSpecs(t *testing.T) {
	var a Address
	copy(a[:], bytes.Repeat([]byte{1}, len(a)))
	for _, c := range []struct{ got, tag string }{
		{PrekeyNamespace(a), "irongall-prekey-v1"},
		{MessageNamespace(a), "irongall-msg-v1"},
		{RevokeNamespace(a), "irongall-revoke-v1"},
		{PassNamespace(a), "irongall-pass-v1"},
		{RevokedCertsNamespace(a), "irongall-revoke-certs-v1"},
	} {
		if c.got != c.tag+":"+a.String() {
			t.Errorf("%s is not %s:<address>", c.got, c.tag)
		}
	}
}

func globIn(t *testing.T, dir, pattern string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil || len(m) == 0 {
		t.Fatalf("no vectors match %s", pattern)
	}
	for i := range m {
		m[i], _ = filepath.Rel(dir, m[i])
	}
	return m
}
