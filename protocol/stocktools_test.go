package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dromas-dev/dromas-client/internal/agetool"
)

// TestVectorsByToolsNotOurs checks the crypto and container vectors with
// tools this project did not write, so that each is the standard's format and
// not this code's reading of it (testdata/vectors/README.md, PROTOCOL.md §16):
// age decrypts each message with its prekey's published test identity to
// exactly its plaintext, and with the other mailbox's not at all; head and sed split that plaintext into the line and
// its signature; ssh-keygen reads each certificate and verifies each signature
// under it, at the vectors' time, and each certificate file is the one its
// signatures carry; and sha256sum gives each address. Nothing
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
	address := func(t *testing.T, mailbox string) string {
		t.Helper()
		return strings.TrimSpace(string(file(t, mailbox+"/address")))
	}
	// The key line of an identity document, as an authorized_keys line.
	key := func(t *testing.T, mailbox string) string {
		t.Helper()
		lines := strings.Split(string(file(t, mailbox+"/identity.doc")), "\n")
		if len(lines) < 2 {
			t.Fatalf("%s/identity.doc has no key line", mailbox)
		}
		return lines[1]
	}
	// The vectors' time, as ssh-keygen's verify-time takes one.
	at := strings.NewReplacer("-", "", "T", "", ":", "").Replace(strings.TrimSpace(string(file(t, "now"))))

	t.Run("sha256sum", func(t *testing.T) {
		tool(t, "sha256sum")
		for _, mailbox := range []string{"a", "b", "c"} {
			out, err := run(t, file(t, mailbox+"/identity.doc"), "sha256sum")
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Fields(string(out))[0]; got != address(t, mailbox) {
				t.Errorf("%s: sha256sum of identity.doc is %s, the address is %s", mailbox, got, address(t, mailbox))
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
		for _, m := range []struct{ msg, key, other string }{{"a-to-b", "b-1.pq", "c-1.classic"}, {"a-to-c", "c-1.classic", "b-1.pq"}} {
			if _, err := run(t, nil, "age", "-d", "-i", "input/"+m.other+".key", "message/"+m.msg+".age"); err == nil {
				t.Errorf("%s: age decrypts it with %s, another mailbox's prekey", m.msg, m.other)
			}
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
		signers := func(name, mailbox string, ca bool) string {
			line := address(t, mailbox) + " "
			if ca {
				line += "cert-authority "
			}
			p := filepath.Join(work, name)
			if err := os.WriteFile(p, []byte(line+key(t, mailbox)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		}
		verify := func(t *testing.T, signersFile, mailbox, ns, msg, sig string) {
			t.Helper()
			if _, err := run(t, file(t, msg), "ssh-keygen", "-Y", "verify", "-f", signersFile, "-I", address(t, mailbox), "-n", ns, "-s", sig, "-O", "verify-time="+at); err != nil {
				t.Errorf("%s over %s: %v", sig, msg, err)
			}
		}
		// A signature carries its certificate and ssh-keygen verifies under that
		// one, while -L reads the .pub alone: so each .pub is held to the
		// certificate its signatures carry, byte for byte, read with the standard
		// library alone (#444 item 3). carried is the key a signature carries.
		carried := func(t *testing.T, sig string) []byte {
			t.Helper()
			_, body, begun := strings.Cut(string(file(t, sig)), "-----BEGIN SSH SIGNATURE-----")
			body, _, ended := strings.Cut(body, "-----END SSH SIGNATURE-----")
			blob, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
			if !begun || !ended || err != nil || len(blob) < 14 || string(blob[:6]) != "SSHSIG" {
				t.Fatalf("%s is not an armored SSHSIG", sig)
			}
			n := uint64(binary.BigEndian.Uint32(blob[10:14]))
			if uint64(len(blob)-14) < n {
				t.Fatalf("%s: its key is cut short", sig)
			}
			return blob[14 : 14+n]
		}
		// keyType is the type a key in SSH's wire form names first.
		keyType := func(k []byte) string {
			if len(k) < 4 || uint64(len(k)-4) < uint64(binary.BigEndian.Uint32(k)) {
				return ""
			}
			return string(k[4 : 4+binary.BigEndian.Uint32(k)])
		}
		carries := func(t *testing.T, pub, sig string) {
			t.Helper()
			f := strings.Fields(string(file(t, pub)))
			if len(f) < 2 {
				t.Fatalf("%s is not a key line", pub)
			}
			cert, err := base64.StdEncoding.DecodeString(f[1])
			if err != nil || !bytes.Equal(carried(t, sig), cert) {
				t.Errorf("%s does not carry the certificate in %s", sig, pub)
			}
		}
		// Every signature in a mailbox's directory that carries a certificate carries
		// that mailbox's work-cert.pub; message/ holds A's. The rest carry the bare
		// identity, verified below.
		for mailbox, sigs := range map[string]string{"a": "a/*.sig", "b": "b/*.sig", "c": "c/*.sig", "message": "message/*.sig"} {
			owner, certified := mailbox, 0
			if mailbox == "message" {
				owner = "a"
			}
			for _, s := range globIn(t, dir, sigs) {
				if strings.HasSuffix(keyType(carried(t, s)), "-cert-v01@openssh.com") {
					carries(t, owner+"/work-cert.pub", s)
					certified++
				}
			}
			if certified == 0 {
				t.Errorf("%s: no signature carries a certificate", sigs)
			}
		}
		for _, c := range []string{"a/work-cert.pub", "b/work-cert.pub", "c/work-cert.pub"} {
			if _, err := run(t, nil, "ssh-keygen", "-L", "-f", c); err != nil {
				t.Errorf("ssh-keygen -L %s: %v", c, err)
			}
		}
		for _, c := range globIn(t, dir, "cert/*.pub") {
			carries(t, c, strings.TrimSuffix(c, ".pub")+".sig")
		}
		ns := func(tag, mailbox string) string { return tag + ":" + address(t, mailbox) }
		for _, mailbox := range []string{"a", "b", "c"} {
			under := signers(mailbox+"-ca", mailbox, true)
			verify(t, under, mailbox, ns("dromas-prekey-v1", mailbox), mailbox+"/prekey-1.txt", mailbox+"/prekey-1.txt.sig")
		}
		underA := signers("a-ca", "a", true)
		verify(t, underA, "a", ns("dromas-prekey-v1", "a"), "a/prekey-2.txt", "a/prekey-2.txt.sig")
		verify(t, underA, "a", ns("dromas-prekey-v1", "a"), "a/prekey-1.txt", "a/prekey-1.txt.sha256.sig")
		verify(t, underA, "a", ns("dromas-pass-v1", "a"), "a/pass.txt", "a/pass.sig")
		verify(t, underA, "a", ns("dromas-msg-v1", "b"), "message/a-to-b.line", "message/a-to-b.sig")
		verify(t, underA, "a", ns("dromas-msg-v1", "c"), "message/a-to-c.line", "message/a-to-c.sig")
		for _, c := range globIn(t, dir, "cert/ok-*.pub") {
			if _, err := run(t, nil, "ssh-keygen", "-L", "-f", c); err != nil {
				t.Errorf("ssh-keygen -L %s: %v", c, err)
			}
			verify(t, underA, "a", ns("dromas-prekey-v1", "a"), "a/prekey-1.txt", strings.TrimSuffix(c, ".pub")+".sig")
		}
		// What the identity signs itself is verified under its bare key.
		for _, mailbox := range []string{"a", "c"} {
			bare := signers(mailbox+"-bare", mailbox, false)
			verify(t, bare, mailbox, ns("dromas-revoke-v1", mailbox), mailbox+"/revoke.txt", mailbox+"/revoke.sig")
		}
		bareA := signers("a-bare", "a", false)
		verify(t, bareA, "a", ns("dromas-revoke-v1", "a"), "a/revoke.txt", "a/revoke.sha256.sig")
		for _, s := range globIn(t, dir, "revoked/ok-*.sig") {
			verify(t, bareA, "a", ns("dromas-revoke-certs-v1", "a"), strings.TrimSuffix(strings.TrimSuffix(s, ".sig"), ".sha256")+".txt", s)
		}
	})
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
