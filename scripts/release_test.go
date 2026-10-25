// The release scripts, tagcheck.sh and release.sh, run in a world of their
// own: a bare repository for origin, a clone holding the two scripts and an
// allowed_signers file naming a throwaway key, and a gh that answers from
// the test (fakeGH), so nothing reaches GitHub or the machine's own keys.
package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeGH answers the calls the scripts make: the repo's name, whether a
// commit listed in $FAKE_GH/passed has a CI run that passed, run 42 for a
// release, and $FAKE_GH/watch as the run's exit status.
const fakeGH = `#!/usr/bin/env bash
echo "$*" >> "$FAKE_GH/gh.log"
case "$1 $2" in
  "repo view") echo dromas-dev/dromas-client ;;
  "run list")
    if [[ " $* " == *" --workflow ci.yml "* ]]; then
      args="$*"; commit=${args##*--commit }; commit=${commit%% *}; n=0
      if [ -f "$FAKE_GH/passed" ]; then
        while read -r c; do [ "$c" = "$commit" ] && n=1; done < "$FAKE_GH/passed"
      fi
      echo "$n"
    else
      echo 42
    fi ;;
  "run watch") exit "$(cat "$FAKE_GH/watch" 2> /dev/null || echo 0)" ;;
  "release view") echo https://example.invalid/release ;;
  *) echo "fake gh: $*" >&2; exit 2 ;;
esac
`

type world struct {
	t                 *testing.T
	dir, origin, work string
	key, other        string // private keys: the one allowed_signers names, and another
	env               []string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	if testing.Short() {
		t.Skip("a world of repositories and keys for each case: seconds each")
	}
	for _, tool := range []string{"git", "ssh-keygen", "bash"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("no %s on PATH", tool)
		}
	}
	dir := t.TempDir()
	w := &world{t: t, dir: dir, origin: filepath.Join(dir, "origin.git"), work: filepath.Join(dir, "work"),
		key: filepath.Join(dir, "key"), other: filepath.Join(dir, "other")}
	bin, home := filepath.Join(dir, "bin"), filepath.Join(dir, "home")
	for _, d := range []string{bin, home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(bin, "gh"), []byte(fakeGH), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, kv := range os.Environ() {
		name, _, _ := strings.Cut(kv, "=")
		if name == "HOME" || name == "PATH" || name == "SSH_AUTH_SOCK" || strings.HasPrefix(name, "GIT_") ||
			strings.HasPrefix(name, "GITHUB_") || strings.HasPrefix(name, "GH_") {
			continue
		}
		w.env = append(w.env, kv)
	}
	w.env = append(w.env, "HOME="+home, "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GIT_CONFIG_NOSYSTEM=1", "FAKE_GH="+dir)

	for _, k := range []string{w.key, w.other} {
		w.run(dir, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", k)
	}
	w.run(dir, "git", "init", "-q", "--bare", "-b", "main", w.origin)
	w.run(dir, "git", "clone", "-q", w.origin, w.work)
	for _, c := range [][]string{{"user.name", "Test"}, {"user.email", "test@example.invalid"},
		{"gpg.format", "ssh"}, {"user.signingkey", w.key}} {
		w.git("config", c[0], c[1])
	}
	for _, f := range []string{"tagcheck.sh", "release.sh"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		w.write("scripts/"+f, string(b), 0o755)
	}
	pub, err := os.ReadFile(w.key + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(string(pub))
	w.write(".github/allowed_signers", `test@example.invalid namespaces="git" `+fields[0]+" "+fields[1]+"\n", 0o644)
	w.commit("the first release")
	w.git("tag", "-s", "v0.1.0", "-m", "v0.1.0")
	w.git("push", "-q", "origin", "main", "v0.1.0")
	w.commit("a change since")
	w.git("push", "-q", "origin", "main")
	return w
}

// run runs a command in dir and fails the test if it fails.
func (w *world) run(dir, name string, args ...string) string {
	w.t.Helper()
	out, code := w.try(dir, name, args...)
	if code != 0 {
		w.t.Fatalf("%s %s: exit %d: %s", name, strings.Join(args, " "), code, out)
	}
	return out
}

// try runs a command in dir and returns its output and exit status.
func (w *world) try(dir, name string, args ...string) (string, int) {
	w.t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir, cmd.Env = dir, w.env
	out, err := cmd.CombinedOutput()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			return string(out), e.ExitCode()
		}
		w.t.Fatalf("%s: %v", name, err)
	}
	return string(out), 0
}

func (w *world) git(args ...string) string {
	w.t.Helper()
	return strings.TrimSpace(w.run(w.work, "git", args...))
}

func (w *world) write(name, body string, mode os.FileMode) {
	w.t.Helper()
	p := filepath.Join(w.work, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		w.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		w.t.Fatal(err)
	}
}

// commit commits a change to a file of its own, and returns the commit.
func (w *world) commit(msg string) string {
	w.t.Helper()
	w.write("changes/"+strings.ReplaceAll(msg, " ", "-"), msg+"\n", 0o644)
	w.git("add", "-A")
	w.git("commit", "-q", "-m", msg)
	return w.git("rev-parse", "HEAD")
}

// passed records a commit's CI run as passed, as fakeGH reads it.
func (w *world) passed(commit string) {
	w.t.Helper()
	f, err := os.OpenFile(filepath.Join(w.dir, "passed"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		w.t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(commit + "\n"); err != nil {
		w.t.Fatal(err)
	}
}

// script runs one of the world's scripts through bash, as Windows, which
// reads no #! line, needs too.
func (w *world) script(name string, args ...string) (string, int) {
	w.t.Helper()
	return w.try(w.work, "bash", append([]string{filepath.Join(w.work, "scripts", name)}, args...)...)
}

// originTag is what origin holds for a tag: "tag" for an annotated one, and
// "" for none.
func (w *world) originTag(tag string) string {
	w.t.Helper()
	out, code := w.try(w.dir, "git", "--git-dir", w.origin, "cat-file", "-t", "refs/tags/"+tag)
	if code != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

func TestTagcheckTakesOnlyASignedAnnotatedTagOnMainWhoseCIPassed(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, refusal string
		tag           func(w *world)
	}{
		{"a signed annotated tag on main whose CI passed", "", func(w *world) {
			w.git("tag", "-s", "v0.1.1", "-m", "v0.1.1")
		}},
		{"a lightweight tag", "not an annotated tag", func(w *world) {
			w.git("tag", "v0.1.1")
		}},
		{"an annotated tag with no signature", "not signed by a key in .github/allowed_signers", func(w *world) {
			w.git("tag", "-a", "--no-sign", "v0.1.1", "-m", "v0.1.1")
		}},
		{"a tag signed by a key allowed_signers does not name", "not signed by a key in .github/allowed_signers", func(w *world) {
			w.git("-c", "user.signingkey="+w.other, "tag", "-s", "v0.1.1", "-m", "v0.1.1")
		}},
		{"a tag on a commit not on main", "is not on origin/main", func(w *world) {
			w.git("checkout", "-q", "-b", "side")
			w.passed(w.commit("a change off main"))
			w.git("tag", "-s", "v0.1.1", "-m", "v0.1.1")
		}},
		{"a tag on a commit whose CI has not passed", "no CI run of", func(w *world) {
			w.git("tag", "-s", "v0.1.1", "-m", "v0.1.1")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			if c.name != "a tag on a commit whose CI has not passed" {
				w.passed(w.git("rev-parse", "HEAD"))
			}
			c.tag(w)
			out, code := w.script("tagcheck.sh", "v0.1.1")
			switch {
			case c.refusal == "" && code != 0:
				t.Errorf("refused: exit %d: %s", code, out)
			case c.refusal != "" && (code != 1 || !strings.Contains(out, c.refusal)):
				t.Errorf("exit %d, want 1 with %q: %s", code, c.refusal, out)
			}
		})
	}
}

func TestReleasePushesTheNextPatchSignedAndWaitsForItsRun(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	head := w.git("rev-parse", "HEAD")
	w.passed(head)
	out, code := w.script("release.sh", "--yes")
	if code != 0 || !strings.Contains(out, "released: https://example.invalid/release") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if got := w.originTag("v0.1.1"); got != "tag" {
		t.Fatalf("origin holds v0.1.1 as %q, want an annotated tag", got)
	}
	if got := w.run(w.dir, "git", "--git-dir", w.origin, "rev-parse", "v0.1.1^{commit}"); strings.TrimSpace(got) != head {
		t.Errorf("v0.1.1 is %s, want origin/main's %s", got, head)
	}
	if out, code := w.script("release.sh", "--yes"); code != 1 || !strings.Contains(out, "is released already") {
		t.Errorf("a second run: exit %d, want 1, released already: %s", code, out)
	}
}

func TestReleaseTakesTheNextPatchOrANewMinorAndNothingElse(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		tag  string
		good bool
	}{
		{"v0.1.1", true}, {"v0.2.0", true}, {"v0.7.0", true},
		{"v0.1.5", false}, {"v0.2.1", false}, {"v0.0.9", false}, {"v0.1.0", false}, {"v1.0.0", false}, {"v1.2.0", false}, {"v0.1", false},
	} {
		t.Run(c.tag, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			w.passed(w.git("rev-parse", "HEAD"))
			before := w.originTag(c.tag)
			out, code := w.script("release.sh", c.tag, "--yes")
			held := before == "" && w.originTag(c.tag) == "tag"
			if c.good && (code != 0 || !held) {
				t.Errorf("exit %d, origin holds it %v: %s", code, held, out)
			}
			if !c.good && (code != 1 || held) {
				t.Errorf("exit %d, origin holds it %v, want a refusal: %s", code, held, out)
			}
		})
	}
}

func TestReleaseRefusesWhatReleaseYmlWould(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, refusal string
		early         bool // refused before the release is shown, and so before anything is signed
		set           func(w *world)
	}{
		{"a checkout with changes", "this checkout has changes", true, func(w *world) {
			w.passed(w.git("rev-parse", "HEAD"))
			w.write("stray", "x\n", 0o644)
		}},
		{"a commit whose CI has not passed", "no CI run of", true, func(*world) {}},
		{"a commit already released", "is released already", true, func(w *world) {
			w.passed(w.git("rev-parse", "HEAD"))
			w.git("tag", "-s", "v0.1.1", "-m", "v0.1.1")
			w.git("push", "-q", "origin", "v0.1.1")
		}},
		{"nothing since the last release", "is released already", true, func(w *world) {
			w.git("reset", "-q", "--hard", "v0.1.0")
			w.git("push", "-q", "--force", "origin", "main")
			w.passed(w.git("rev-parse", "HEAD"))
		}},
		{"a key allowed_signers does not name", "deleted, nothing pushed", false, func(w *world) {
			w.passed(w.git("rev-parse", "HEAD"))
			w.git("config", "user.signingkey", w.other)
		}},
		{"a push that fails", "the push failed", false, func(w *world) {
			w.passed(w.git("rev-parse", "HEAD"))
			w.git("remote", "set-url", "--push", "origin", filepath.Join(w.dir, "nowhere"))
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			w := newWorld(t)
			c.set(w)
			out, code := w.script("release.sh", "--yes")
			if code != 1 || !strings.Contains(out, c.refusal) {
				t.Errorf("exit %d, want 1 with %q: %s", code, c.refusal, out)
			}
			if c.early && strings.Contains(out, "would release") {
				t.Errorf("refused only after it showed the release, not before: %s", out)
			}
			if c.name != "a commit already released" {
				if w.originTag("v0.1.1") != "" {
					t.Error("origin holds v0.1.1")
				}
				if tags := w.git("tag", "-l", "v0.1.1"); tags != "" {
					t.Errorf("the checkout kept a tag: %s", tags)
				}
			}
		})
	}
}

func TestReleaseCatchesUpWithOriginMainFirst(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	other := filepath.Join(w.dir, "other-clone")
	w.run(w.dir, "git", "clone", "-q", w.origin, other)
	script := filepath.Join(other, "scripts", "release.sh")
	b, err := os.ReadFile(script)
	if err != nil {
		t.Fatal(err)
	}
	marked := strings.Replace(string(b), "main() {\n", "main() {\n  echo 'the script as origin/main has it'\n", 1)
	if err := os.WriteFile(script, []byte(marked), 0o755); err != nil {
		t.Fatal(err)
	}
	w.run(other, "git", "add", "-A")
	w.run(other, "git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-q", "-m", "elsewhere")
	w.run(other, "git", "push", "-q", "origin", "main")
	newest := strings.TrimSpace(w.run(other, "git", "rev-parse", "HEAD"))
	w.passed(newest)
	out, code := w.script("release.sh", "--yes")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "the script as origin/main has it") {
		t.Errorf("it ran the script as the checkout had it, not as origin/main has it: %s", out)
	}
	if got := strings.TrimSpace(w.run(w.dir, "git", "--git-dir", w.origin, "rev-parse", "v0.1.1^{commit}")); got != newest {
		t.Errorf("v0.1.1 is %s, want origin/main's newest, %s", got, newest)
	}
	if got := w.git("rev-parse", "HEAD"); got != newest {
		t.Errorf("the checkout is at %s, want %s", got, newest)
	}
}

func TestReleaseSaysWhenItsRunFails(t *testing.T) {
	t.Parallel()
	w := newWorld(t)
	w.passed(w.git("rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(w.dir, "watch"), []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := w.script("release.sh", "--yes")
	if code != 1 || !strings.Contains(out, "the release run failed") {
		t.Errorf("exit %d, want 1, the release run failed: %s", code, out)
	}
}
