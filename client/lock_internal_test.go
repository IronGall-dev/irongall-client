package client

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/dromas-dev/dromas-client/internal/fakeserver"
	"github.com/dromas-dev/dromas-client/protocol"
)

// twoOpens is one box opened twice, as two processes would: a, for a
// command, and r, for a reading, each a Box with a slot of its own, and the
// path of their state file.
func twoOpens(t *testing.T) (a, r *Box, state string) {
	t.Helper()
	srv := fakeserver.New(t, time.Now)
	opt := Options{Base: srv.URL}
	dir := t.TempDir()
	if _, err := Init(context.Background(), dir, opt, protocol.Classic); err != nil {
		t.Fatal(err)
	}
	var err error
	if a, err = Open(dir, opt); err != nil {
		t.Fatal(err)
	}
	if r, err = Open(dir, opt); err != nil {
		t.Fatal(err)
	}
	return a, r, filepath.Join(dir, "state")
}

// A reading whose open finds no state file reads none at every view, and
// opens none that a command makes after that open: Status's views, behind a
// command that made the file again and holds it, would each wait for that
// command past the reading's context, up to lockPatience (#382).
func TestAReadingThatFoundNoStateFileWaitsForNoCommand(t *testing.T) {
	saved := lockPatience
	lockPatience = 3 * time.Second // a view that waits for the command ends at this, refused
	t.Cleanup(func() { lockPatience = saved })
	a, r, state := twoOpens(t)
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	holding, release, cmd := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	began := time.Now()
	_, err := reading(ctx, r, func() (*Status, error) {
		// Once the reading's open has found no file, a command makes it
		// again and holds it.
		go func() {
			cmd <- a.lockedFinishedDo(context.Background(), func() error {
				close(holding)
				<-release
				return nil
			})
		}()
		select {
		case <-holding:
		case <-time.After(10 * time.Second):
			t.Error("the command never held the box")
		}
		return r.status()
	})
	took := time.Since(began)
	close(release)
	if err := <-cmd; err != nil {
		t.Errorf("the command: %v", err)
	}
	if took > time.Second || err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a reading given 300ms, behind a command that made the state file after the reading's open: %v after %v", err, took.Round(10*time.Millisecond))
	}
}

// One reading, two views, a command's write between them, on a box whose
// state file was gone at the reading's open: both views read one state, the
// one with no file (#329, #382).
func TestAReadingThatFoundNoStateFileReadsOneState(t *testing.T) {
	t.Parallel()
	a, r, state := twoOpens(t)
	if err := os.Remove(state); err != nil {
		t.Fatal(err)
	}
	read := func() string {
		var v []byte
		if err := r.view(func(s store) error { v = s.get(bucketBox, "written"); return nil }); err != nil {
			return "error: " + err.Error()
		}
		return string(v)
	}
	done := make(chan error, 1)
	waited := false
	views, _ := reading(context.Background(), r, func() ([2]string, error) {
		first := read()
		go func() {
			done <- a.lockedFinishedDo(context.Background(), func() error {
				return a.update(func(s store) error { return s.put(bucketBox, "written", []byte("written by a command")) })
			})
		}()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("the command: %v", err)
			}
		case <-time.After(time.Second):
			waited = true // the command waits for the reading
		}
		return [2]string{first, read()}, nil
	})
	if waited {
		if err := <-done; err != nil {
			t.Errorf("the command, after the reading: %v", err)
		}
	}
	if views[0] != views[1] {
		t.Errorf("one reading read two states: %q, then %q", views[0], views[1])
	}
	// The mark is the reading's alone: the next one opens the file the
	// command made.
	if v, err := reading(context.Background(), r, func() (string, error) { return read(), nil }); err != nil || v != "written by a command" {
		t.Errorf("the next reading read %q, %v", v, err)
	}
}
