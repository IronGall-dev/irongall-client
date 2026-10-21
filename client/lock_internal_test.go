package client

import (
	"os"
	"testing"
)

// A holder releasing the lock deletes lock/pid, then drops its flock. A
// consumer that opened lock/pid just before the delete and flocks just after
// the drop holds a file that is no longer the lock: it must start again and
// take the real one, or a third consumer makes a new lock and two run.
func TestLockFileDeletedUnderTheFlock(t *testing.T) {
	b, err := newBox(t.TempDir(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	dir := b.path("lock")
	// A crashed client's lock, held by no one, which this consumer takes over.
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/pid", []byte("12345\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lockOpened = func() {
		lockOpened = func() {}
		_ = os.Remove(dir + "/pid") // the holder releasing, after our open
		_ = os.Remove(dir)
	}
	t.Cleanup(func() { lockOpened = func() {} })
	l, err := b.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.release() }()
	if !stillNamed(l.pid, dir+"/pid") {
		t.Fatal("holding a lock file that lock/ no longer names")
	}
}
