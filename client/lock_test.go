package client_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// Every command that writes the box holds its lock from start to end, and
// one that finds it held waits, says so once, and runs once it is free:
// two commands of a box never share its files (#62, #83, #96).
func TestEveryCommandWaitsForTheLock(t *testing.T) {
	ctx := context.Background()
	commands := []struct {
		name string
		run  func(x *client.Box, peer *client.Box) error
	}{
		{"send", func(x, p *client.Box) error { _, err := x.Send(ctx, p.Address(), "waited"); return err }},
		{"flush", func(x, _ *client.Box) error { _, err := x.Flush(ctx); return err }},
		{"receive", func(x, _ *client.Box) error { _, err := x.Receive(ctx); return err }},
		{"resolve", func(x, p *client.Box) error { _, err := x.Resolve(ctx, p.Address()); return err }},
		{"ask", func(x, p *client.Box) error { _, err := x.Ask(ctx, p.Address()); return err }},
		{"keep a revocation", func(x, p *client.Box) error {
			rec, err := p.Revocation()
			if err != nil {
				return err
			}
			_, _, err = x.KeepRevocation(rec)
			return err
		}},
		{"rekey", func(x, _ *client.Box) error { _, err := x.Rekey(ctx, ""); return err }},
		{"allow", func(x, p *client.Box) error { _, err := x.Allow(ctx, p.Address()); return err }},
		{"alias", func(x, p *client.Box) error { return x.SetAlias("peer", p.Address()) }},
	}
	for _, c := range commands {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			a, peer := e.box(protocol.Classic), e.box(protocol.Classic)
			var waited atomic.Int32
			opt := e.opts()
			opt.Waiting = func() { waited.Add(1) }
			x, err := client.Open(a.Dir(), opt)
			if err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(a.Dir(), "lock")
			if err := os.Mkdir(lock, 0o700); err != nil { // another command's
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- c.run(x, peer) }()
			select {
			case err := <-done:
				t.Fatalf("ran while another command held the lock: %v", err)
			case <-time.After(300 * time.Millisecond):
			}
			if err := os.Remove(lock); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatalf("once the lock was free: %v", err)
			}
			if n := waited.Load(); n != 1 {
				t.Errorf("Waiting was told %d times, want once", n)
			}
			if exists(lock) {
				t.Error("the lock was not released")
			}
		})
	}
}

// Two commands of one box keeping two revocations of one address's
// certificates at once keep the higher (#83): with no lock, both read before
// either wrote, and the last rename won whatever its serial.
func TestTwoProcessesKeepTheHigherSerial(t *testing.T) {
	e := newEnv(t)
	a := e.box(protocol.Classic)
	key, err := os.ReadFile(filepath.Join(a.Dir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	rec := func(through uint64) *protocol.Revocations {
		certs, err := protocol.NewRevokedCertificates(a.Address(), through)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := protocol.SignRevokedCertificates(id, certs)
		if err != nil {
			t.Fatal(err)
		}
		return &protocol.Revocations{Identity: a.Identity().Document(), RevokedCertificates: certs.Statement(), RevokedCertificatesSignature: sig}
	}
	low, high := rec(200), rec(300)
	for i := range 30 {
		b := e.box(protocol.Classic) // neither record held yet
		p1, err := client.Open(b.Dir(), e.opts())
		if err != nil {
			t.Fatal(err)
		}
		p2, err := client.Open(b.Dir(), e.opts())
		if err != nil {
			t.Fatal(err)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Go(func() { <-start; _, _, _ = p1.KeepRevocation(high) })
		wg.Go(func() { <-start; _, _, _ = p2.KeepRevocation(low) })
		close(start)
		wg.Wait()
		if _, h, err := b.KeepRevocation(low); err != nil || h.Certificates == nil || h.Certificates.Through != 300 {
			t.Fatalf("run %d: after verifying through 300, holds %+v (%v)", i, h, err)
		}
	}
}
