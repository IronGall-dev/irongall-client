package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/IronGall-dev/irongall-client/protocol"
	"golang.org/x/crypto/ssh"
)

// The command, as it is run: it listens, keeps a record put to it, serves it
// back, and after a restart on the same directory still holds it.
func TestTheCommandServesWhatItKeeps(t *testing.T) {
	dir := t.TempDir()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	id, err := protocol.IdentityOf(signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.SignRevocation(signer, id.Address())
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(protocol.Revocations{Identity: id.Document(), Revocation: sig})
	if err != nil {
		t.Fatal(err)
	}

	for round, want := range []int{http.StatusNotFound, http.StatusOK} {
		ctx, stop := context.WithCancel(context.Background())
		listening, done := make(chan string, 1), make(chan error, 1)
		var logs bytes.Buffer
		go func() { done <- run(ctx, []string{"--dir", dir, "--listen", "127.0.0.1:0"}, &logs, listening) }()
		var base string
		select {
		case addr := <-listening:
			base = "http://" + addr
		case err := <-done:
			t.Fatalf("round %d: the command stopped: %v", round, err)
		case <-time.After(10 * time.Second):
			t.Fatalf("round %d: the command never listened", round)
		}
		url := base + "/v1/" + id.Address().String() + "/revocations"
		resp, err := http.Get(url)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != want {
			t.Fatalf("round %d: GET before the PUT: %d, want %d", round, resp.StatusCode, want)
		}
		req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if resp, err = http.DefaultClient.Do(req); err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if want := []int{http.StatusCreated, http.StatusOK}[round]; resp.StatusCode != want {
			t.Fatalf("round %d: PUT: %d, want %d", round, resp.StatusCode, want)
		}
		if resp, err = http.Get(url); err != nil {
			t.Fatal(err)
		}
		var rec protocol.Revocations
		err = json.NewDecoder(resp.Body).Decode(&rec)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("round %d: GET after the PUT: %d, %v", round, resp.StatusCode, err)
		}
		if _, err := protocol.VerifyRevocation(id.Address(), rec.Identity, rec.Revocation); err != nil {
			t.Fatalf("round %d: what it serves does not verify: %v", round, err)
		}
		stop()
		if err := <-done; err != nil {
			t.Fatalf("round %d: it did not stop cleanly: %v", round, err)
		}
		// A lookup is never logged: the log names the address once, for the
		// record kept, and never in the round that kept nothing.
		if n := strings.Count(logs.String(), id.Address().String()); n != 1-round {
			t.Fatalf("round %d: the log names the address %d times:\n%s", round, n, logs.String())
		}
		if !strings.Contains(logs.String(), []string{"0 addresses held", "1 addresses held"}[round]) {
			t.Fatalf("round %d: the log does not say what is held:\n%s", round, logs.String())
		}
	}
}

func TestTheCommandsFlags(t *testing.T) {
	ctx := context.Background()
	if err := run(ctx, nil, io.Discard, nil); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("with no directory: %v", err)
	}
	dir := t.TempDir()
	for name, args := range map[string][]string{
		"a proxy with no header":   {"--dir", dir, "--trusted-proxy", "10.0.0.0/8"},
		"a header with no proxy":   {"--dir", dir, "--client-ip-header", "X-Real-IP"},
		"a proxy that is no range": {"--dir", dir, "--trusted-proxy", "ten", "--client-ip-header", "X-Real-IP"},
		"no room for a body":       {"--dir", dir, "--max-body", "0"},
		"an argument":              {"--dir", dir, "serve"},
	} {
		if err := run(ctx, args, io.Discard, nil); err == nil {
			t.Errorf("%s was taken", name)
		}
	}
	var help bytes.Buffer
	if err := run(ctx, []string{"--help"}, &help, nil); !errors.Is(err, flag.ErrHelp) || !strings.Contains(help.String(), "--writes-per-hour") || strings.Contains(help.String(), "\n  -dir") {
		t.Fatalf("--help: %v\n%s", err, help.String())
	}
}
