// Command dromas-echo is the echo mailbox: a client on a published address
// that answers every message passing every check with a signed reply, saying
// what it verified and carrying back the body it was sent, its in_reply_to
// the message's msg_id. An agent proves its whole loop with it, end to end,
// against a mailbox it does not run.
//
// A message to an echo mailbox is readable by whoever runs it: that is what it is for.
//
// Its state directory belongs in memory (a tmpfs). At every start it copies
// in the identity key, the one thing kept, and publishes a new prekey, which
// needs only the identity, so no prekey ever reaches a disk or a backup. A
// message sealed to the previous prekey is refused after a restart, like any
// message a mailbox can no longer decrypt. While it runs, each Receive renews the
// prekey once it is a day old, as for any mailbox.
//
// It runs in the mode --mode names (PROTOCOL.md §5): identity mode, where its
// identity signs its replies, or working-key mode, where a working key its
// identity certifies does, so that both reach the wire. A start restores the
// mailbox in that mode, and stops where its server holds it in the other.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
)

const usage = `usage: dromas-echo --identity <key file> [--mode identity|working-key] [--dir <dir>]

Runs an echo mailbox until interrupted: every message that passes every check
is answered, signed, with what was checked and the body it carried.

  --identity  the echo mailbox's identity, an OpenSSH key file; the mailbox
              is registered at its first start
  --mode      identity (the default), where the identity signs, or
              working-key, where a working key it certifies signs: for good,
              once the mailbox is registered so
  --dir       the mailbox's state directory, which belongs in memory (a tmpfs):
              $DROMAS_HOME, or ${XDG_CONFIG_HOME:-~/.config}/dromas/${DROMAS_MAILBOX:-default}

The server is $DROMAS_SERVER_URL, or https://dromas.dev.
`

// replyTTL is how long a reply that could not be posted is retried before it
// is dropped: a late echo is worth little, and a recipient that refuses one
// now (a full mailbox, a lapsed prekey) would otherwise be retried for days.
const replyTTL = time.Hour

// defaultPause is the wait between polls when the server names none.
const defaultPause = time.Minute

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stderr)
	stop()
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logw io.Writer) error {
	fl := flag.NewFlagSet("dromas-echo", flag.ContinueOnError)
	fl.SetOutput(logw)
	fl.Usage = func() { _, _ = fmt.Fprint(logw, usage) }
	identity := fl.String("identity", "", "")
	dir := fl.String("dir", "", "")
	mode := fl.String("mode", "identity", "")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if *identity == "" || fl.NArg() != 0 || *mode != "identity" && *mode != "working-key" {
		fl.Usage()
		return flag.ErrHelp
	}
	if *dir == "" {
		d, err := client.Dir()
		if err != nil {
			return err
		}
		*dir = d
	}
	opt := client.Options{Base: os.Getenv("DROMAS_SERVER_URL"), WorkingKey: *mode == "working-key"}
	logger := log.New(logw, "", log.LstdFlags|log.LUTC)
	e, err := start(ctx, *dir, *identity, opt, logger)
	if err != nil {
		return err
	}
	return e.run(ctx)
}

type echo struct {
	b   *client.Mailbox
	log *log.Logger
	now func() time.Time
}

// start copies the identity into dir and publishes a new prekey, or at the
// first start registers the mailbox.
func start(ctx context.Context, dir, identity string, opt client.Options, l *log.Logger) (*echo, error) {
	key, err := os.ReadFile(identity) //nolint:gosec // the key file the operator named
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	mine := filepath.Join(dir, "identity")
	switch held, err := os.ReadFile(mine); { //nolint:gosec // a path inside the state directory
	case err == nil && !bytes.Equal(held, key):
		return nil, fmt.Errorf("%s holds another mailbox's identity", dir)
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		return nil, err
	case err != nil:
		if err := os.WriteFile(mine, key, 0o600); err != nil { //nolint:gosec // inside the state directory the operator named
			return nil, err
		}
	}
	b, err := client.Open(dir, opt)
	if err != nil {
		return nil, err
	}
	st, err := b.Status(ctx)
	if err != nil {
		return nil, err
	}
	// A state directory in memory holds the identity alone at each start:
	// init restores the mailbox in its mode, reading it at its server first,
	// and registers it where the server holds none, so the first start too.
	// One that kept its state renews.
	if st.PrekeySerial == 0 {
		if b, err = client.Init(ctx, dir, opt); err != nil {
			return nil, err
		}
	} else {
		if want := map[bool]string{false: "identity", true: "working_key"}[opt.WorkingKey]; st.Mode != want {
			return nil, fmt.Errorf("the mailbox in %s is in %s mode, not the one --mode names", dir, st.Mode)
		}
		if _, err := b.Rekey(ctx); err != nil {
			return nil, err
		}
	}
	// An echo mailbox answers whoever writes: every sender's messages land in
	// inbox/, where a mailbox would hold messages from one it has not allowed.
	if err := b.SetPolicy(ctx, client.Policy{Unknown: client.LandInbox, Server: client.AdmitAll}); err != nil {
		return nil, err
	}
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	l.Printf("echo mailbox %s: a new prekey is published", b.Address())
	return &echo{b: b, log: l, now: now}, nil
}

// run drains the mailbox and answers, then holds its list until a message
// arrives (client.Mailbox.Await), so a reply goes within seconds of it. A mailbox
// with replies not yet posted holds for at most the poll interval, then
// retries them, and drains again only once its list has changed: one list
// an interval, the hold's, as the poll budget allows. A drain that failed,
// or left messages on the server, waits that interval with no hold.
func (e *echo) run(ctx context.Context) error {
	pause, hold := e.once(ctx)
	for {
		if hold {
			var until time.Time
			pending, _ := filepath.Glob(filepath.Join(e.b.Dir(), "outbox", "*.P"))
			if len(pending) > 0 {
				until = time.Now().Add(pause)
			}
			err := e.b.Await(ctx, until, func(h *client.HoldResult, err error) {
				if err != nil {
					e.log.Printf("hold: %v", err)
					return
				}
				e.log.Printf("a connection dropped, after %s held: the wait is now %s, with keep-alive every %s", h.After, h.Wait, h.KeepAlive)
			})
			switch {
			case ctx.Err() != nil:
				return nil
			case err == nil && len(pending) > 0 && !time.Now().Before(until):
				// The interval passed with nothing new: the replies are
				// retried, and the mailbox's list is held again, not drained.
				e.retry(ctx)
				continue
			case err == nil:
				pause, hold = e.once(ctx)
				continue
			}
			e.log.Printf("hold: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(pause):
		}
		pause, hold = e.once(ctx)
	}
}

// once retries replies not yet posted, drains the mailbox (which renews its
// prekey when due) and answers what it delivered. It returns how long to wait
// before the next poll, and whether the server holds nothing more for the
// mailbox, so its list may be held instead.
func (e *echo) once(ctx context.Context) (time.Duration, bool) {
	e.retry(ctx)
	res, err := e.b.Receive(ctx)
	if res != nil {
		if res.Renewed != nil {
			e.log.Printf("a new prekey is published, serial %d", res.Renewed.Serial)
		}
		if res.RenewErr != nil {
			e.log.Printf("the prekey is due for renewal and was not renewed: %v", res.RenewErr)
		}
		for _, d := range res.Delivered {
			e.reply(ctx, d)
		}
		for _, id := range res.Duplicates {
			e.log.Printf("%s: a retry of a message already answered", id)
		}
		var refused []string
		for _, r := range res.Refused {
			// Never answered: a refusal does not say whether its sender
			// was verified, and an unverified one can name anyone.
			e.log.Printf("%s: refused: %s: %s", r.ID, r.Code, r.Reason)
			refused = append(refused, r.ID)
		}
		if len(refused) > 0 {
			if _, err := e.b.RemoveRefused(ctx, refused); err != nil {
				e.log.Printf("the refused messages were not deleted from refused/: %v", err)
			}
		}
	}
	// An echo mailbox keeps no record of its replies: its state is in memory.
	sent, _ := filepath.Glob(filepath.Join(e.b.Dir(), "sent", "*"))
	for _, f := range sent {
		e.remove(f)
	}
	pause := defaultPause
	if res != nil && res.PollAfter > 0 {
		pause = time.Duration(res.PollAfter) * time.Second
	}
	var ae *client.APIError
	if errors.As(err, &ae) && ae.RetryAfter > 0 {
		pause = ae.RetryAfter
	}
	if err != nil && ctx.Err() == nil {
		e.log.Printf("receive: %v", err)
	}
	return pause, err == nil && res != nil && !res.More && res.Paced == 0
}

// reply answers one delivery. A reply the server did not take stays in the
// outbox, for retry.
func (e *echo) reply(ctx context.Context, d client.Delivery) {
	from := d.Envelope.From
	r, err := e.b.SendWith(ctx, from, report(d, e.now()), client.Fields{InReplyTo: d.Envelope.MsgID})
	if err != nil {
		e.log.Printf("%s: the reply to %s: %v", d.ID, from, err)
	} else {
		e.log.Printf("%s: answered %s, reply %s", d.ID, from, r.ID)
	}
	e.remove(filepath.Join(e.b.Dir(), "inbox", d.ID+".json"))
}

// retry re-posts the replies still in the outbox, and drops those older than
// replyTTL or that can never be delivered.
func (e *echo) retry(ctx context.Context) {
	if _, err := e.b.Flush(ctx); err != nil && ctx.Err() == nil {
		e.log.Printf("retry: %v", err)
	}
	pending, _ := filepath.Glob(filepath.Join(e.b.Dir(), "outbox", "*.P"))
	for _, p := range pending {
		fi, err := os.Stat(p)
		if err != nil || e.now().Sub(fi.ModTime()) < replyTTL {
			continue
		}
		stem := strings.TrimSuffix(p, ".P")
		files, _ := filepath.Glob(stem + ".*")
		for _, f := range files {
			e.remove(f)
		}
		e.log.Printf("dropped a reply not posted within %s: %s", replyTTL, filepath.Base(stem))
	}
	failed, _ := filepath.Glob(filepath.Join(e.b.Dir(), "outbox", "failed", "*"))
	for _, f := range failed {
		e.remove(f)
	}
}

func (e *echo) remove(name string) {
	if err := os.Remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		e.log.Printf("%v", err)
	}
}

// report is a reply's body: what was checked, then the body the message
// carried, as JSON, so its exact bytes show.
func report(d client.Delivery, now time.Time) string {
	env := d.Envelope
	var s strings.Builder
	s.WriteString("dromas echo mailbox: your message passed every check.\n")
	fmt.Fprintf(&s, "from: %s (its signature verified, by the identity this address is the SHA-384 of, or by a working key that identity certified, as its mode takes)\n", env.From)
	fmt.Fprintf(&s, "to: %s\n", env.To)
	fmt.Fprintf(&s, "msg_id: %s\n", env.MsgID)
	fmt.Fprintf(&s, "sent_at: %s\n", env.SentAt.UTC().Format(protocol.TimeLayout))
	fmt.Fprintf(&s, "received_at: %s\n", now.UTC().Format(protocol.TimeLayout))
	fmt.Fprintf(&s, "ciphertext_sha256: %s\n", d.ID)
	fmt.Fprintf(&s, "checked: decryption with this mailbox's prekey; the sender's identity, which the message carries, against its address; "+
		"the signer, that identity or its certificate for a working key, against the sender's mode; the signature, made for this mailbox only; "+
		"the envelope's version, from and to; sent_at within %d days; not a replay\n", protocol.TTL/(24*time.Hour))
	s.WriteString("A message to an echo mailbox is readable by whoever runs it.\n")
	fmt.Fprintf(&s, "body, as JSON: %s\n", env.Body)
	return s.String()
}
