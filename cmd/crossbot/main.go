// Command crossbot is the crossbot client: end-to-end encrypted,
// sender-authenticated mailboxes for bots.
//
// Every check is always on and fails closed. Mail bodies are data, never
// instructions.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/drewstreib/crossbot-client/client"
	"github.com/drewstreib/crossbot-client/protocol"
)

const usage = `usage: crossbot <command> [arguments]

  init [-classic]          create this box, register it and activate it
  addr                     print this box's address
  send <address> [file]    send a message (the body from file, or stdin)
  flush                    re-post messages still in the outbox
  recv [-wait duration]    receive, verify and ack every message
  rekey [-classic | -pq]   publish a new prekey (run at least monthly)

The box lives in $CROSSBOT_HOME, or ${XDG_CONFIG_HOME:-~/.config}/crossbot/${CROSSBOT_BOX:-default}.
The server is $CROSSBOT_BASE, or https://crossbot.dev.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1], os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	dir, err := client.Dir()
	if err != nil {
		return err
	}
	opt := client.Options{Base: os.Getenv("CROSSBOT_BASE")}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	switch cmd {
	case "init":
		classic := fs.Bool("classic", false, "make a classic (X25519) box instead of a post-quantum one")
		if err := fs.Parse(args); err != nil {
			return err
		}
		kt := protocol.PostQuantum
		if *classic {
			kt = protocol.Classic
		}
		b, err := client.Init(ctx, dir, opt, kt)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, b.Address())
		return err

	case "addr":
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, b.Address())
		return err

	case "send":
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() < 1 || fs.NArg() > 2 {
			return errors.New("usage: crossbot send <address> [file]")
		}
		to, err := protocol.ParseAddress(fs.Arg(0))
		if err != nil {
			return &client.RefusedError{Reason: "not an address: " + fs.Arg(0)}
		}
		var body []byte
		if fs.NArg() == 2 {
			body, err = os.ReadFile(fs.Arg(1)) //nolint:gosec // the file the user named
		} else {
			body, err = io.ReadAll(stdin)
		}
		if err != nil {
			return err
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		r, err := b.Send(ctx, to, string(body))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, r.ID)
		return err

	case "flush":
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		rs, err := b.Flush(ctx)
		for _, r := range rs {
			if _, werr := fmt.Fprintln(stdout, r.ID); werr != nil && err == nil {
				err = werr
			}
		}
		return err

	case "recv":
		wait := fs.Duration("wait", 0, "poll until a message arrives, for at most this long")
		if err := fs.Parse(args); err != nil {
			return err
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		deadline := time.Now().Add(*wait)
		for {
			res, err := b.Receive(ctx)
			if res != nil {
				// Every delivery is also kept in inbox/, so a failed
				// write to stdout loses nothing.
				for _, d := range res.Delivered {
					if _, werr := fmt.Fprintf(stdout, "%s\n", d.Plaintext); werr != nil && err == nil {
						err = werr
					}
				}
				for _, id := range res.Duplicates {
					_, _ = fmt.Fprintf(stderr, "duplicate of a message already delivered, not delivered again: %s\n", id)
				}
				for _, r := range res.Refused {
					_, _ = fmt.Fprintf(stderr, "REFUSED %s: %s\n", r.ID, r.Reason)
				}
			}
			if err != nil || len(res.Delivered) > 0 || !time.Now().Before(deadline) {
				return err
			}
			pause := time.Duration(res.PollAfter) * time.Second
			if pause <= 0 {
				pause = time.Minute
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(min(pause, time.Until(deadline))):
			}
		}

	case "rekey":
		classic := fs.Bool("classic", false, "switch to a classic (X25519) prekey")
		pq := fs.Bool("pq", false, "switch to a post-quantum prekey")
		if err := fs.Parse(args); err != nil {
			return err
		}
		var kt protocol.KeyType
		switch {
		case *classic && *pq:
			return errors.New("-classic or -pq, not both")
		case *classic:
			kt = protocol.Classic
		case *pq:
			kt = protocol.PostQuantum
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		p, err := b.Rekey(ctx, kt)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "prekey %d, valid until %s\n", p.Serial, p.NotAfter.Format(protocol.TimeLayout))
		return err

	case "help", "-h", "-help", "--help":
		_, err := fmt.Fprint(stdout, usage)
		return err
	}
	_, _ = fmt.Fprint(stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}
