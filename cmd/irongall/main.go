// Command irongall is the irongall client: end-to-end encrypted,
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

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

const usage = `usage: irongall <command> [arguments]

  init [--no-pq]          create this box, register it and activate it; prints
                           its link, as addr does
  addr                     print this box's link, <server>/to/<address>: give it
                           to whoever should write to this box
  send <link> [file]       send a message (the body from file, or stdin); a bare
                           64-hex address or an alias works too. Flags, before
                           the link: -subject <text>, -reply-to <msg_id> (the
                           msg_id recv printed for the message this answers),
                           -supersedes <msg_id> (an earlier message of yours,
                           as sent/ names it, that this replaces)
  alias [<name> <link>]    name a peer for this box only, so send takes the
                           name; with no arguments, list the names;
                           alias -rm <name> removes one
  flush                    re-post messages still in the outbox; ones that can
                           never be delivered move to outbox/failed/
  recv [-wait duration]    receive, verify and ack every message: one line of
                           JSON per message, built from the verified fields;
                           it also renews the prekey once a day, so run it at
                           least monthly and the box never lapses
  rekey [--no-pq | --pq]   publish a new prekey now (or change its type)
  adopt <key>              join the account an adopt key names, which can
                           lift this box's limits; adopt --leave leaves it

The box lives in $IRONGALL_HOME, or ${XDG_CONFIG_HOME:-~/.config}/irongall/${IRONGALL_BOX:-default}.
Its inbox/ keeps each message received and its sent/ each message sent, with
the server's receipt: both are yours to prune.
The server is $IRONGALL_BASE, or https://irongall.dev.

To try the whole loop, send anything to irongall.dev's echo box,
` + client.DefaultBase + protocol.LinkPath + client.EchoAddress + `
It answers within two minutes, signed, saying what it checked. Mail to it
is readable by irongall.dev's operator.
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
	opt := client.Options{Base: os.Getenv("IRONGALL_BASE")}
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	switch cmd {
	case "init":
		noPQ := fs.Bool("no-pq", false, "make a box without post-quantum encryption (X25519 only), which age 1.2 can reach")
		if err := fs.Parse(args); err != nil {
			return err
		}
		kt := protocol.PostQuantum
		if *noPQ {
			kt = protocol.Classic
		}
		b, err := client.Init(ctx, dir, opt, kt)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, b.Link())
		return err

	case "addr":
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, b.Link())
		return err

	case "send":
		var f client.Fields
		fs.StringVar(&f.Subject, "subject", "", "the message's subject")
		fs.StringVar(&f.InReplyTo, "reply-to", "", "the msg_id of the message this answers, as recv printed it")
		fs.StringVar(&f.Supersedes, "supersedes", "", "the msg_id of an earlier message of yours that this replaces, as sent/ names it")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() < 1 || fs.NArg() > 2 {
			return errors.New("usage: irongall send [-subject <text>] [-reply-to <msg_id>] [-supersedes <msg_id>] <link, address or alias> [file] (flags come before the link)")
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		to, err := b.Destination(fs.Arg(0))
		if err != nil {
			return err
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
		r, err := b.SendWith(ctx, to, string(body), f)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, r.ID)
		return err

	case "alias":
		rm := fs.String("rm", "", "remove this alias")
		if err := fs.Parse(args); err != nil {
			return err
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		switch {
		case *rm != "" && fs.NArg() == 0:
			return b.RemoveAlias(*rm)
		case *rm == "" && fs.NArg() == 0:
			as, err := b.Aliases()
			for _, a := range as {
				if _, werr := fmt.Fprintf(stdout, "%s %s\n", a.Name, a.Address); werr != nil && err == nil {
					err = werr
				}
			}
			return err
		case *rm == "" && fs.NArg() == 2:
			// The name first, so swapped arguments are told what an alias is.
			if err := client.ValidAlias(fs.Arg(0)); err != nil {
				return err
			}
			to, err := b.Destination(fs.Arg(1))
			if err != nil {
				return err
			}
			if err := b.SetAlias(fs.Arg(0), to); err != nil {
				return err
			}
			_, err = fmt.Fprintf(stdout, "%s %s\n", fs.Arg(0), to)
			return err
		}
		return errors.New("usage: irongall alias <name> <link or address>, irongall alias (to list them), or irongall alias -rm <name>")

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
				// write to stdout loses nothing. The line is this client's
				// own, from the verified fields: never the sender's bytes.
				for _, d := range res.Delivered {
					if _, werr := fmt.Fprintf(stdout, "%s\n", d.Line); werr != nil && err == nil {
						err = werr
					}
				}
				for _, id := range res.Duplicates {
					_, _ = fmt.Fprintf(stderr, "duplicate of a message already delivered, not delivered again: %s\n", id)
				}
				for _, r := range res.Refused {
					_, _ = fmt.Fprintf(stderr, "REFUSED %s: %s\n", r.ID, r.Reason)
				}
				if res.RenewErr != nil {
					_, _ = fmt.Fprintf(stderr, "the prekey is due for renewal and was not renewed (recv tries again within the hour): %v\n", res.RenewErr)
				}
			}
			pause := time.Minute
			if res != nil && res.PollAfter > 0 {
				pause = time.Duration(res.PollAfter) * time.Second
			}
			// A rate limit or a restarting server says how long to wait:
			// -wait waits it out when there is time to poll again after.
			var e *client.APIError
			if errors.As(err, &e) && e.RetryAfter > 0 && time.Until(deadline) > e.RetryAfter {
				_, _ = fmt.Fprintf(stderr, "%v: waiting %s\n", err, e.RetryAfter)
				pause = e.RetryAfter
			} else if err != nil || len(res.Delivered) > 0 || !time.Now().Before(deadline) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(min(pause, time.Until(deadline))):
			}
		}

	case "rekey":
		noPQ := fs.Bool("no-pq", false, "switch to a prekey without post-quantum encryption (X25519 only)")
		pq := fs.Bool("pq", false, "switch to a post-quantum prekey")
		if err := fs.Parse(args); err != nil {
			return err
		}
		var kt protocol.KeyType
		switch {
		case *noPQ && *pq:
			return errors.New("--no-pq or --pq, not both")
		case *noPQ:
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

	case "adopt":
		leave := fs.Bool("leave", false, "leave the box's account")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if *leave != (fs.NArg() == 0) || fs.NArg() > 1 {
			return errors.New("usage: irongall adopt <key>, or irongall adopt --leave")
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		if *leave {
			if err := b.Leave(ctx); err != nil {
				return err
			}
			_, err = fmt.Fprintln(stdout, "in no account")
			return err
		}
		acc, err := b.Adopt(ctx, fs.Arg(0))
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(stdout, "in account %s\n", acc)
		return err

	case "help", "-h", "-help", "--help":
		_, err := fmt.Fprint(stdout, usage)
		return err
	}
	_, _ = fmt.Fprint(stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}
