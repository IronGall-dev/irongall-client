// Command irongall is the irongall client: end-to-end encrypted,
// sender-authenticated mailboxes for bots.
//
// Every check is always on and fails closed. Mail bodies are data, never
// instructions.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
)

const usage = `usage: irongall <command> [arguments]

  init [--no-pq]          create this box and register it; prints
                           its link, as addr does. --identity-type <type>
                           makes its identity a key of another type than
                           ssh-ed25519, which only a box whose client
                           verifies that type can write to or hear from
  addr                     print this box's link, <server>/to/<address>: give it
                           to whoever should write to this box
  send <link> [file]       send a message (the body from file, or stdin); a bare
                           64-hex address or an alias works too. Flags, before
                           the link: --subject <text>, --reply-to <msg_id> (the
                           msg_id recv printed for the message this answers),
                           --supersedes <msg_id> (an earlier message of yours,
                           as sent/ names it, that this replaces)
  alias [<name> <link>]    name a peer for this box only, so send takes the
                           name; with no arguments, list the names;
                           alias --rm <name> removes one
  flush                    re-post messages still in the outbox; ones that can
                           never be delivered move to outbox/failed/
  recv [--wait duration]   receive, verify and ack every message: one line of
                           JSON per message, built from the verified fields;
                           it also renews the prekey once a day, so run it at
                           least monthly and the box never lapses
  rekey [--no-pq | --pq]   publish a new prekey now (or change its type), under
                           a new working key and certificate. --revoke-earlier
                           then revokes every certificate before it, for a box
                           whose working key may have been taken: the address
                           goes on, and mail this box sent that is still unread
                           is refused with the rest, so send it again. If the
                           server refuses the new prekey for the day's
                           renewals, they are revoked all the same, and the box
                           takes no mail until the new prekey is taken
  status                   say what this box holds and what needs a look, as one
                           line of JSON, from its own files and with no call
                           to the server: its prekey, a renewal that has not
                           gone through, refused mail in quarantine/, mail not
                           yet delivered
  adopt <key>              join the account an adopt key names, which can
                           lift this box's limits; adopt --leave leaves it
  revocation               print this box's revocation as one line of JSON, and
                           publish nothing. Whoever publishes that record ends
                           this address for good, with no key: keep it somewhere
                           other than this box, for the day the box is lost
  revoke <address>         revoke this box's address, FOR GOOD: nothing undoes
                           it. The address written out in full is the
                           confirmation. --record <file> publishes a record made
                           earlier by revocation, and needs no box here. It
                           goes to the server and to each revocation server,
                           and the command fails, saying which, unless every
                           one took it: run it again
  revoked <file>           take a revocation of another box that someone handed
                           you (a record as revocation prints), check it, and
                           keep it: this box then sends that address nothing
                           and takes nothing from it. A record may carry a
                           revocation of the box's certificates, which is kept
                           the same way. revoked --ask <link> asks the server
                           and each revocation server what it holds about a
                           box, and keeps what verifies: send does that by
                           itself, before it posts. revoked --publish <file>
                           sends a record that carries a revocation of
                           certificates, and none of the address, to the
                           server and each revocation server: this box's own
                           revoked-certs.json, when a server did not take it

The box lives in $IRONGALL_HOME, or ${XDG_CONFIG_HOME:-~/.config}/irongall/${IRONGALL_BOX:-default}.
Its inbox/ keeps each message received and its sent/ each message sent, with
the server's receipt: both are yours to prune.
The server is $IRONGALL_BASE, or https://irongall.dev.
Beside its server a box asks revocation servers whether an address is revoked,
and publishes its own revocations to them: those $IRONGALL_REVOCATION_SERVERS
names (URLs with spaces or commas between, or "none"), or else those its
revocation-servers file names, one to a line. With neither, a box on
irongall.dev asks ` + client.DefaultRevocationServer + `, which irongall.dev's
operator runs, and a box on another server asks none. A revocation server
learns which addresses a box asks about: name one run by anyone else only if
you mean to tell it. No answer from one changes nothing, and status lists them.
With each prekey a box declares which identity key types its client verifies,
and so whose mail it takes: every type this client verifies, unless
$IRONGALL_SENDER_KEY_TYPES says otherwise ("any": do not say).

Exit status: 0, done. 1, the command failed. 2, help. 3, the command did its
work and the box needs a look: from recv, mail was received as printed and
the prekey, due for renewal, was not renewed; from status, its "attention"
list is not empty. recv says on stderr what it refused, keeping each refused
message in quarantine/, and refused mail does not change its exit status,
since any sender can cause one: keep recv's stderr, or run status after it. A refusal is
"REFUSED <id>: <code>: <words>", the words this client's own: it never quotes
a message. What a server says in an error is printed in quotes, as its words.

To try the whole loop, send anything to irongall.dev's echo box,
` + client.DefaultBase + protocol.LinkPath + client.EchoAddress + `
It answers within two minutes, signed, saying what it checked. Mail to it
is readable by irongall.dev's operator.

The README has the rest, with what this client checks and how to test it:
` + readme + `
`

// readme is where this client's documentation is: the public repository it
// is built from, never the server.
const readme = "https://github.com/IronGall-dev/irongall-client#readme"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1], os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	var look *needsALook
	switch {
	case errors.Is(err, flag.ErrHelp):
		os.Exit(2)
	case errors.As(err, &look):
		if look.why != "" {
			fmt.Fprintln(os.Stderr, look.why)
		}
		os.Exit(3)
	case err != nil:
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// needsALook is how a command says it did its work and the box needs a look:
// exit status 3, where a failure is 1.
type needsALook struct{ why string }

func (e *needsALook) Error() string { return e.why }

func run(ctx context.Context, cmd string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	dir, err := client.Dir()
	if err != nil {
		return err
	}
	opt := client.Options{Base: os.Getenv("IRONGALL_BASE")}
	if v := os.Getenv("IRONGALL_SENDER_KEY_TYPES"); v != "" {
		opt.SenderKeyTypes = strings.Split(v, ",")
	}
	if v := os.Getenv("IRONGALL_REVOCATION_SERVERS"); v != "" {
		if opt.RevocationServers, err = client.ParseRevocationServers(v); err != nil {
			return fmt.Errorf("$IRONGALL_REVOCATION_SERVERS: %w", err)
		}
	}
	// Said, and nothing more: a box does not wait on a revocation server.
	opt.NoAnswer = func(server string, err error) {
		_, _ = fmt.Fprintf(stderr, "the revocation server %s gave no answer, which changes nothing here: %v\n", server, err)
	}
	// The flag package takes one dash or two and writes one. This client
	// writes two everywhere, so it prints a command's flags and a bad flag's
	// error itself.
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	parse := func() error {
		err := fs.Parse(args)
		switch {
		case errors.Is(err, flag.ErrHelp):
			printFlags(stderr, fs)
		case err != nil:
			err = errors.New(oneDash.ReplaceAllString(err.Error(), "$1--$2"))
		}
		return err
	}
	switch cmd {
	case "init":
		noPQ := fs.Bool("no-pq", false, "make a box without post-quantum encryption (X25519 only), which age 1.2 can reach")
		idType := fs.String("identity-type", "", "make the identity a key of this type, not ssh-ed25519: "+protocol.IdentityP256+". Every client verifies ssh-ed25519; a box of another type is reached only by boxes whose client verifies it")
		if err := parse(); err != nil {
			return err
		}
		kt := protocol.PostQuantum
		if *noPQ {
			kt = protocol.Classic
		}
		if opt.IdentityType = *idType; *idType != "" && *idType != protocol.IdentityEd25519 {
			_, _ = fmt.Fprintf(stderr, "WARNING: a box whose identity is of the key type %s can neither write to nor hear from a box whose client does not verify that type. Every client verifies ssh-ed25519, which init makes without --identity-type.\n", *idType)
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
		fs.StringVar(&f.Subject, "subject", "", "the message's subject: any `text`")
		fs.StringVar(&f.InReplyTo, "reply-to", "", "the `msg_id` of the message this answers, as recv printed it")
		fs.StringVar(&f.Supersedes, "supersedes", "", "the `msg_id` of an earlier message of yours that this replaces, as sent/ names it")
		if err := parse(); err != nil {
			return err
		}
		if fs.NArg() < 1 || fs.NArg() > 2 {
			return errors.New("usage: irongall send [--subject <text>] [--reply-to <msg_id>] [--supersedes <msg_id>] <link, address or alias> [file] (flags come before the link)")
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
		rm := fs.String("rm", "", "remove the alias of this `name`")
		if err := parse(); err != nil {
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
		return errors.New("usage: irongall alias <name> <link or address>, irongall alias (to list them), or irongall alias --rm <name>")

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
		if err := parse(); err != nil {
			return err
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		deadline := time.Now().Add(*wait)
		// renewErr is a renewal that was due and failed, and that no later
		// Receive of this run made good.
		var renewErr error
		for {
			res, err := b.Receive(ctx)
			if res != nil {
				if res.Renewed != nil {
					renewErr = nil
				}
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
					_, _ = fmt.Fprintf(stderr, "REFUSED %s: %s: %s\n", r.ID, r.Code, r.Reason)
				}
				if res.More {
					_, _ = fmt.Fprintln(stderr, "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server")
				}
				if res.RenewErr != nil {
					renewErr = res.RenewErr
					_, _ = fmt.Fprintf(stderr, "the prekey is due for renewal and was not renewed (recv tries again within the hour): %v\n", res.RenewErr)
				}
			}
			pause := time.Minute
			if res != nil && res.PollAfter > 0 {
				pause = time.Duration(res.PollAfter) * time.Second
			}
			// A rate limit or a restarting server says how long to wait:
			// --wait waits it out when there is time to poll again after.
			var e *client.APIError
			if errors.As(err, &e) && e.RetryAfter > 0 && time.Until(deadline) > e.RetryAfter {
				_, _ = fmt.Fprintf(stderr, "%v: waiting %s\n", err, e.RetryAfter)
				pause = e.RetryAfter
			} else if err != nil || len(res.Delivered) > 0 || !time.Now().Before(deadline) {
				if err == nil && renewErr != nil {
					return &needsALook{"mail was received as printed, and the prekey was not renewed: this box needs a look (irongall status)"}
				}
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(min(pause, time.Until(deadline))):
			}
		}

	case "status":
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		st, err := b.Status()
		if err != nil {
			return err
		}
		line, err := json.Marshal(st)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(stdout, "%s\n", line); err != nil {
			return err
		}
		if len(st.Attention) > 0 {
			return &needsALook{}
		}
		return nil

	case "rekey":
		noPQ := fs.Bool("no-pq", false, "switch to a prekey without post-quantum encryption (X25519 only)")
		pq := fs.Bool("pq", false, "switch to a post-quantum prekey")
		earlier := fs.Bool("revoke-earlier", false, "also revoke every certificate before the new one, for a box whose working key may have been taken; if the server refuses the new prekey for the day's renewals, they are revoked all the same")
		if err := parse(); err != nil {
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
		if !*earlier {
			p, err := b.Rekey(ctx, kt)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(stdout, "prekey %d, valid until %s\n", p.Serial, p.NotAfter.Format(protocol.TimeLayout))
			return err
		}
		r, err := b.RenewAndRevoke(ctx, kt)
		if r == nil {
			return fmt.Errorf("no new prekey, and nothing is revoked: %w", err)
		}
		if r.Prekey != nil {
			if _, err := fmt.Fprintf(stdout, "prekey %d, valid until %s\n", r.Prekey.Serial, r.Prekey.NotAfter.Format(protocol.TimeLayout)); err != nil {
				return err
			}
		}
		switch {
		case r.Revoked == nil && r.NotRenewed != nil:
			return fmt.Errorf("the new prekey is NOT published, and nothing is revoked: %w. The revocation goes out without the new prekey only when the server refuses it for the day's renewals", r.NotRenewed)
		case r.Revoked == nil && err != nil:
			return fmt.Errorf("the new prekey is published, and the earlier certificates are NOT revoked: %w", err)
		case r.Revoked == nil:
			_, err = fmt.Fprintln(stdout, "no earlier certificate to revoke")
			return err
		}
		_, _ = fmt.Fprintln(stderr, "Mail this box sent before now, and that its reader has not read yet, was signed under a certificate just revoked and will be refused: send it again.")
		// A server took the revocation, and not every one: it is out, this
		// box keeps it, and the record it keeps is what publishes it again.
		if err != nil {
			return fmt.Errorf("the revocation of the certificates through %d is not everywhere: %w. This box keeps it, and this publishes it again: irongall revoked --publish %s", r.Revoked.Through, err, filepath.Join(dir, "revoked-certs.json"))
		}
		if _, err := fmt.Fprintf(stdout, "certificates through %d revoked\n", r.Revoked.Through); err != nil || r.NotRenewed == nil {
			return err
		}
		// The revocation went out without the new prekey: the box is dark
		// until the server takes it.
		return fmt.Errorf("the new prekey is NOT published: %w. Every certificate before %d is revoked, the one this box was using among them, so it takes no mail until the new prekey is taken: irongall rekey sends it again, and so does irongall recv", r.NotRenewed, r.Below)

	case "adopt":
		leave := fs.Bool("leave", false, "leave the box's account")
		if err := parse(); err != nil {
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

	case "revocation":
		if err := parse(); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("usage: irongall revocation")
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		rec, err := b.Revocation()
		if err != nil {
			return err
		}
		line, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(stderr, "This record revokes this box's address, for good, when anyone publishes it (irongall revoke <address> --record <file>). Nothing was published. Keep it somewhere other than this box.")
		_, err = fmt.Fprintf(stdout, "%s\n", line)
		return err

	case "revoke":
		record := fs.String("record", "", "publish the record in this `file`, made earlier by irongall revocation, in place of signing one with this box's identity")
		if err := parse(); err != nil {
			return err
		}
		const how = "usage: irongall revoke [--record <file>] <address> (the 64-character address, in full: it is the confirmation, and a revocation cannot be undone)"
		if fs.NArg() != 1 {
			return errors.New(how)
		}
		a, err := protocol.ParseAddress(fs.Arg(0))
		if err != nil {
			return errors.New(how)
		}
		// The box here, if there is one: a record is published to the
		// revocation servers it lists. With --record none is needed.
		b, openErr := client.Open(dir, opt)
		var rec *protocol.Revocations
		if *record != "" {
			if rec, err = readRecord(*record); err != nil {
				return err
			}
			if protocol.Address(sha256.Sum256(rec.Identity)) != a {
				return errors.New("the record is a revocation of another address than the one named: nothing was published")
			}
		} else {
			if openErr != nil {
				return openErr
			}
			if b.Address() != a {
				return errors.New("that is not this box's address: nothing was published. irongall revoke takes this box's own address, or a record of another with --record")
			}
			if rec, err = b.Revocation(); err != nil {
				return err
			}
		}
		// To the server and to each revocation server, every one whatever
		// the others answer.
		var perr error
		if openErr == nil {
			_, perr = b.Revoke(ctx, rec)
		} else {
			_, perr = client.Revoke(ctx, opt, rec)
		}
		var part *client.NotPublishedError
		if perr != nil && (!errors.As(perr, &part) || len(part.Took) == 0) {
			return perr
		}
		// Once any server has taken it, it is out. If the box it is about is
		// the one here, it keeps it too.
		if openErr == nil && b.Address() == a {
			if _, _, err := b.KeepRevocation(rec); err != nil {
				return err
			}
		}
		// Not everywhere is a failure, and says who took it and who did not:
		// the same command again is the cure.
		if perr != nil {
			return perr
		}
		_, err = fmt.Fprintf(stdout, "revoked %s\n", a)
		return err

	case "revoked":
		ask := fs.Bool("ask", false, "ask the server, and each revocation server this box lists, what it holds about the box a `link`, address or alias names, in place of reading a record from a file, and keep what verifies")
		publish := fs.Bool("publish", false, "send the record in the `file`, which carries a revocation of certificates and none of the address, to the server and to each revocation server this box lists, and keep it")
		if err := parse(); err != nil {
			return err
		}
		if fs.NArg() != 1 || (*ask && *publish) {
			return errors.New("usage: irongall revoked <file> (a record as irongall revocation prints), irongall revoked --ask <link>, or irongall revoked --publish <file>")
		}
		b, err := client.Open(dir, opt)
		if err != nil {
			return err
		}
		var a protocol.Address
		var held *client.Held
		if *publish {
			rec, err := readRecord(fs.Arg(0))
			if err != nil {
				return err
			}
			// What ends an address goes out only with that address written
			// in full, as its confirmation.
			if len(rec.Revocation) > 0 {
				return errors.New("the record carries a revocation of its address, which nothing undoes: nothing was published. irongall revoke --record <file> <address> publishes one, with the address in full as the confirmation")
			}
			if a, _, err = b.KeepRevocation(rec); err != nil {
				return err
			}
			certs, err := protocol.ParseRevokedCertificates(rec.RevokedCertificates)
			if err != nil {
				return err
			}
			if _, err := b.Publish(ctx, rec); err != nil {
				return err
			}
			_, err = fmt.Fprintf(stdout, "published the revocation of the certificates of %s through %d\n", a, certs.Through)
			return err
		}
		if *ask {
			if a, err = b.Destination(fs.Arg(0)); err != nil {
				return err
			}
			if held, err = b.Ask(ctx, a); err != nil {
				return err
			}
		} else {
			rec, err := readRecord(fs.Arg(0))
			if err != nil {
				return err
			}
			if a, held, err = b.KeepRevocation(rec); err != nil {
				return err
			}
		}
		// What the box holds, which is what it checks a send and a read
		// against. A server's "none" is its word, and is said as that.
		switch {
		case held.Revoked:
			_, err = fmt.Fprintf(stdout, "revoked %s\n", a)
		case held.Certificates != nil:
			_, err = fmt.Fprintf(stdout, "certificates of %s revoked through %d\n", a, held.Certificates.Through)
		default:
			_, _ = fmt.Fprintln(stderr, "That is the word of whoever was asked, this box's server and the revocation servers it lists, and any of them can keep a record back: a record from the box's owner settles it (irongall revoked <file>).")
			_, err = fmt.Fprintf(stdout, "no revocation of %s shown\n", a)
		}
		return err

	case "help", "-h", "-help", "--help":
		_, err := fmt.Fprint(stdout, usage)
		return err
	}
	_, _ = fmt.Fprint(stderr, usage)
	return fmt.Errorf("unknown command %q", cmd)
}

// maxRecord bounds a revocation record read from a file: one is under a
// kilobyte.
const maxRecord = 64 << 10

// readRecord reads a revocation record: the JSON irongall revocation prints.
// What it holds is checked by whoever uses it.
func readRecord(name string) (*protocol.Revocations, error) {
	f, err := os.Open(name) //nolint:gosec // a file the caller named
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read only
	data, err := io.ReadAll(io.LimitReader(f, maxRecord+1))
	if err != nil {
		return nil, err
	}
	var rec protocol.Revocations
	if len(data) > maxRecord || protocol.Unmarshal(data, &rec) != nil || len(rec.Identity) == 0 || (len(rec.Revocation) == 0 && len(rec.RevokedCertificates) == 0) {
		return nil, errors.New("the file is not a revocation record: one is a line of JSON with \"identity\" and \"revocation\", as irongall revocation prints, or with a revocation of its certificates")
	}
	return &rec, nil
}

// oneDash finds a flag as the flag package's errors write it, with one dash.
var oneDash = regexp.MustCompile(`(^|[ :])-([a-z])`)

// printFlags prints a command's flags, with two dashes.
func printFlags(w io.Writer, fs *flag.FlagSet) {
	_, _ = fmt.Fprintf(w, "flags of irongall %s (irongall help describes every command):\n", fs.Name())
	fs.VisitAll(func(f *flag.Flag) {
		value, usage := flag.UnquoteUsage(f)
		if value != "" {
			value = " <" + value + ">"
		}
		_, _ = fmt.Fprintf(w, "  --%s%s\n        %s\n", f.Name, value, usage)
	})
}
