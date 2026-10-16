package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/spf13/cobra"
)

// tree is every command: the everyday ones at the top level, and a group for
// each thing that has more than one thing done to it.
func (e *cli) tree() *cobra.Command {
	root := e.group("irongall", "", "",
		e.initCmd(), e.addrCmd(), e.sendCmd(), e.recvCmd(), e.statusCmd(), e.heldCmd(),
		e.group("peer", "who may write to this box: allow, block, list",
			`Mail from a sender this box has not allowed is held in held/ (irongall held
lists it), and mail from a sender it blocked is dropped. Sending to a box, or
naming it with irongall alias add, allows it too. The box's policy file says
where mail from a sender not allowed lands, and whom its server takes mail
from: irongall help has it.`,
			e.allowCmd(), e.blockCmd(), e.peerListCmd()),
		e.group("alias", "names for peers, which send takes in place of a link: add, rm, list",
			`An alias is this box's own name for a peer, kept in its aliases file as
"<name> <address>" lines, which either client and a person may write. A name
allows its peer, as irongall peer allow does, and is never moved: to change
one, remove it and add it again.`,
			e.aliasAddCmd(), e.aliasRmCmd(), e.aliasListCmd()),
		e.group("outbox", "mail not yet delivered: flush",
			`A message is kept in outbox/ until a server takes it. One that can never be
delivered moves to outbox/failed/: delete it there to drop it.`,
			e.flushCmd()),
		e.group("prekey", "the key senders encrypt to: renew",
			`A prekey is valid for 33 days, under a working key and a certificate made
with it. irongall recv renews it once a day, so run recv at least monthly and
the box never lapses.`,
			e.renewCmd()),
		e.group("cert", "this box's certificates: revoke-earlier, publish-revoked",
			`This box's identity certifies a working key with each prekey, and the working
key signs what the box says. A box whose working key may have been taken
revokes every certificate before a new one: the address goes on.`,
			e.revokeEarlierCmd(), e.publishRevokedCmd()),
		e.group("account", "the account that can lift this box's limits: adopt, leave",
			`An account can lift the limits of the boxes in it. An adopt key, from the
account's holder, puts a box in it.`,
			e.adoptCmd(), e.leaveCmd()),
		e.group("revocation", "ending an address for good: make, publish, keep, ask",
			`A revocation ends an address for good, and only its identity's own signature
makes one. A box keeps every revocation that verifies, of an address and of an
address's certificates, and checks what it sends and receives against them.`,
			e.makeCmd(), e.publishCmd(), e.keepCmd(), e.askCmd()),
	)
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpFunc(func(c *cobra.Command, _ []string) {
		_, _ = io.WriteString(e.stdout, helpText(c))
	})
	root.SetHelpCommand(command("help [<command>]", "print this help, or a command's",
		`irongall help <command> and irongall <command> --help print a command's
help, and irongall <group> help a group's.`,
		cobra.ArbitraryArgs, func(_ *cobra.Command, args []string) error {
			t, rest, err := root.Find(args)
			switch {
			case err != nil:
				return err
			case len(rest) > 0:
				return unknown(t, rest)
			}
			_, err = io.WriteString(e.stdout, helpText(t))
			return err
		}))
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error { return wrong(c, "%v", err) })
	return root
}

func (e *cli) initCmd() *cobra.Command {
	var noPQ bool
	var idType string
	c := command("init [flags]", "create this box and register it; prints its link",
		`Create this box and register it, and print its address and its link,
<server>/to/<address>, as addr does.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			kt := protocol.PostQuantum
			if noPQ {
				kt = protocol.Classic
			}
			opt := e.opt
			var warning any
			if opt.IdentityType = idType; idType != "" && idType != protocol.IdentityEd25519 {
				warning = fmt.Sprintf("WARNING: a box whose identity is of the key type %s can neither write to nor hear from a box whose client does not verify that type. Every client verifies ssh-ed25519, which init makes without --identity-type.", idType)
			}
			b, err := client.Init(c.Context(), e.dir, opt, kt)
			if err != nil {
				return err
			}
			return e.out(line("box", "address", b.Address(), "link", b.Link(), "message", warning))
		})
	c.Flags().BoolVar(&noPQ, "no-pq", false, "make a box without post-quantum encryption (X25519 only), which age 1.2 can reach")
	c.Flags().StringVar(&idType, "identity-type", "", "make the identity a key of this `type`, not ssh-ed25519: "+protocol.IdentityP256+". Every client verifies ssh-ed25519; a box of another type is reached only by boxes whose client verifies it")
	return c
}

func (e *cli) addrCmd() *cobra.Command {
	return command("addr", "print this box's link, for whoever should write to it",
		`Print this box's address and its link, <server>/to/<address>: give the link
to whoever should write to this box.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			return e.out(line("box", "address", b.Address(), "link", b.Link()))
		})
}

func (e *cli) sendCmd() *cobra.Command {
	var f client.Fields
	var asJSON bool
	c := command("send [flags] <link, address or alias> [file]", "send a message: the body from a file, or stdin",
		`Send one message to a link, a bare 64-hex address or an alias, with the body
from the file, or from stdin, and print the server's id for it and its msg_id.
It waits in outbox/ until a server takes it (irongall outbox flush posts it
again), and is then kept in sent/ with the server's receipt. Sending to a box
allows it.

The body is text, unless --json says it is one JSON value: then an object
arrives as that object, not as a string. One its reader would refuse, a name
twice in an object among them, is refused, and nothing is sent.`,
		nargs(1, 2), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			to, err := b.Destination(args[0])
			if err != nil {
				return err
			}
			var body []byte
			if len(args) == 2 {
				body, err = os.ReadFile(args[1]) //nolint:gosec // the file the user named
			} else {
				body, err = io.ReadAll(e.stdin)
			}
			if err != nil {
				return err
			}
			var s *client.Sent
			if asJSON {
				s, err = b.SendJSON(c.Context(), to, body, f)
			} else {
				s, err = b.SendWith(c.Context(), to, string(body), f)
			}
			if err != nil {
				return err
			}
			return e.out(sent(s))
		})
	c.Flags().BoolVar(&asJSON, "json", false, "the body is one JSON value, sent as that value and not as text")
	c.Flags().StringVar(&f.Subject, "subject", "", "the message's subject: any `text`")
	c.Flags().StringVar(&f.InReplyTo, "reply-to", "", "the `msg_id` of the message this answers, as recv printed it")
	c.Flags().StringVar(&f.Supersedes, "supersedes", "", "the `msg_id` of an earlier message of yours that this replaces, as sent/ names it")
	return c
}

func (e *cli) recvCmd() *cobra.Command {
	var wait time.Duration
	c := command("recv [flags]", "receive, verify and ack every message: one line of JSON each",
		`Receive, verify and ack every message: a "mail" line for each, built from the
verified fields. It also renews the prekey once a day, so run it at least
monthly and the box never lapses. It prints a "refused" line for each message
it refused, keeping it in quarantine/, and a "held" line for each it held,
keeping it in held/.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			return e.recv(c, b, wait)
		})
	c.Flags().DurationVar(&wait, "wait", 0, "poll until a message arrives, for at most this long")
	return c
}

func (e *cli) recv(c *cobra.Command, b *client.Box, wait time.Duration) error {
	ctx := c.Context()
	deadline := time.Now().Add(wait)
	// renewErr is a renewal that was due and failed, and that no later
	// Receive of this run made good; aclErr the same for the box's ACL.
	var renewErr, aclErr error
	for {
		res, err := b.Receive(ctx)
		if res != nil {
			if res.Renewed != nil {
				renewErr = nil
			}
			// A mail line is this client's own, from the verified fields:
			// never the sender's bytes.
			var lines [][]byte
			for _, d := range res.Delivered {
				lines = append(lines, mail(d))
			}
			for _, id := range res.Duplicates {
				lines = append(lines, line("duplicate", "id", id, "message", "a retry of a message already delivered: not delivered again"))
			}
			for _, r := range res.Refused {
				lines = append(lines, line("refused", "id", r.ID, "code", r.Code, "message", r.Reason))
			}
			for _, h := range res.Held {
				lines = append(lines, line("held", "id", h.ID, "from", h.Envelope.From, "message",
					"from a sender this box has not allowed: kept in held/ (irongall held lists it, and irongall peer allow delivers it)"))
			}
			for _, id := range res.Blocked {
				lines = append(lines, line("dropped", "id", id, "message", "from a sender this box blocked: dropped"))
			}
			switch {
			case res.Paced > 0:
				lines = append(lines, line("paced", "retry_after", seconds(res.Paced), "message",
					fmt.Sprintf("the server paces how much mail this box takes out: the rest is still on the server; run recv again in %d seconds or later", seconds(res.Paced))))
			case res.More:
				lines = append(lines, line("more", "message", "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"))
			}
			if res.RenewErr != nil {
				renewErr = res.RenewErr
				lines = append(lines, line("renewal_failed", failure(fmt.Errorf("the prekey is due for renewal and was not renewed: recv tries again within the hour, and irongall status says whether it went through: %w", res.RenewErr))...))
			}
			aclErr = res.ACLErr
			if res.ACLErr != nil {
				lines = append(lines, line("acl_not_sent", failure(fmt.Errorf("this box's ACL has changed and was not sent to its server: the next recv sends it, and irongall status says whether it went through: %w", res.ACLErr))...))
			}
			// Every delivery is also kept in inbox/, and every refusal in
			// quarantine/, so a failed write to stdout loses nothing.
			for _, l := range lines {
				if werr := e.out(l); werr != nil && err == nil {
					err = werr
				}
			}
		}
		pause := time.Minute
		if res != nil && res.PollAfter > 0 {
			pause = time.Duration(res.PollAfter) * time.Second
		}
		// A paced drain goes on once the server's wait is over, and not
		// before: what is left is on the server, whatever the poll interval.
		if res != nil && res.Paced > 0 {
			pause = res.Paced
		}
		// A rate limit or a restarting server says how long to wait:
		// --wait waits it out when there is time to poll again after.
		var ae *client.APIError
		if errors.As(err, &ae) && ae.RetryAfter > 0 && time.Until(deadline) > ae.RetryAfter {
			e.say(line("waiting", append([]any{"for", "server"}, failure(err)...)...))
			pause = ae.RetryAfter
		} else if err != nil || len(res.Delivered) > 0 || !time.Now().Before(deadline) {
			if err == nil && (renewErr != nil || aclErr != nil) {
				return &needsALook{}
			}
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(min(pause, time.Until(deadline))):
		}
	}
}

func (e *cli) statusCmd() *cobra.Command {
	return command("status", "say what this box holds and what needs a look, as one line of JSON",
		`Say what this box holds and what needs a look, as one "status" line, from its
own files and with no call to the server: its prekey, a renewal that has not
gone through, refused mail in quarantine/, held mail, mail not yet delivered.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			s, err := b.Status()
			if err != nil {
				return err
			}
			st, err := json.Marshal(s)
			if err != nil {
				return err
			}
			if err := e.out(typed("status", st)); err != nil {
				return err
			}
			if len(s.Attention) > 0 {
				return &needsALook{}
			}
			return nil
		})
}

func (e *cli) heldCmd() *cobra.Command {
	return command("held", "list the mail held/ keeps, one line of JSON for each sender",
		`List the mail held/ keeps, from senders this box has not allowed: a
"held_sender" line for each sender, with its address, the ids, and the first
and last sent_at. held/<id>.json is the message recv's "mail" line would have
carried. irongall peer allow delivers a sender's held mail to inbox/, and
irongall peer block deletes it.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			hs, err := b.HeldMail()
			for _, h := range hs {
				l, jerr := json.Marshal(h)
				if jerr == nil {
					jerr = e.out(typed("held_sender", l))
				}
				if jerr != nil && err == nil {
					err = jerr
				}
			}
			return err
		})
}

func (e *cli) allowCmd() *cobra.Command {
	var rebuild bool
	c := command("allow [flags] <link, address or alias>", "let a sender's mail land in inbox/, and deliver what held/ keeps from it",
		`Let a sender's mail land in inbox/. It moves what held/ keeps from that sender
to inbox/, printing it as recv does, then an "allowed" line. --rebuild, with
no sender, adds back every address an alias names or sent/ shows, for an
allowed file that was lost.`,
		func(c *cobra.Command, args []string) error {
			if rebuild && len(args) > 0 {
				return wrong(c, "irongall peer allow --rebuild takes no sender: it adds back every address an alias names or sent/ shows")
			}
			if rebuild {
				return nil
			}
			return nargs(1, 1)(c, args)
		}, func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			if rebuild {
				n, err := b.RebuildAllowed()
				if err != nil {
					return err
				}
				if err := e.out(line("allowed_rebuilt", "added", n)); err != nil {
					return err
				}
				return b.SyncACL(c.Context())
			}
			a, err := b.Destination(args[0])
			if err != nil {
				return err
			}
			moved, err := b.Allow(c.Context(), a)
			for _, d := range moved {
				if werr := e.out(mail(d)); werr != nil && err == nil {
					err = werr
				}
			}
			if err != nil {
				return err
			}
			return e.out(line("allowed", "address", a))
		})
	c.Flags().BoolVar(&rebuild, "rebuild", false, "add back every address an alias names or sent/ shows, for an allowed file that was lost")
	return c
}

func (e *cli) blockCmd() *cobra.Command {
	return command("block <link, address or alias>", "drop a sender's mail, here and at the server",
		`Drop a sender's mail, here and at the server, and delete what held/ keeps
from it, then print a "blocked" line. Blocking wins over allowing.`,
		nargs(1, 1), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			a, err := b.Destination(args[0])
			if err != nil {
				return err
			}
			n, err := b.Block(c.Context(), a)
			if err != nil {
				if n > 0 {
					return fmt.Errorf("%w (%d messages held from it were deleted)", err, n)
				}
				return err
			}
			return e.out(line("blocked", "address", a, "deleted", n))
		})
}

func (e *cli) peerListCmd() *cobra.Command {
	var allowed, blocked bool
	c := command("list [flags]", "list the senders allowed and blocked",
		`List the senders this box allows and blocks, an "allowed" or a "blocked" line
each, with its address. The allowed are those its allowed file lists and
those an alias names. Blocking wins over allowing, so an address can be on
both.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			if !allowed && !blocked {
				allowed, blocked = true, true
			}
			for _, l := range []struct {
				on   bool
				name string
				list func() ([]protocol.Address, error)
			}{{allowed, "allowed", b.Allowed}, {blocked, "blocked", b.Blocked}} {
				if !l.on {
					continue
				}
				as, err := l.list()
				if err != nil {
					return err
				}
				for _, a := range as {
					if err := e.out(line(l.name, "address", a)); err != nil {
						return err
					}
				}
			}
			return nil
		})
	c.Flags().BoolVar(&allowed, "allowed", false, "list the senders allowed only")
	c.Flags().BoolVar(&blocked, "blocked", false, "list the senders blocked only")
	return c
}

func (e *cli) aliasAddCmd() *cobra.Command {
	return command("add <name> <link or address>", "name a peer, so send takes the name",
		`Name a peer for this box only, so send takes the name. A name is up to 32
lowercase letters, digits, '.', '_' and '-', starting with a letter or a
digit. It allows its peer.`,
		nargs(2, 2), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			// The name first, so swapped arguments are told what an alias is.
			if err := client.ValidAlias(args[0]); err != nil {
				return err
			}
			to, err := b.Destination(args[1])
			if err != nil {
				return err
			}
			if err := b.SetAlias(args[0], to); err != nil {
				return err
			}
			if err := e.out(line("alias", "name", args[0], "address", to)); err != nil {
				return err
			}
			return b.SyncACL(c.Context())
		})
}

func (e *cli) aliasRmCmd() *cobra.Command {
	return command("rm <name>", "remove a name", `Remove the alias of this name, and print an "alias_removed" line.`,
		nargs(1, 1), func(_ *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			if err := b.RemoveAlias(args[0]); err != nil {
				return err
			}
			return e.out(line("alias_removed", "name", args[0]))
		})
}

func (e *cli) aliasListCmd() *cobra.Command {
	return command("list", "list the names, an \"alias\" line each",
		`List the names this box has given its peers, an "alias" line each, with the
name and its address.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			as, err := b.Aliases()
			for _, a := range as {
				if werr := e.out(line("alias", "name", a.Name, "address", a.Address)); werr != nil && err == nil {
					err = werr
				}
			}
			return err
		})
}

func (e *cli) flushCmd() *cobra.Command {
	return command("flush", "post again what is still in the outbox",
		`Post again every message still in the outbox, unchanged, and print a "sent"
line for each the server takes, as send does: a retry gets the original
receipt. One that can never be delivered moves to outbox/failed/.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			ss, err := b.Flush(c.Context())
			for _, s := range ss {
				if werr := e.out(sent(s)); werr != nil && err == nil {
					err = werr
				}
			}
			return err
		})
}

// keyType is the prekey type --no-pq or --pq asks for, and none for neither:
// the box keeps the type it has.
func keyType(noPQ, pq bool) (protocol.KeyType, error) {
	switch {
	case noPQ && pq:
		return "", errors.New("--no-pq or --pq, not both")
	case noPQ:
		return protocol.Classic, nil
	case pq:
		return protocol.PostQuantum, nil
	}
	return "", nil
}

func (e *cli) renewCmd() *cobra.Command {
	var noPQ, pq bool
	c := command("renew [flags]", "publish a new prekey now, or change its type",
		`Publish a new prekey now, under a new working key and certificate. With
neither --no-pq nor --pq it keeps the type the box has.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			kt, err := keyType(noPQ, pq)
			if err != nil {
				return wrong(c, "%v", err)
			}
			b, err := e.box()
			if err != nil {
				return err
			}
			p, err := b.Rekey(c.Context(), kt)
			if err != nil {
				return err
			}
			return e.out(prekey(p))
		})
	c.Flags().BoolVar(&noPQ, "no-pq", false, "switch to a prekey without post-quantum encryption (X25519 only)")
	c.Flags().BoolVar(&pq, "pq", false, "switch to a post-quantum prekey")
	return c
}

func (e *cli) revokeEarlierCmd() *cobra.Command {
	var noPQ, pq bool
	c := command("revoke-earlier [flags]", "publish a new prekey, then revoke every certificate before it",
		`For a box whose working key may have been taken: publish a new prekey, under
a new working key and certificate, as irongall prekey renew does, then revoke
every certificate before it. The address goes on, and mail this box sent that
is still unread is refused with the rest, so send it again. If the server
refuses the new prekey for the day's renewals, they are revoked all the same,
and the box takes no mail until the new prekey is taken.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			kt, err := keyType(noPQ, pq)
			if err != nil {
				return wrong(c, "%v", err)
			}
			b, err := e.box()
			if err != nil {
				return err
			}
			r, err := b.RenewAndRevoke(c.Context(), kt)
			if r == nil {
				return fmt.Errorf("no new prekey, and nothing is revoked: %w", err)
			}
			if r.Prekey != nil {
				if err := e.out(prekey(r.Prekey)); err != nil {
					return err
				}
			}
			switch {
			case r.Revoked == nil && r.NotRenewed != nil:
				return fmt.Errorf("the new prekey is NOT published, and nothing is revoked: %w. The revocation goes out without the new prekey only when the server refuses it for the day's renewals", r.NotRenewed)
			case r.Revoked == nil && err != nil:
				return fmt.Errorf("the new prekey is published, and the earlier certificates are NOT revoked: %w", err)
			case r.Revoked == nil:
				return e.out(line("no_earlier_certificate", "message", "no earlier certificate to revoke"))
			}
			const resend = "Mail this box sent before now, and that its reader has not read yet, was signed under a certificate just revoked and will be refused: send it again."
			// A server took the revocation, and not every one: it is out, this
			// box keeps it, and the record it keeps is what publishes it again.
			if err != nil {
				return fmt.Errorf("the revocation of the certificates through %d is not everywhere: %w. This box keeps it, and this publishes it again: irongall cert publish-revoked. %s", r.Revoked.Through, err, resend)
			}
			if err := e.out(line("certificates_revoked", "address", b.Address(), "through", r.Revoked.Through, "message", resend)); err != nil || r.NotRenewed == nil {
				return err
			}
			// The revocation went out without the new prekey: the box is dark
			// until the server takes it.
			return fmt.Errorf("the new prekey is NOT published: %w. Every certificate before %d is revoked, the one this box was using among them, so it takes no mail until the new prekey is taken: irongall prekey renew sends it again, and so does irongall recv", r.NotRenewed, r.Below)
		})
	c.Flags().BoolVar(&noPQ, "no-pq", false, "switch to a prekey without post-quantum encryption (X25519 only)")
	c.Flags().BoolVar(&pq, "pq", false, "switch to a post-quantum prekey")
	return c
}

func (e *cli) publishRevokedCmd() *cobra.Command {
	return command("publish-revoked [<file>]", "send a revocation of certificates to every server again",
		`Send a record that carries a revocation of certificates, and none of an
address, to the server and to each revocation server, and keep it: the file
named, or with none this box's own revoked-certs.json, when a server did not
take it. A record that ends an address is refused: irongall revocation publish
takes that one, with the address in full.`,
		nargs(0, 1), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			name := filepath.Join(e.dir, "revoked-certs.json")
			if len(args) == 1 {
				name = args[0]
			} else if _, err := os.Stat(name); errors.Is(err, os.ErrNotExist) {
				return errors.New("this box holds no revocation of its certificates: irongall cert revoke-earlier makes one")
			}
			rec, err := readRecord(name)
			if err != nil {
				return err
			}
			// What ends an address goes out only with that address written
			// in full, as its confirmation.
			if len(rec.Revocation) > 0 {
				return errors.New("the record carries a revocation of its address, which nothing undoes: nothing was published. irongall revocation publish --record <file> <address> publishes one, with the address in full as the confirmation")
			}
			a, _, err := b.KeepRevocation(rec)
			if err != nil {
				return err
			}
			certs, err := protocol.ParseRevokedCertificates(rec.RevokedCertificates)
			if err != nil {
				return err
			}
			if _, err := b.Publish(c.Context(), rec); err != nil {
				return err
			}
			return e.out(line("certificates_revoked", "address", a, "through", certs.Through, "message", "published to the server and to each revocation server"))
		})
}

func (e *cli) adoptCmd() *cobra.Command {
	return command("adopt <key>", "join the account an adopt key names",
		`Join the account an adopt key names, which can lift this box's limits.`,
		nargs(1, 1), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			acc, err := b.Adopt(c.Context(), args[0])
			if err != nil {
				return err
			}
			return e.out(line("account", "account", acc))
		})
}

func (e *cli) leaveCmd() *cobra.Command {
	return command("leave", "leave the box's account", `Leave the box's account.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			if err := b.Leave(c.Context()); err != nil {
				return err
			}
			return e.out(line("account", "account", json.RawMessage("null"), "message", "in no account"))
		})
}

func (e *cli) makeCmd() *cobra.Command {
	return command("make", "print this box's revocation, and publish nothing",
		`Print this box's revocation record, one "revocation_record" line, and publish
nothing. Whoever publishes that record ends this address for good, with no
key: keep it where only you can read it, somewhere other than this box, for
the day the box is lost (umask 077; irongall revocation make > <file>). The
line is the record as every server takes it: irongall revocation publish
--record publishes it, and so does a PUT of it to
<server>/v1/<address>/revocations.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			rec, err := b.Revocation()
			if err != nil {
				return err
			}
			// The record names its own type, first: the line is the record.
			r, err := json.Marshal(rec)
			if err != nil {
				return err
			}
			return e.out(r)
		})
}

func (e *cli) publishCmd() *cobra.Command {
	var record string
	const how = "irongall revocation publish takes the 64-character address, in full: it is the confirmation, and a revocation cannot be undone"
	c := command("publish [flags] <address>", "revoke this box's address, FOR GOOD",
		`Revoke this box's address, FOR GOOD: nothing undoes it. The address written
out in full is the confirmation. --record <file> publishes a record made
earlier by irongall revocation make, and needs no box here. It goes to the
server and to each revocation server, and the command fails, saying which,
unless every one took it: run it again.`,
		func(c *cobra.Command, args []string) error {
			if len(args) != 1 {
				return wrong(c, "%s", how)
			}
			return nil
		}, func(c *cobra.Command, args []string) error {
			a, err := protocol.ParseAddress(args[0])
			if err != nil {
				return errors.New(how)
			}
			// The box here, if there is one: a record is published to the
			// revocation servers it lists. With --record none is needed.
			b, openErr := e.box()
			var rec *protocol.Revocations
			if record != "" {
				if rec, err = readRecord(record); err != nil {
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
					return errors.New("that is not this box's address: nothing was published. irongall revocation publish takes this box's own address, or a record of another with --record")
				}
				if rec, err = b.Revocation(); err != nil {
					return err
				}
			}
			// To the server and to each revocation server, every one whatever
			// the others answer.
			var perr error
			if openErr == nil {
				_, perr = b.Revoke(c.Context(), rec)
			} else {
				_, perr = client.Revoke(c.Context(), e.opt, rec)
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
			return e.out(line("revoked", "address", a, "message", "published to the server and to each revocation server"))
		})
	c.Flags().StringVar(&record, "record", "", "publish the record in this `file`, made earlier by irongall revocation make, in place of signing one with this box's identity")
	return c
}

func (e *cli) keepCmd() *cobra.Command {
	return command("keep <file>", "keep a revocation someone handed you",
		`Take a revocation of another box that someone handed you (a record as
irongall revocation make prints), check it, and keep it: this box then sends
that address nothing and takes nothing from it. A record may carry a
revocation of the box's certificates, which is kept the same way.`,
		nargs(1, 1), func(_ *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			rec, err := readRecord(args[0])
			if err != nil {
				return err
			}
			a, held, err := b.KeepRevocation(rec)
			if err != nil {
				return err
			}
			return e.sayHeld(a, held)
		})
}

func (e *cli) askCmd() *cobra.Command {
	return command("ask <link, address or alias>", "ask the servers what they hold about a box, and keep what verifies",
		`Ask the server, and each revocation server this box lists, what it holds
about a box, and keep what verifies. send does that by itself, before it
posts.`,
		nargs(1, 1), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			a, err := b.Destination(args[0])
			if err != nil {
				return err
			}
			held, err := b.Ask(c.Context(), a)
			if err != nil {
				return err
			}
			return e.sayHeld(a, held)
		})
}

// sayHeld says what the box holds of an address, which is what it checks a
// send and a read against. A server's "none" is its word, and is said as that.
func (e *cli) sayHeld(a protocol.Address, held *client.Held) error {
	switch {
	case held.Revoked:
		return e.out(line("revoked", "address", a))
	case held.Certificates != nil:
		return e.out(line("certificates_revoked", "address", a, "through", held.Certificates.Through))
	}
	return e.out(line("not_revoked", "address", a, "message", "no revocation shown. That is the word of whoever was asked, this box's server and the revocation servers it lists, and any of them can keep a record back: a record from the box's owner settles it (irongall revocation keep <file>)."))
}

// sent is the line for a message the server took.
func sent(s *client.Sent) []byte {
	return line("sent", "id", s.ID, "msg_id", s.MsgID, "to", s.To)
}

// prekey is the line for a prekey this box published.
func prekey(p *protocol.Prekey) []byte {
	return line("prekey", "serial", p.Serial, "not_after", p.NotAfter.UTC().Format(protocol.TimeLayout))
}

// maxRecord bounds a revocation record read from a file: one is under a
// kilobyte.
const maxRecord = 64 << 10

// readRecord reads a revocation record: the JSON irongall revocation make
// prints. What it holds is checked by whoever uses it.
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
		return nil, errors.New("the file is not a revocation record: one is a line of JSON with \"identity\" and \"revocation\", as irongall revocation make prints, or with a revocation of its certificates")
	}
	return &rec, nil
}
