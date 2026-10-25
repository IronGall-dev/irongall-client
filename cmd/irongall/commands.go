package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/spf13/cobra"
)

// tree is every command: the everyday ones at the top level, and a group for
// each thing that has more than one thing done to it.
func (e *cli) tree() *cobra.Command {
	root := e.group("irongall", "", "",
		e.initCmd(), e.addrCmd(), e.sendCmd(), e.recvCmd(), e.showCmd(), e.statusCmd(), e.heldCmd(),
		e.group("peer", "who may write to this box: allow, block, list",
			`Mail from a sender this box has not allowed is held in held/ (irongall held
lists it), and mail from a sender it blocked is dropped. Sending to a box, or
naming it with irongall alias add, allows it too. The box's policy file says
where mail from a sender not allowed lands, and whom its server takes mail
from: irongall help has it.`,
			e.allowCmd(), e.blockCmd(), e.peerListCmd()),
		e.group("alias", "names for peers, which send takes in place of a link: add, rm, list",
			`An alias is this box's own name for a peer, kept in its aliases file as
"<name> <address>" lines, which a person may write too. A name
allows its peer, as irongall peer allow does, and is never moved: to change
one, remove it and add it again.`,
			e.aliasAddCmd(), e.aliasRmCmd(), e.aliasListCmd()),
		e.group("outbox", "mail not yet delivered: flush",
			`A message is kept in outbox/ until a server takes it. One that can never be
delivered moves to outbox/failed/: delete it there to drop it.`,
			e.flushCmd()),
		e.group("quarantine", "mail refused for a failed check: list, rm",
			`A message that failed a check is never delivered: recv acks it and keeps it
in quarantine/, as evidence of who sent what. Read it through these commands,
which print this client's words only: the files keep what the server served,
with each of its strings in base64 that is not of its form.`,
			e.quarantineListCmd(), e.quarantineRmCmd()),
		e.group("prekey", "the key senders encrypt to: renew, lifetime",
			`A prekey is valid for 33 days, or the shorter lifetime this box is set to,
under a working key and a certificate made with it. irongall recv renews it
once it is a day old, so run recv at least monthly, and the box never lapses;
irongall prekey lifetime --help says how often for a shorter lifetime.`,
			e.renewCmd(), e.lifetimeCmd()),
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
		checked(nargs(0, 0), func(c *cobra.Command, _ []string) error {
			if idType != "" && !slices.Contains(protocol.IdentityTypes(), idType) {
				return wrong(c, "%s makes an identity of the key type %s, and %q is not one", c.CommandPath(), strings.Join(protocol.IdentityTypes(), " or "), idType)
			}
			return nil
		}), func(c *cobra.Command, _ []string) error {
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
			if err := e.out(sent(s)); err != nil {
				return err
			}
			return e.aclNotSent(s.ACLErr)
		})
	// curl's --json posts what it is given with no check that it is JSON; this
	// one holds the body to its reader's rules first, so a name given twice is
	// refused, never kept once.
	c.Flags().BoolVar(&asJSON, "json", false, "the body is one JSON value, sent as that value and not as text")
	c.Flags().StringVar(&f.Subject, "subject", "", "the message's subject: any `text`")
	c.Flags().StringVar(&f.InReplyTo, "reply-to", "", "the `msg_id` of the message this answers, as recv printed it")
	c.Flags().StringVar(&f.Supersedes, "supersedes", "", "the `msg_id` of an earlier message of yours that this replaces, as sent/ names it")
	return c
}

func (e *cli) recvCmd() *cobra.Command {
	var wait, drain time.Duration
	var headers bool
	c := command("recv [flags]", "receive, verify and ack every message: one line of JSON each",
		`Receive, verify and ack every message: a "mail" line for each, built from the
verified fields. It also renews the prekey once a day, so run it at least
monthly and the box never lapses. It prints a "refused" line for each message
it refused, keeping it in quarantine/, and a "held" line for each it held,
keeping it in held/.

With --headers, a "mail_headers" line takes each "mail" line's place: its
"envelope" has the fields this client checked with none of the text the
sender chose, no body and no subject, and the line has the body's size. Each
message is kept in inbox/ as ever, and irongall show <id> prints its "mail"
line, so a reader can decide by sender before it reads what the sender wrote.

One drain runs for at most --drain-time, holding the box's lock: there it
stops with a "more" line, as at its other limits, and keeps what it read of
the message it was fetching, which the next recv goes on from.`,
		checked(nargs(0, 0), func(c *cobra.Command, _ []string) error {
			if drain <= 0 {
				return wrong(c, "%s --drain-time takes a duration above zero, such as 15m", c.CommandPath())
			}
			return nil
		}), func(c *cobra.Command, _ []string) error {
			e.opt.DrainTime = drain
			b, err := e.box()
			if err != nil {
				return err
			}
			return e.recv(c, b, wait, headers)
		})
	c.Flags().DurationVar(&wait, "wait", 0, "poll until a message arrives, for at most this long")
	c.Flags().DurationVar(&drain, "drain-time", client.DefaultDrainTime, "how long one drain runs before it stops for the next recv")
	// As an IMAP client fetches a message's ENVELOPE apart from its body (RFC
	// 9051 §6.4.5), as mail clients list headers before they open a message.
	c.Flags().BoolVar(&headers, "headers", false, "print each message's checked fields and its body's size, without its body or subject")
	return c
}

func (e *cli) showCmd() *cobra.Command {
	return command("show <id>", "print a message inbox/ keeps, as recv printed it",
		`Print the "mail" line of a message inbox/ keeps, by the id recv printed: what
recv prints without --headers. An id that is not 64 lowercase hex is refused
before any file is read.`,
		checked(nargs(1, 1), func(c *cobra.Command, args []string) error {
			if !client.IsID(args[0]) {
				return wrong(c, "%s takes a message's id, 64 lowercase hex, as recv prints it", c.CommandPath())
			}
			return nil
		}), func(_ *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			l, err := b.InboxLine(args[0])
			if err != nil {
				return err
			}
			return e.out(mail(client.Delivery{ID: args[0], Line: l}))
		})
}

func (e *cli) quarantineListCmd() *cobra.Command {
	return command("list", "list the mail quarantine/ keeps, one line of JSON each",
		`List the mail quarantine/ keeps: a "quarantined" line for each message, with
its id, the code it was refused for (the README's table has each), and the
sender and the time the server gave, each only when it has its form.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			qs, err := b.Quarantined(c.Context())
			for _, q := range qs {
				l, jerr := json.Marshal(q)
				if jerr == nil {
					jerr = e.out(typed("quarantined", l))
				}
				if jerr != nil && err == nil {
					err = jerr
				}
			}
			return err
		})
}

func (e *cli) quarantineRmCmd() *cobra.Command {
	var all bool
	c := command("rm [flags] [<id>...]", "delete refused mail from quarantine/",
		`Delete each message named, by the id irongall quarantine list prints, or with
--all every one, and print a "removed" line for each. Nothing is deleted when
an id is not one, or names no message quarantine/ keeps.`,
		func(c *cobra.Command, args []string) error {
			switch {
			case all && len(args) > 0:
				return wrong(c, "%s takes ids or --all, not both", c.CommandPath())
			case !all && len(args) == 0:
				return wrong(c, "%s takes the ids to delete, or --all", c.CommandPath())
			}
			for _, id := range args {
				if !client.IsID(id) {
					return wrong(c, "%s takes messages' ids, 64 lowercase hex, as irongall quarantine list prints them", c.CommandPath())
				}
			}
			return nil
		}, func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			gone, err := b.RemoveQuarantined(c.Context(), args)
			for _, id := range gone {
				if werr := e.out(line("removed", "id", id)); werr != nil && err == nil {
					err = werr
				}
			}
			return err
		})
	c.Flags().BoolVar(&all, "all", false, "delete every message quarantine/ keeps")
	return c
}

func (e *cli) recv(c *cobra.Command, b *client.Box, wait time.Duration, headers bool) error {
	ctx := c.Context()
	deadline := time.Now().Add(wait)
	// renewErr is a renewal that was due and failed, and that no later
	// Receive of this run made good; aclErr the same for the box's ACL;
	// notMade what the box's last read of itself served that it did not make;
	// and replaced that a renewal of this run found an ACL at the server that
	// the box had not sent, and replaced it.
	var renewErr, aclErr error
	var notMade *client.NotMade
	replaced := false
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
				if headers {
					lines = append(lines, mailHeaders(d))
				} else {
					lines = append(lines, mail(d))
				}
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
				lines = append(lines, line("paced", "retry_after", seconds(res.Again()), "message",
					fmt.Sprintf("the server paces how much mail this box takes out: the rest is still on the server; run recv again in %d seconds or later", seconds(res.Again()))))
			case res.More:
				lines = append(lines, line("more", "message", "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server"))
			}
			if res.RenewErr != nil {
				renewErr = res.RenewErr
				lines = append(lines, line("renewal_failed", failure(fmt.Errorf("the prekey is due for renewal and was not renewed: recv tries again within the hour, and irongall status says whether it went through: %w", res.RenewErr))...))
			}
			notMade = res.NotMade
			if res.NotMade != nil {
				lines = append(lines, notMadeLine(res.NotMade))
			}
			aclErr = res.ACLErr
			if res.ACLErr != nil {
				lines = append(lines, line("acl_not_sent", failure(fmt.Errorf("the next recv sends this box's ACL, and irongall status says whether it went through: %w", res.ACLErr))...))
			}
			if res.ACLReplaced {
				replaced = true
				lines = append(lines, line("acl_replaced", "message", "this box's server held an ACL other than the one this box last sent it, which another machine of this box, someone holding its pass or the server itself wrote: this box sent its own in its place"))
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
		if res != nil && res.Again() > 0 {
			pause = res.Again()
		}
		// A rate limit or a restarting server says how long to wait:
		// --wait waits it out when there is time to poll again after.
		var ae *client.APIError
		if errors.As(err, &ae) && ae.RetryAfter > 0 && time.Until(deadline) > ae.RetryAfter {
			e.say(line("waiting", append([]any{"for", "server"}, failure(err)...)...))
			pause = ae.RetryAfter
		} else if err != nil || len(res.Delivered) > 0 || !time.Now().Before(deadline) {
			if err == nil && (renewErr != nil || aclErr != nil || notMade != nil || replaced) {
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
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			s, err := b.Status(c.Context())
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
				n, err := b.RebuildAllowed(c.Context())
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
from it, then print a "blocked" line. Blocking wins over allowing. The server
then refuses that sender's next send as sender_not_allowed, which is final,
so the sender learns that it is refused.`,
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
			if err := b.SetAlias(c.Context(), args[0], to); err != nil {
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
		nargs(1, 1), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			if err := b.RemoveAlias(c.Context(), args[0]); err != nil {
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
		`Post again every message still in the outbox, each sealed afresh to what the
box holds now, and print a "sent" line for each the server takes, as send
does. One that can never be delivered moves to outbox/failed/.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			ss, err := b.Flush(c.Context())
			var aclErr error
			for _, s := range ss {
				if werr := e.out(sent(s)); werr != nil && err == nil {
					err = werr
				}
				aclErr = s.ACLErr
			}
			if err != nil {
				return err
			}
			return e.aclNotSent(aclErr)
		})
}

// aclNotSent says that a post went ahead though the box's ACL was not taken,
// since the one its server last took admits the reply: the box needs a look.
func (e *cli) aclNotSent(err error) error {
	if err == nil {
		return nil
	}
	if werr := e.out(line("acl_not_sent", failure(fmt.Errorf("the box's server takes the reply under the ACL it last took: the next send or recv sends this box's, and irongall status says whether it went through: %w", err))...)); werr != nil {
		return werr
	}
	return &needsALook{}
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
		checked(nargs(0, 0), func(c *cobra.Command, _ []string) error {
			if _, err := keyType(noPQ, pq); err != nil {
				return wrong(c, "%v", err)
			}
			return nil
		}), func(c *cobra.Command, _ []string) error {
			kt, _ := keyType(noPQ, pq)
			b, err := e.box()
			if err != nil {
				return err
			}
			p, err := b.Rekey(c.Context(), kt)
			if p != nil {
				// Published, whatever fault of this box came after.
				if werr := e.out(prekey(p)); err == nil {
					err = werr
				}
			}
			if err != nil {
				return err
			}
			nm, err := b.NotMade(c.Context())
			if err != nil || nm == nil {
				return err
			}
			if err := e.out(notMadeLine(nm)); err != nil {
				return err
			}
			return &needsALook{}
		})
	c.Flags().BoolVar(&noPQ, "no-pq", false, "switch to a prekey without post-quantum encryption (X25519 only)")
	c.Flags().BoolVar(&pq, "pq", false, "switch to a post-quantum prekey")
	return c
}

// shortLifetime is the prekey lifetime under which setting one warns: with
// less, a recv once a day does not renew a prekey while the room a renewal
// leaves is left (client.RecvWithin): the day between two recv runs, the
// day recv waits to renew, the hour for the renewal's own calls and the hour
// for clocks.
const shortLifetime = 2*24*time.Hour + time.Hour + protocol.MaxSkew

func (e *cli) lifetimeCmd() *cobra.Command {
	return command("lifetime [<time>]", "how long each new prekey is valid for: print it, or set it",
		`Print how long each new prekey of this box is valid for, or set it, from
1d3h to 33d, the default. A time is written as sshd writes one: numbers, each
with its unit, s, m, h, d or w, added together, as in 2d2h or 90m; a number
with no unit is seconds. recv renews the prekey once it is a day old, so with
a lifetime L it must run at least every L less a day and two hours, or the
prekey runs out, or comes so near it that a sender whose clock is ahead
refuses it, and senders are refused until the box renews. A lifetime set
lower holds from the next recv, which renews a prekey made for longer.`,
		checked(nargs(0, 1), func(c *cobra.Command, args []string) error {
			if len(args) == 0 {
				return nil
			}
			d, err := parseTime(args[0])
			if err != nil {
				return wrong(c, "%v", err)
			}
			if d < client.MinPrekeyLifetime || d > protocol.PrekeyLifetime {
				return wrong(c, "a prekey lifetime is from %s to %s, and %s is not", formatTime(client.MinPrekeyLifetime), formatTime(protocol.PrekeyLifetime), formatTime(d))
			}
			return nil
		}), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			if len(args) == 1 {
				d, _ := parseTime(args[0])
				if err := b.SetPrekeyLifetime(c.Context(), d); err != nil {
					return err
				}
			}
			d, err := b.PrekeyLifetime()
			if err != nil {
				return err
			}
			var warning any
			if d < shortLifetime {
				warning = fmt.Sprintf("WARNING: a lifetime under %s risks a single missed daily check-in leaving this box unable to receive messages. At %s, run irongall recv at least every %s.", formatTime(shortLifetime), formatTime(d), formatTime(client.RecvWithin(d)))
			}
			return e.out(line("prekey_lifetime", "seconds", int64(d/time.Second), "lifetime", formatTime(d), "message", warning))
		})
}

// timeUnits are the units of a time as sshd reads one (sshd_config(5), TIME
// FORMATS), in either case.
var timeUnits = map[byte]time.Duration{'s': time.Second, 'm': time.Minute, 'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour}

// parseTime reads a time as sshd does (sshd_config(5), TIME FORMATS): a
// sequence of numbers, each with a unit or none for seconds, added together,
// as in 600, 10m or 2d1h. It is OpenSSH's convtime, as 10.3p1 to 10.6p1 have
// it (misc.c, convtime_double; #193): each number in decimal digits alone,
// any number of them, a fraction only on seconds and only with a digit after
// its point, seconds named once, and the sum truncated to whole seconds, at
// most INT_MAX of them.
//
// It differs from convtime in one place, kept as it is (#389): a fraction
// below binary64's smallest normal, 2.2250738585072014e-308, so with some
// 308 digits after its point, which strconv.ParseFloat reads as a subnormal
// or zero, and convtime refuses wherever its libc's strtod sets ERANGE for
// an underflow (POSIX.1-2024, strtod). Which such fractions underflow is the
// libc's, glibc alone measured, so no code here follows one. Such a fraction
// is under a second, which the truncation drops: what parseTime takes there
// is the seconds the rest of the time names, every time convtime takes reads
// as the same seconds here, and the only time parseTime reads is one the
// box's owner types (prekey lifetime).
func parseTime(s string) (time.Duration, error) {
	no := fmt.Errorf("%.40q is no time: one is numbers, each with its unit (s, m, h, d or w), as in 2d1h", s)
	if s == "" {
		return 0, no
	}
	total, seconds := 0.0, false
	for p := 0; p < len(s); {
		i := p
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i < len(s) && s[i] == '.' {
			i++
			for i < len(s) && s[i] >= '0' && s[i] <= '9' {
				i++
			}
		}
		num := s[p:i]
		if strings.Trim(num, ".") == "" { // no digit: what strtod reads none of
			return 0, no
		}
		v, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, no
		}
		unit := 1.0
		switch {
		case i == len(s) || s[i] == 's' || s[i] == 'S':
			if seconds {
				return 0, no
			}
			seconds = true
		default:
			u, ok := timeUnits[s[i]|0x20]
			if !ok || u == time.Second {
				return 0, no
			}
			unit = u.Seconds()
		}
		if strings.Contains(num, ".") && (unit > 1 || num[len(num)-1] == '.') {
			return 0, no
		}
		total += v * unit
		if p = i; p < len(s) {
			p++
		}
	}
	if total > math.MaxInt32 {
		return 0, fmt.Errorf("%.40q is longer than any prekey lifetime", s)
	}
	return time.Duration(int64(total)) * time.Second, nil
}

// formatTime writes d as parseTime reads it, in days, hours, minutes and
// seconds, as in 1d1h or 33d.
func formatTime(d time.Duration) string {
	var b strings.Builder
	for _, u := range []struct {
		d time.Duration
		c string
	}{{24 * time.Hour, "d"}, {time.Hour, "h"}, {time.Minute, "m"}, {time.Second, "s"}} {
		if n := d / u.d; n > 0 {
			fmt.Fprintf(&b, "%d%s", n, u.c)
			d -= n * u.d
		}
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
}

func (e *cli) revokeEarlierCmd() *cobra.Command {
	var noPQ, pq bool
	c := command("revoke-earlier [flags]", "revoke every certificate before a new one, then publish a new prekey under it",
		`For a box whose working key may have been taken: make a new prekey, under a
new working key and certificate, revoke every certificate before that one, and
then publish the new prekey. The address goes on, and mail this box sent that
is still unread is refused with the rest, so send it again. Until the server
takes the new prekey, the box sends no mail, and once its server holds the
revocation it takes none there either.`,
		checked(nargs(0, 0), func(c *cobra.Command, _ []string) error {
			if _, err := keyType(noPQ, pq); err != nil {
				return wrong(c, "%v", err)
			}
			return nil
		}), func(c *cobra.Command, _ []string) error {
			kt, _ := keyType(noPQ, pq)
			b, err := e.box()
			if err != nil {
				return err
			}
			r, err := b.RenewAndRevoke(c.Context(), kt)
			return e.remedied(b.Address(), r, err)
		})
	c.Flags().BoolVar(&noPQ, "no-pq", false, "switch to a prekey without post-quantum encryption (X25519 only)")
	c.Flags().BoolVar(&pq, "pq", false, "switch to a post-quantum prekey")
	return c
}

// remedied prints what the remedy of box own did, r and err as
// RenewAndRevoke returned them, and returns the command's error: what became
// of the new prekey first, then of the revocation, then a fault of the box
// after what a server took, which is never dropped (#110, #383). What a
// server took is said as taken. A box shown its own revocation says that
// alone (#326), and RenewAndRevoke's error is then that revocation
// (outcome), so nothing is dropped there.
func (e *cli) remedied(own protocol.Address, r *client.Remedy, err error) error {
	if r == nil {
		var gone *client.RevokedError
		if errors.As(err, &gone) {
			return err
		}
		return fmt.Errorf("no new prekey, and nothing is revoked: %w", err)
	}
	// A box shown its own revocation before its renewal was taken says
	// that alone: it sends nothing again and renews nothing (#326).
	if gone := (*client.RevokedError)(nil); errors.As(r.NotRenewed, &gone) && gone.Own {
		return r.NotRenewed
	}
	if r.Unread != nil {
		if err := e.out(line("box_unread", failure(fmt.Errorf("this box's server could not be read, or served what this box does not take, so the new certificate was numbered from what this box knows: %w", r.Unread))...)); err != nil {
			return err
		}
	}
	if r.Prekey != nil {
		if err := e.out(prekey(r.Prekey)); err != nil {
			return err
		}
	}
	if r.Revoked != nil {
		const resend = "Mail this box sent before now, and that its reader has not read yet, was signed under a certificate just revoked and will be refused: send it again."
		if err := e.out(line("certificates_revoked", "address", own, "through", r.Revoked.Through, "message", resend)); err != nil {
			return err
		}
	}
	dark := fmt.Sprintf("Every certificate before %d is revoked, the one this box was using among them, so it sends no mail, and its server takes none for it, until the new prekey is taken: irongall prekey renew sends it again, and so does irongall recv", r.Below)
	// What a line printed above has not said, the prekey's first.
	var said error
	switch {
	case r.NotRenewed == nil && r.NotRevoked == nil && r.Revoked == nil:
		if err == nil {
			return e.out(line("no_earlier_certificate", "message", "no earlier certificate to revoke"))
		}
	case r.NotRenewed == nil && r.NotRevoked == nil:
	case r.NotRenewed == nil:
		said = fmt.Errorf("the new prekey is published, and the earlier certificates are NOT revoked: %w. irongall cert revoke-earlier revokes them", r.NotRevoked)
	case r.NotRevoked == nil:
		said = fmt.Errorf("the new prekey is NOT published: %w. %s", r.NotRenewed, dark)
	default:
		said = fmt.Errorf("the new prekey is NOT published: %w, and nothing is revoked: %v. irongall cert revoke-earlier tries both again", r.NotRenewed, r.NotRevoked)
	}
	// Then the fault of this box after what a server took, in every case.
	switch {
	case said == nil:
		return err
	case err == nil:
		return said
	}
	return fmt.Errorf("%w. %w", said, err)
}

func (e *cli) publishRevokedCmd() *cobra.Command {
	return command("publish-revoked [<file>]", "send a revocation of certificates to the server again",
		`Send a record that carries a revocation of certificates, and none of an
address, to the server, and keep it: the file named, or with none the one
this box keeps of its own certificates, when a server did not take it. A
record that ends an address is refused: irongall revocation publish takes
that one, with the address in full.`,
		nargs(0, 1), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			var rec *protocol.Revocations
			if len(args) == 1 {
				rec, err = readRecord(args[0])
			} else {
				rec, err = b.CertificatesRecord(c.Context())
				if err == nil && rec == nil {
					err = errors.New("this box holds no revocation of its certificates: irongall cert revoke-earlier makes one")
				}
			}
			if err != nil {
				return err
			}
			// What ends an address goes out only with that address written
			// in full, as its confirmation.
			if len(rec.Revocation) > 0 {
				return errors.New("the record carries a revocation of its address, which nothing undoes: nothing was published. irongall revocation publish --record <file> <address> publishes one, with the address in full as the confirmation")
			}
			a, _, err := b.KeepRevocation(c.Context(), rec)
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
			through, said := certs.Through, "published to the server"
			if a == b.Address() {
				// A server that held a higher one showed it, and the box keeps
				// that one.
				if held, err := b.CertificatesRecord(c.Context()); err == nil && held != nil {
					if h, err := protocol.ParseRevokedCertificates(held.RevokedCertificates); err == nil && h.Through > through {
						through, said = h.Through, "the server holds a revocation of this box's certificates through a higher serial, which covers this one: this box keeps that one"
					}
				}
			}
			if err := e.out(line("certificates_revoked", "address", a, "through", through, "message", said)); err != nil {
				return err
			}
			// A server that holds the address revoked took the record as done
			// once its revocation verified, and the box keeps that one.
			if a != b.Address() {
				return nil
			}
			st, err := b.Status(c.Context())
			if err != nil || !st.Revoked {
				return err
			}
			return e.out(line("revoked", "address", a, "message", "the server holds this address revoked, and the revocation verifies: this box signs nothing more"))
		})
}

func (e *cli) adoptCmd() *cobra.Command {
	return command("adopt", "join the account an adopt key names: the key on stdin",
		`Join the account an adopt key names, which can lift this box's limits. The key
is read from stdin, never from the command line, where ps, a shell's history
and an agent's transcript would keep it: irongall account adopt < key.txt.
What is read is held to an adopt key's form before anything is sent, so a
wrong file goes nowhere, and no error prints the key.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			key, err := adoptKey(e.stdin)
			if err != nil {
				return err
			}
			b, err := e.box()
			if err != nil {
				return err
			}
			acc, err := b.Adopt(c.Context(), key)
			if err != nil {
				return err
			}
			return e.out(line("account", "account", acc))
		})
}

// adoptKey reads an adopt key from r: one line, its line feed optional, of
// an adopt key's form (PROTOCOL.md §11.16), "iga1_" and base64url. Anything
// else is refused in words that never quote it, since it may be the key, or
// a secret piped in by mistake.
func adoptKey(r io.Reader) (string, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(maxAdoptKey+len("\r\n")+1)))
	if err != nil {
		return "", err
	}
	key := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if len(key) > maxAdoptKey || !adoptKeyForm.MatchString(key) {
		return "", errors.New("stdin does not hold an adopt key, one line of \"iga1_\" and base64url: nothing is sent, and what was read is not shown")
	}
	return key, nil
}

// adoptKeyForm is an adopt key's form, and maxAdoptKey the most bytes one
// may be (PROTOCOL.md §11.16).
var adoptKeyForm = regexp.MustCompile(`\Aiga1_[A-Za-z0-9_-]+\z`)

const maxAdoptKey = 1024

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
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			rec, err := b.Revocation(c.Context())
			if err != nil {
				return err
			}
			// The record names its own type, which it writes first, as every
			// line has its type: the line is the record.
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
server, and the command fails unless the server took it: run it again.`,
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
			// The box here, if there is one, keeps the record once the server
			// took it. With --record none is needed.
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
				if rec, err = b.Revocation(c.Context()); err != nil {
					return err
				}
			}
			var perr error
			if openErr == nil {
				_, perr = b.Revoke(c.Context(), rec)
			} else {
				_, perr = client.Revoke(c.Context(), e.opt, rec)
			}
			if perr != nil {
				return perr
			}
			// Once the server has taken it, it is out. If the box it is about is
			// the one here, it keeps it too.
			if openErr == nil && b.Address() == a {
				if _, _, err := b.KeepRevocation(c.Context(), rec); err != nil {
					return err
				}
			}
			return e.out(line("revoked", "address", a, "message", "published to the server"))
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
		nargs(1, 1), func(c *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			rec, err := readRecord(args[0])
			if err != nil {
				return err
			}
			a, held, err := b.KeepRevocation(c.Context(), rec)
			if err != nil {
				return err
			}
			return e.sayHeld(a, held)
		})
}

func (e *cli) askCmd() *cobra.Command {
	return command("ask <link, address or alias>", "ask the server what it holds about a box, and keep what verifies",
		`Ask the server what it holds about a box, and keep what verifies. send does that by itself, before it
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
	return e.out(line("not_revoked", "address", a, "message", "no revocation shown. That is the server's word, and it can keep a record back: a record from the box's owner settles it (irongall revocation keep <file>)."))
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

// notMadeLine is the line that says the box's server served a statement in
// its name that it did not make.
func notMadeLine(nm *client.NotMade) []byte {
	return line("prekey_not_made", "serial", nm.Serial, "certificate_serial", nm.CertificateSerial, "own_certificate", nm.OwnCertificate, "at", nm.At, "message", nm.Words())
}

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
		return nil, errors.New("the file is not a revocation record: one is a line of JSON with \"identity\" and \"revocation_signature\", as irongall revocation make prints, or with a revocation of its certificates")
	}
	return &rec, nil
}
