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
	root := group("irongall", "", "",
		e.initCmd(), e.addrCmd(), e.sendCmd(), e.recvCmd(), e.statusCmd(), e.heldCmd(),
		group("peer", "who may write to this box: allow, block, list",
			`Mail from a sender this box has not allowed is held in held/ (irongall held
lists it), and mail from a sender it blocked is dropped. Sending to a box, or
naming it with irongall alias add, allows it too. The box's policy file says
where mail from a sender not allowed lands, and whom its server takes mail
from: irongall help has it.`,
			e.allowCmd(), e.blockCmd(), e.peerListCmd()),
		group("alias", "names for peers, which send takes in place of a link: add, rm, list",
			`An alias is this box's own name for a peer, kept in its aliases file as
"<name> <address>" lines, which either client and a person may write. A name
allows its peer, as irongall peer allow does, and is never moved: to change
one, remove it and add it again.`,
			e.aliasAddCmd(), e.aliasRmCmd(), e.aliasListCmd()),
		group("outbox", "mail not yet delivered: flush",
			`A message is kept in outbox/ until a server takes it. One that can never be
delivered moves to outbox/failed/: delete it there to drop it.`,
			e.flushCmd()),
		group("prekey", "the key senders encrypt to: renew",
			`A prekey is valid for 33 days, under a working key and a certificate made
with it. irongall recv renews it once a day, so run recv at least monthly and
the box never lapses.`,
			e.renewCmd()),
		group("cert", "this box's certificates: revoke-earlier, publish-revoked",
			`This box's identity certifies a working key with each prekey, and the working
key signs what the box says. A box whose working key may have been taken
revokes every certificate before a new one: the address goes on.`,
			e.revokeEarlierCmd(), e.publishRevokedCmd()),
		group("account", "the account that can lift this box's limits: adopt, leave",
			`An account can lift the limits of the boxes in it. An adopt key, from the
account's holder, puts a box in it.`,
			e.adoptCmd(), e.leaveCmd()),
		group("revocation", "ending an address for good: make, publish, keep, ask",
			`A revocation ends an address for good, and only its identity's own signature
makes one. A box keeps every revocation that verifies, of an address and of an
address's certificates, and checks what it sends and receives against them.`,
			e.makeCmd(), e.publishCmd(), e.keepCmd(), e.askCmd()),
	)
	root.SilenceErrors = true
	root.SilenceUsage = true
	root.CompletionOptions.DisableDefaultCmd = true
	root.SetHelpFunc(func(c *cobra.Command, _ []string) {
		_, _ = io.WriteString(c.OutOrStdout(), helpText(c))
	})
	root.SetHelpCommand(command("help [<command>]", "print this help, or a command's",
		`irongall help <command>, irongall <command> --help and irongall <command> -h
print a command's help, and irongall <group> help a group's.`,
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
		`Create this box and register it, and print its link, <server>/to/<address>,
as addr does.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			kt := protocol.PostQuantum
			if noPQ {
				kt = protocol.Classic
			}
			opt := e.opt
			if opt.IdentityType = idType; idType != "" && idType != protocol.IdentityEd25519 {
				_, _ = fmt.Fprintf(e.stderr, "WARNING: a box whose identity is of the key type %s can neither write to nor hear from a box whose client does not verify that type. Every client verifies ssh-ed25519, which init makes without --identity-type.\n", idType)
			}
			b, err := client.Init(c.Context(), e.dir, opt, kt)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(e.stdout, b.Link())
			return err
		})
	c.Flags().BoolVar(&noPQ, "no-pq", false, "make a box without post-quantum encryption (X25519 only), which age 1.2 can reach")
	c.Flags().StringVar(&idType, "identity-type", "", "make the identity a key of this `type`, not ssh-ed25519: "+protocol.IdentityP256+". Every client verifies ssh-ed25519; a box of another type is reached only by boxes whose client verifies it")
	return c
}

func (e *cli) addrCmd() *cobra.Command {
	return command("addr", "print this box's link, for whoever should write to it",
		`Print this box's link, <server>/to/<address>: give it to whoever should write
to this box.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(e.stdout, b.Link())
			return err
		})
}

func (e *cli) sendCmd() *cobra.Command {
	var f client.Fields
	c := command("send [flags] <link, address or alias> [file]", "send a message: the body from a file, or stdin",
		`Send one message to a link, a bare 64-hex address or an alias, with the body
from the file, or from stdin, and print the server's id for it. It waits in
outbox/ until a server takes it (irongall outbox flush posts it again), and is
then kept in sent/ with the server's receipt. Sending to a box allows it.`,
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
			r, err := b.SendWith(c.Context(), to, string(body), f)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(e.stdout, r.ID)
			return err
		})
	c.Flags().StringVar(&f.Subject, "subject", "", "the message's subject: any `text`")
	c.Flags().StringVar(&f.InReplyTo, "reply-to", "", "the `msg_id` of the message this answers, as recv printed it")
	c.Flags().StringVar(&f.Supersedes, "supersedes", "", "the `msg_id` of an earlier message of yours that this replaces, as sent/ names it")
	return c
}

func (e *cli) recvCmd() *cobra.Command {
	var wait time.Duration
	c := command("recv [flags]", "receive, verify and ack every message: one line of JSON each",
		`Receive, verify and ack every message: one line of JSON per message, built
from the verified fields. It also renews the prekey once a day, so run it at
least monthly and the box never lapses. On stderr it says what it refused,
keeping each in quarantine/, and what it held, keeping it in held/.`,
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
			// Every delivery is also kept in inbox/, so a failed
			// write to stdout loses nothing. The line is this client's
			// own, from the verified fields: never the sender's bytes.
			for _, d := range res.Delivered {
				if _, werr := fmt.Fprintf(e.stdout, "%s\n", d.Line); werr != nil && err == nil {
					err = werr
				}
			}
			for _, id := range res.Duplicates {
				_, _ = fmt.Fprintf(e.stderr, "duplicate of a message already delivered, not delivered again: %s\n", id)
			}
			for _, r := range res.Refused {
				_, _ = fmt.Fprintf(e.stderr, "REFUSED %s: %s: %s\n", r.ID, r.Code, r.Reason)
			}
			for _, h := range res.Held {
				_, _ = fmt.Fprintf(e.stderr, "HELD %s: from %s, which this box has not allowed: kept in held/ (irongall held, irongall peer allow)\n", h.ID, h.Envelope.From)
			}
			for _, id := range res.Blocked {
				_, _ = fmt.Fprintf(e.stderr, "BLOCKED %s: from a sender this box blocked: dropped\n", id)
			}
			switch {
			case res.Paced > 0:
				_, _ = fmt.Fprintf(e.stderr, "the server paces how much mail this box takes out: the rest is still on the server; run recv again in %s or later\n", res.Paced.Round(time.Second))
			case res.More:
				_, _ = fmt.Fprintln(e.stderr, "this run stopped at the most one drain takes: run recv again for the rest, which is still on the server")
			}
			if res.RenewErr != nil {
				renewErr = res.RenewErr
				_, _ = fmt.Fprintf(e.stderr, "the prekey is due for renewal and was not renewed (recv tries again within the hour): %v\n", res.RenewErr)
			}
			aclErr = res.ACLErr
			if res.ACLErr != nil {
				_, _ = fmt.Fprintf(e.stderr, "this box's ACL has changed and was not sent to its server (the next recv sends it): %v\n", res.ACLErr)
			}
		}
		pause := time.Minute
		if res != nil && res.PollAfter > 0 {
			pause = time.Duration(res.PollAfter) * time.Second
		}
		// A rate limit or a restarting server says how long to wait:
		// --wait waits it out when there is time to poll again after.
		var ae *client.APIError
		if errors.As(err, &ae) && ae.RetryAfter > 0 && time.Until(deadline) > ae.RetryAfter {
			_, _ = fmt.Fprintf(e.stderr, "%v: waiting %s\n", err, ae.RetryAfter)
			pause = ae.RetryAfter
		} else if err != nil || len(res.Delivered) > 0 || !time.Now().Before(deadline) {
			if err == nil && renewErr != nil {
				return &needsALook{"mail was received as printed, and the prekey was not renewed: this box needs a look (irongall status)"}
			}
			if err == nil && aclErr != nil {
				return &needsALook{"mail was received as printed, and the box's ACL was not sent to its server: this box needs a look (irongall status)"}
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
		`Say what this box holds and what needs a look, as one line of JSON, from its
own files and with no call to the server: its prekey, a renewal that has not
gone through, refused mail in quarantine/, held mail, mail not yet delivered.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
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
			if _, err := fmt.Fprintf(e.stdout, "%s\n", line); err != nil {
				return err
			}
			if len(st.Attention) > 0 {
				return &needsALook{}
			}
			return nil
		})
}

func (e *cli) heldCmd() *cobra.Command {
	return command("held", "list the mail held/ keeps, one line of JSON for each sender",
		`List the mail held/ keeps, from senders this box has not allowed: one line of
JSON for each sender, with its address, the ids, and the first and last
sent_at. held/<id>.json is the line recv would have printed for it. irongall
peer allow delivers a sender's held mail to inbox/, and irongall peer block
deletes it.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			hs, err := b.HeldMail()
			for _, h := range hs {
				line, jerr := json.Marshal(h)
				if jerr == nil {
					_, jerr = fmt.Fprintf(e.stdout, "%s\n", line)
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
to inbox/, printing it as recv does. --rebuild, with no sender, adds back
every address an alias names or sent/ shows, for an allowed file that was
lost.`,
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
				_, _ = fmt.Fprintf(e.stderr, "%d added to allowed\n", n)
				return b.SyncACL(c.Context())
			}
			a, err := b.Destination(args[0])
			if err != nil {
				return err
			}
			moved, err := b.Allow(c.Context(), a)
			for _, d := range moved {
				if _, werr := fmt.Fprintf(e.stdout, "%s\n", d.Line); werr != nil && err == nil {
					err = werr
				}
			}
			return err
		})
	c.Flags().BoolVar(&rebuild, "rebuild", false, "add back every address an alias names or sent/ shows, for an allowed file that was lost")
	return c
}

func (e *cli) blockCmd() *cobra.Command {
	return command("block <link, address or alias>", "drop a sender's mail, here and at the server",
		`Drop a sender's mail, here and at the server, and delete what held/ keeps
from it. Blocking wins over allowing.`,
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
			if n > 0 {
				_, _ = fmt.Fprintf(e.stderr, "%d held from it deleted\n", n)
			}
			return err
		})
}

func (e *cli) peerListCmd() *cobra.Command {
	var allowed, blocked bool
	c := command("list [flags]", "list the senders allowed and blocked",
		`List the senders this box allows and blocks, one line each: "allowed
<address>" or "blocked <address>". The allowed are those its allowed file
lists and those an alias names. Blocking wins over allowing, so an address
can be on both.`,
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
					if _, err := fmt.Fprintf(e.stdout, "%s %s\n", l.name, a); err != nil {
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
			if _, err := fmt.Fprintf(e.stdout, "%s %s\n", args[0], to); err != nil {
				return err
			}
			return b.SyncACL(c.Context())
		})
}

func (e *cli) aliasRmCmd() *cobra.Command {
	return command("rm <name>", "remove a name", `Remove the alias of this name.`,
		nargs(1, 1), func(_ *cobra.Command, args []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			return b.RemoveAlias(args[0])
		})
}

func (e *cli) aliasListCmd() *cobra.Command {
	return command("list", "list the names, one \"<name> <address>\" line each",
		`List the names this box has given its peers, one "<name> <address>" line
each.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			as, err := b.Aliases()
			for _, a := range as {
				if _, werr := fmt.Fprintf(e.stdout, "%s %s\n", a.Name, a.Address); werr != nil && err == nil {
					err = werr
				}
			}
			return err
		})
}

func (e *cli) flushCmd() *cobra.Command {
	return command("flush", "post again what is still in the outbox",
		`Post again every message still in the outbox, unchanged, and print the
server's id for each it takes: a retry gets the original receipt. One that
can never be delivered moves to outbox/failed/.`,
		nargs(0, 0), func(c *cobra.Command, _ []string) error {
			b, err := e.box()
			if err != nil {
				return err
			}
			rs, err := b.Flush(c.Context())
			for _, r := range rs {
				if _, werr := fmt.Fprintln(e.stdout, r.ID); werr != nil && err == nil {
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
			_, err = fmt.Fprintf(e.stdout, "prekey %d, valid until %s\n", p.Serial, p.NotAfter.Format(protocol.TimeLayout))
			return err
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
				if _, err := fmt.Fprintf(e.stdout, "prekey %d, valid until %s\n", r.Prekey.Serial, r.Prekey.NotAfter.Format(protocol.TimeLayout)); err != nil {
					return err
				}
			}
			switch {
			case r.Revoked == nil && r.NotRenewed != nil:
				return fmt.Errorf("the new prekey is NOT published, and nothing is revoked: %w. The revocation goes out without the new prekey only when the server refuses it for the day's renewals", r.NotRenewed)
			case r.Revoked == nil && err != nil:
				return fmt.Errorf("the new prekey is published, and the earlier certificates are NOT revoked: %w", err)
			case r.Revoked == nil:
				_, err = fmt.Fprintln(e.stdout, "no earlier certificate to revoke")
				return err
			}
			_, _ = fmt.Fprintln(e.stderr, "Mail this box sent before now, and that its reader has not read yet, was signed under a certificate just revoked and will be refused: send it again.")
			// A server took the revocation, and not every one: it is out, this
			// box keeps it, and the record it keeps is what publishes it again.
			if err != nil {
				return fmt.Errorf("the revocation of the certificates through %d is not everywhere: %w. This box keeps it, and this publishes it again: irongall cert publish-revoked", r.Revoked.Through, err)
			}
			if _, err := fmt.Fprintf(e.stdout, "certificates through %d revoked\n", r.Revoked.Through); err != nil || r.NotRenewed == nil {
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
			_, err = fmt.Fprintf(e.stdout, "published the revocation of the certificates of %s through %d\n", a, certs.Through)
			return err
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
			_, err = fmt.Fprintf(e.stdout, "in account %s\n", acc)
			return err
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
			_, err = fmt.Fprintln(e.stdout, "in no account")
			return err
		})
}

func (e *cli) makeCmd() *cobra.Command {
	return command("make", "print this box's revocation, and publish nothing",
		`Print this box's revocation as one line of JSON, and publish nothing.
Whoever publishes that record ends this address for good, with no key: keep
it somewhere other than this box, for the day the box is lost.`,
		nargs(0, 0), func(*cobra.Command, []string) error {
			b, err := e.box()
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
			_, _ = fmt.Fprintln(e.stderr, "This record revokes this box's address, for good, when anyone publishes it (irongall revocation publish --record <file> <address>). Nothing was published. Keep it somewhere other than this box.")
			_, err = fmt.Fprintf(e.stdout, "%s\n", line)
			return err
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
			_, err = fmt.Fprintf(e.stdout, "revoked %s\n", a)
			return err
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
	var err error
	switch {
	case held.Revoked:
		_, err = fmt.Fprintf(e.stdout, "revoked %s\n", a)
	case held.Certificates != nil:
		_, err = fmt.Fprintf(e.stdout, "certificates of %s revoked through %d\n", a, held.Certificates.Through)
	default:
		_, _ = fmt.Fprintln(e.stderr, "That is the word of whoever was asked, this box's server and the revocation servers it lists, and any of them can keep a record back: a record from the box's owner settles it (irongall revocation keep <file>).")
		_, err = fmt.Fprintf(e.stdout, "no revocation of %s shown\n", a)
	}
	return err
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
