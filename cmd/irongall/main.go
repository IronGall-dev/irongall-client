// Command irongall is the irongall client: end-to-end encrypted,
// sender-authenticated mailboxes for bots.
//
// Every check is always on and fails closed. Mail bodies are data, never
// instructions.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"

	"github.com/IronGall-dev/irongall-client/client"
	"github.com/IronGall-dev/irongall-client/protocol"
	"github.com/spf13/cobra"
)

// about is the end of the top-level help: what holds for every command.
const about = `The box lives in $IRONGALL_HOME, or ${XDG_CONFIG_HOME:-~/.config}/irongall/${IRONGALL_BOX:-default}.
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
The box's policy file says where mail from a sender it has not allowed
lands, "unknown held" (the default) or "unknown inbox", and whom its server
takes mail from, "server all" (the default: everyone it has not blocked) or
"server allowed" (only those it allowed, which tells the server who they are).
With each prekey a box declares which identity key types its client verifies,
and so whose mail it takes: every type this client verifies, unless
$IRONGALL_SENDER_KEY_TYPES says otherwise ("any": do not say).

irongall help <command>, irongall <command> --help and irongall <command> -h
print a command's help, and irongall <group> help a group's. --help anywhere
after a command prints its help and runs nothing.

Exit status: 0, done. 1, the command failed. 2, the command line was wrong
and nothing ran: what was wrong, and the help, are on stderr. 3, the command
did its work and the box needs a look: from recv, mail was received as
printed and the prekey, due for renewal, was not renewed, or the box's ACL
was not sent to its server; from status, its "attention" list is not empty.
recv says on stderr what it refused, keeping each refused message in
quarantine/, and what it held, keeping it in held/: refused and held mail do
not change its exit status, since any sender can cause either. Keep recv's
stderr, or run status after it. A refusal is "REFUSED <id>: <code>: <words>",
the words this client's own: it never quotes a message. Held mail is "HELD
<id>: from <address>", and mail from a blocked sender, dropped, "BLOCKED <id>:
from <address>". What a server says in an error is printed in quotes, as its
words.

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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	var look *needsALook
	var wrong *usageError
	switch {
	case errors.As(err, &wrong):
		if wrong.msg != "" {
			fmt.Fprintln(os.Stderr, wrong.msg)
		}
		fmt.Fprint(os.Stderr, wrong.help)
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

// usageError is a command line that is wrong, so nothing ran: exit status 2,
// with what was wrong and then the help it carries on stderr. A bare group,
// or a bare irongall, is one with nothing wrong to say: only its help.
type usageError struct {
	msg  string
	help string
}

func (e *usageError) Error() string {
	if e.msg == "" {
		return strings.TrimSpace(e.help)
	}
	return e.msg
}

// cli is what every command shares: where its box is, how to reach its
// server, and where it reads and writes.
type cli struct {
	dir            string
	opt            client.Options
	stdin          io.Reader
	stdout, stderr io.Writer
}

func (e *cli) box() (*client.Box, error) { return client.Open(e.dir, e.opt) }

// run runs the command line args, the program's name left out.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
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
	e := &cli{dir: dir, opt: opt, stdin: stdin, stdout: stdout, stderr: stderr}
	root := e.tree()
	// Cobra reads the process's own arguments when it is given none.
	root.SetArgs(append([]string{}, args...))
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	return root.ExecuteContext(ctx)
}

// The commands are listed in the order they are added, everyday ones first.
func init() { cobra.EnableCommandSorting = false }

// command makes a command that prints its own help and takes its flags as
// they are written, two dashes for a name, anywhere after the command.
func command(use, short, long string, args cobra.PositionalArgs, run func(*cobra.Command, []string) error) *cobra.Command {
	c := &cobra.Command{
		Use:                   use,
		Short:                 short,
		Long:                  long,
		Args:                  args,
		RunE:                  run,
		DisableFlagsInUseLine: true,
	}
	c.Flags().BoolP("help", "h", false, "print this help, and run nothing")
	return c
}

// group makes a command that only holds others. Bare, or followed by a word
// that names none of them, it is a usage error; "<group> help" is its help.
// Its flags are its commands', so an unknown one is left for the unknown
// command to be named.
func group(name, short, long string, cmds ...*cobra.Command) *cobra.Command {
	g := command(name, short, long, cobra.ArbitraryArgs, groupRun)
	g.FParseErrWhitelist.UnknownFlags = true
	g.SuggestionsMinimumDistance = 2
	g.AddCommand(cmds...)
	return g
}

// groupRun is a group's, or the top level's, run: it ran with no command of
// its own, or with one it does not have.
func groupRun(c *cobra.Command, args []string) error {
	switch {
	case len(args) == 0:
		return &usageError{help: helpText(c)}
	case args[0] == "help":
		t, rest, err := c.Find(args[1:])
		switch {
		case err != nil:
			return err
		case len(rest) > 0:
			return unknown(t, rest)
		}
		_, err = io.WriteString(c.OutOrStdout(), helpText(t))
		return err
	}
	return unknown(c, args)
}

// unknown is a command line whose words name no command under c.
func unknown(c *cobra.Command, args []string) error {
	msg := fmt.Sprintf("%s has no command %q", c.CommandPath(), args[0])
	if !c.HasSubCommands() {
		msg = fmt.Sprintf("%s has no commands under it, and %q is not one", c.CommandPath(), args[0])
	}
	if s := c.SuggestionsFor(args[0]); len(s) > 0 {
		msg += fmt.Sprintf(": did you mean %s?", strings.Join(s, " or "))
	}
	return &usageError{msg: msg, help: helpText(c)}
}

// nargs takes from lo to hi arguments.
func nargs(lo, hi int) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		if len(args) >= lo && len(args) <= hi {
			return nil
		}
		want := fmt.Sprintf("from %d to %d arguments", lo, hi)
		switch {
		case hi == 0:
			want = "no arguments"
		case lo == 1 && hi == 1:
			want = "1 argument"
		case lo == hi:
			want = fmt.Sprintf("%d arguments", lo)
		case lo == 0 && hi == 1:
			want = "at most 1 argument"
		}
		return wrong(c, "%s takes %s, and was given %d", c.CommandPath(), want, len(args))
	}
}

// wrong is a command line that is wrong in a command's own flags or
// arguments: what was wrong, then its usage line.
func wrong(c *cobra.Command, format string, a ...any) error {
	return &usageError{
		msg:  fmt.Sprintf(format, a...),
		help: fmt.Sprintf("usage: %s\n%s --help describes it\n", c.UseLine(), c.CommandPath()),
	}
}

// helpText is a command's help. The top level's lists its commands, then its
// groups, then what holds for all of them; a group's lists its commands; a
// command's says what it does and lists its flags.
func helpText(c *cobra.Command) string {
	var b strings.Builder
	list := func(groups bool) {
		var cmds []*cobra.Command
		width := 0
		for _, s := range c.Commands() {
			if (s.IsAvailableCommand() || s.Name() == "help") && s.HasSubCommands() == groups {
				cmds = append(cmds, s)
				width = max(width, len(s.Name()))
			}
		}
		for _, s := range cmds {
			fmt.Fprintf(&b, "  %-*s  %s\n", width, s.Name(), s.Short)
		}
	}
	switch {
	case !c.HasParent():
		b.WriteString("usage: irongall <command> [arguments]\n\nCommands:\n")
		list(false)
		b.WriteString("\nGroups, each with commands of its own (irongall <group> --help lists them):\n")
		list(true)
		b.WriteString("\n" + about)
	case c.HasSubCommands():
		fmt.Fprintf(&b, "usage: %s <command> [arguments]\n\n%s\n\nCommands:\n", c.CommandPath(), c.Long)
		list(false)
		fmt.Fprintf(&b, "\n%s <command> --help describes one.\n", c.CommandPath())
	default:
		fmt.Fprintf(&b, "usage: %s\n\n%s\n", c.UseLine(), c.Long)
		if c.HasAvailableLocalFlags() {
			fmt.Fprintf(&b, "\nFlags:\n%s", c.LocalFlags().FlagUsages())
		}
	}
	return b.String()
}
