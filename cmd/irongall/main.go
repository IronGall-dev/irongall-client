// Command irongall is the irongall client: end-to-end encrypted,
// sender-authenticated mailboxes for bots.
//
// Every check is always on and fails closed. Mail bodies are data, never
// instructions.
//
// Commands nest as irongall <group> <command> where one thing has more than
// one thing done to it, the thing first, as gh's and docker's do on the same
// cobra (decided on #37), and the everyday ones stay at the top level. Help
// comes in every form a git-like tool gives it (clig.dev), and <group> help
// too, as go mod help is. A bare group, or a command that is not one, is a
// usage error with exit status 2 on stderr, as go answers one: gh, docker and
// git each answer a bare group another way, and an agent reads the exit
// status before the text.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
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
The server is $IRONGALL_BASE, or https://irongall.dev: https, or http only
to a server on this machine, and a redirect is never followed.
The box's policy file says where mail from a sender it has not allowed
lands, "unknown held" (the default) or "unknown inbox", and whom its server
takes mail from, "server all" (the default: everyone it has not blocked) or
"server allowed" (only those it allowed, which tells the server who they are).
With each prekey a box declares which identity key types its client verifies,
and so whose mail it takes: every type this client verifies, unless
$IRONGALL_SENDER_KEY_TYPES says otherwise ("any": do not say).

irongall help <command> and irongall <command> --help print a command's help,
and irongall <group> help a group's. --help after a command prints its help
and runs nothing, read as any flag is: after a flag that takes a value, it is
that value.

Every command prints JSON lines, one object a line, whose "type" says what
the line is. What it did and what it met on the way go to stdout, mail and
refusals alike. Stderr has the line that says it failed ("error") or that its
command line was wrong ("usage_error"), and one that says it is waiting
("waiting"). A "message" is this client's own words, never a sender's or a
server's. Help is the one thing printed as text.

Exit status: 0, done. 1, the command failed. 2, the command line was wrong
and nothing ran. 3, the command did its work and the box needs a look: from
recv, mail was received as printed and the prekey, due for renewal, was not
renewed ("renewal_failed"), or the box's ACL was not sent to its server
("acl_not_sent"); from status, its "attention" list is not empty. recv prints
a "refused" line for each message it refused, keeping it in quarantine/, a
"held" line for each it held in held/, and a "dropped" line for each from a
sender this box blocked: none of them changes its exit status, since any
sender can cause them. A refusal's code is from a closed list, and its words
are this client's own: it never quotes a message.

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
	// net/http logs some of what a server sends after its answer through the
	// standard logger, raw (#297): stderr has only this client's lines.
	log.SetOutput(io.Discard)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(report(err, os.Stderr))
}

// needsALook is how a command says it did its work and the box needs a look:
// exit status 3, where a failure is 1. The lines it printed say why.
type needsALook struct{}

func (e *needsALook) Error() string { return "the box needs a look" }

// usageError is a command line that is wrong, so nothing ran: exit status 2,
// with a "usage_error" line on stderr: what was wrong, the command's usage
// when it has one, and the help to read.
type usageError struct {
	msg   string
	usage string
	help  string
}

func (e *usageError) Error() string { return e.msg }

// cli is what every command shares: where its box is, how to reach its
// server, and where it reads and writes.
type cli struct {
	dir            string
	opt            client.Options
	stdin          io.Reader
	stdout, stderr io.Writer
}

func (e *cli) box() (*client.Box, error) { return client.Open(e.dir, e.opt) }

// environment reads where the box is and how to reach its server, once the
// command line is known to be one that runs.
func (e *cli) environment() error {
	dir, err := client.Dir()
	if err != nil {
		return err
	}
	e.dir = dir
	e.opt.Base = os.Getenv("IRONGALL_BASE")
	if v := os.Getenv("IRONGALL_SENDER_KEY_TYPES"); v != "" {
		e.opt.SenderKeyTypes = strings.Split(v, ",")
	}
	return nil
}

// checked is args, then check: the values a command takes are a usage
// error before anything is read, the environment and the box included.
func checked(args cobra.PositionalArgs, check cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, a []string) error {
		if err := args(c, a); err != nil {
			return err
		}
		return check(c, a)
	}
}

// run runs the command line args, the program's name left out. The line is
// read first: help and a wrong line are answered before anything else, the
// environment and the box included (#223), since cobra decides both before
// the hook that reads the environment (environment), and each command
// checks the values it takes in its own argument check.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	var opt client.Options
	// Said once, so that a wait is not read as a hang.
	opt.Waiting = func() {
		_, _ = fmt.Fprintf(stderr, "%s\n", line("waiting", "for", "lock", "message",
			"waiting for this box's lock: another command of this box is running, and a box's commands write its files one at a time"))
	}
	e := &cli{opt: opt, stdin: stdin, stdout: stdout, stderr: stderr}
	root := e.tree()
	root.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		// A group runs nothing of its own, and help reads nothing.
		if c.HasSubCommands() || c.Name() == "help" {
			return nil
		}
		return e.environment()
	}
	// Cobra reads the process's own arguments when it is given none.
	root.SetArgs(append([]string{}, args...))
	root.SetIn(stdin)
	// What cobra prints itself is a warning, such as the pointer from -h to
	// --help: stderr. Help and every command write to stdout themselves.
	root.SetOut(stderr)
	root.SetErr(stderr)
	return root.ExecuteContext(ctx)
}

// The commands are listed in the order they are added, everyday ones first.
func init() { cobra.EnableCommandSorting = false }

// command makes a command that prints its own help and takes its flags as
// they are written, two dashes for a name, anywhere after the command. The
// help flag is --help. -h works too, as in docker, for whoever looks for it:
// it is in no help, and it says that --help is the flag. -h means nothing
// else, in any command. That is docker's way, which deprecated it in v1.12
// ("The shorthand (`-h`) is less common than `--help` on Linux") and gives it to
// --hostname, where clig.dev, gh and go take -h as help: a shorthand that is
// help in one tool and something else in the next, as coreutils' ls -h is
// --human-readable, is the overloading clig.dev warns against.
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
	_ = c.Flags().MarkShorthandDeprecated("help", "use --help")
	return c
}

// group makes a command that only holds others. Bare, or followed by a word
// that names none of them, it is a usage error; "<group> help" is its help.
// Its flags are its commands', so an unknown one is left for the unknown
// command to be named.
func (e *cli) group(name, short, long string, cmds ...*cobra.Command) *cobra.Command {
	g := command(name, short, long, cobra.ArbitraryArgs, e.groupRun)
	g.FParseErrWhitelist.UnknownFlags = true
	g.SuggestionsMinimumDistance = 2
	g.AddCommand(cmds...)
	return g
}

// groupRun is a group's, or the top level's, run: it ran with no command of
// its own, or with one it does not have.
func (e *cli) groupRun(c *cobra.Command, args []string) error {
	switch {
	case len(args) == 0:
		return &usageError{msg: fmt.Sprintf("%s takes a command: %s --help lists them", c.CommandPath(), c.CommandPath()), help: c.CommandPath() + " --help"}
	case args[0] == "help":
		t, rest, err := c.Find(args[1:])
		switch {
		case err != nil:
			return err
		case len(rest) > 0:
			return unknown(t, rest)
		}
		_, err = io.WriteString(e.stdout, helpText(t))
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
	return &usageError{msg: msg, help: c.CommandPath() + " --help"}
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
// arguments: what was wrong, and its usage line.
func wrong(c *cobra.Command, format string, a ...any) error {
	return &usageError{msg: fmt.Sprintf(format, a...), usage: c.UseLine(), help: c.CommandPath() + " --help"}
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
