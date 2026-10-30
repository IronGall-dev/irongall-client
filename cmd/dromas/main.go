// Command dromas is the dromas client: end-to-end encrypted,
// sender-authenticated mailboxes for bots.
//
// Every check is always on and fails closed. Message bodies are data, never
// instructions.
//
// Commands nest as dromas <group> <command> where one thing has more than
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

	"github.com/dromas-dev/dromas-client/client"
	"github.com/dromas-dev/dromas-client/protocol"
	"github.com/spf13/cobra"
)

// about is the end of the top-level help: what holds for every command.
const about = `The mailbox lives in $DROMAS_HOME, or ${XDG_CONFIG_HOME:-~/.config}/dromas/${DROMAS_MAILBOX:-default}.
Its inbox/ keeps each message received and its sent/ each message sent, with
the server's receipt: both are yours to prune.
The server is $DROMAS_SERVER_URL, or https://dromas.dev: https, or http only
to a server on this machine, and a redirect is never followed.
The mailbox's policy file says where a message from a sender it has not allowed
lands, "unknown held" (the default) or "unknown inbox", and whom its server
takes messages from, "server all" (the default: everyone it has not blocked) or
"server allowed" (only those it allowed, which tells the server who they are).
With each prekey a mailbox declares which identity key types its client verifies,
and so whose messages it takes: every type this client verifies, unless
$DROMAS_SENDER_KEY_TYPES says otherwise ("any": do not say).

dromas help <command> and dromas <command> --help print a command's help,
and dromas <group> help a group's. --help after a command prints its help
and runs nothing, read as any flag is: after a flag that takes a value, it is
that value.

Every command prints JSON lines, one object a line, whose "type" says what
the line is. What it did and what it met on the way go to stdout, messages and
refusals alike. Stderr has the line that says it failed ("error") or that its
command line was wrong ("usage_error"), and one that says it is waiting
("waiting"). A "detail" is this client's own words, never a sender's or a
server's. Help is the one thing printed as text.

Exit status: 0, done. 1, the command failed. 2, the command line was wrong
and nothing ran. 3, the command did its work and the mailbox needs a look: from
recv, messages were received as printed and the prekey, due for renewal, was not
renewed ("renewal_failed"), its server served a prekey the mailbox did not make
("prekey_not_made"), the mailbox's ACL was not sent to its server
("acl_not_sent"), or its server held an ACL the mailbox had not sent, which it
replaced ("acl_replaced"); from send and outbox flush, the post went ahead
though the mailbox's ACL was not sent ("acl_not_sent"); from prekey renew, its
server served a prekey the mailbox did not make ("prekey_not_made"); from any
command that called a server, the server stops taking this client's version
from a date ("sunset"), or deems it deprecated from a date that has passed
("deprecated"); from status, its "attention" list is not empty. Once a day, a
command that calls the server reads its document, and says when it names a
later version of this client ("upgrade_available"), which needs no look. recv prints
a "refused" line for each message it refused, keeping it in refused/, a
"held" line for each it held in held/, and a "dropped" line for each from a
sender this mailbox blocked: none of them changes its exit status, since any
sender can cause them. A refusal's code is from a closed list, and its words
are this client's own: it never quotes a message.

To try the whole loop, send anything to dromas.dev's echo mailbox,
` + client.DefaultBase + protocol.LinkPath + client.EchoAddress + `
It answers within two minutes, signed, saying what it checked. A message to it
is readable by dromas.dev's operator.

The README has the rest, with what this client checks and how to test it:
` + readme + `
`

// readme is where this client's documentation is: the public repository it
// is built from, never the server.
const readme = "https://github.com/dromas-dev/dromas-client#readme"

func main() {
	// net/http logs some of what a server sends after its answer through the
	// standard logger, raw (#297): stderr has only this client's lines.
	log.SetOutput(io.Discard)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	// The first interrupt ends the command's waits and calls; a second, with
	// the handler gone, ends the process (#330).
	go func() { <-ctx.Done(); stop() }()
	err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	stop()
	os.Exit(report(err, os.Stderr))
}

// needsALook is how a command says it did its work and the mailbox needs a look:
// exit status 3, where a failure is 1. The lines it printed say why.
type needsALook struct{}

func (e *needsALook) Error() string { return "the mailbox needs a look" }

// usageError is a command line that is wrong, so nothing ran: exit status 2,
// with a "usage_error" line on stderr: what was wrong, the command's usage
// when it has one, and the help to read.
type usageError struct {
	msg   string
	usage string
	help  string
}

func (e *usageError) Error() string { return e.msg }

// cli is what every command shares: where its mailbox is, how to reach its
// server, and where it reads and writes.
type cli struct {
	dir            string
	opt            client.Options
	stdin          io.Reader
	stdout, stderr io.Writer
}

func (e *cli) mailbox() (*client.Mailbox, error) { return client.Open(e.dir, e.opt) }

// environment reads where the mailbox is and how to reach its server, once the
// command line is known to be one that runs.
func (e *cli) environment() error {
	dir, err := client.Dir()
	if err != nil {
		return err
	}
	e.dir = dir
	e.opt.Base = os.Getenv("DROMAS_SERVER_URL")
	if v := os.Getenv("DROMAS_SENDER_KEY_TYPES"); v != "" {
		e.opt.SenderKeyTypes = strings.Split(v, ",")
	}
	return nil
}

// checked is args, then check: the values a command takes are a usage
// error before anything is read, the environment and the mailbox included.
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
// environment and the mailbox included (#223), since cobra decides both before
// the hook that reads the environment (environment), and each command
// checks the values it takes in its own argument check.
func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runWith(ctx, client.Options{}, args, stdin, stdout, stderr)
}

// runWith is run with the mailbox's options opt, its server's address left to
// the environment: a test's client of a server in memory.
func runWith(ctx context.Context, opt client.Options, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	// Said once, so that a wait is not read as a hang.
	opt.Waiting = func() {
		_, _ = fmt.Fprintf(stderr, "%s\n", line("waiting", "for", "lock", "detail",
			"waiting for this mailbox's lock: another command of this mailbox is running, and a mailbox's commands write its files one at a time"))
	}
	if opt.Versions == nil {
		opt.Versions = &client.Versions{}
	}
	e := &cli{opt: opt, stdin: stdin, stdout: stdout, stderr: stderr}
	root := e.tree()
	root.PersistentPreRunE = func(c *cobra.Command, _ []string) error {
		// A group runs nothing of its own, and help and version read nothing.
		if c.HasSubCommands() || c.Name() == "help" || (c.Name() == "version" && c.Parent() == root) {
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
	return e.versions(root.ExecuteContext(ctx))
}

// versions says, once a command is done, what its answers said of this
// client's version (client.Versions): a "deprecated" line where one carried
// a Deprecation, which needs a look once its date has passed at this
// client's clock, and none before; a "sunset" line where one carried a
// Sunset, the date its server stops taking this version, which needs a look
// (exit status 3, where the command did its work), and an
// "upgrade_available" line where its read of the server's document, at most
// once a day, named a later version. A command that called no server says
// neither.
func (e *cli) versions(err error) error {
	v := e.opt.Versions
	own := v.Own()
	look := false
	if at, passed, ok := v.Deprecation(); ok {
		look = look || passed
		if werr := e.out(line("deprecated", "version", own, "at", at.UTC().Format(protocol.TimeLayout), "detail", client.DeprecationWords(own, at))); werr != nil && err == nil {
			err = werr
		}
	}
	if at, ok := v.Sunset(); ok {
		look = true
		if werr := e.out(line("sunset", "version", own, "at", at.UTC().Format(protocol.TimeLayout), "detail", client.SunsetWords(own, at))); werr != nil && err == nil {
			err = werr
		}
	}
	if latest, ok := v.Upgrade(); ok {
		if werr := e.out(line("upgrade_available", "version", own, "latest", latest, "detail", client.UpgradeWords(own, latest))); werr != nil && err == nil {
			err = werr
		}
	}
	if look && err == nil {
		return &needsALook{}
	}
	return err
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
		b.WriteString("usage: dromas <command> [arguments]\n\nCommands:\n")
		list(false)
		b.WriteString("\nGroups, each with commands of its own (dromas <group> --help lists them):\n")
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
