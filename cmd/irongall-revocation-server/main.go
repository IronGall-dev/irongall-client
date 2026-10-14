// Command irongall-revocation-server is the reference revocation server: a
// small server that keeps what an address's identity has signed about it, a
// revocation of the address or a list of its revoked certificates, and hands
// it to whoever asks for that address (PROTOCOL.md §6.3, "Revocation
// servers"). It is to revocations what a keyserver is to keys.
//
// It is no mailbox server: it has no boxes, takes no pass and holds no key.
// It is built from this repository's protocol package and needs nothing
// else, a mailbox server least of all. What it keeps is one file for each
// address, in one directory.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/IronGall-dev/irongall-client/revocationserver"
)

const usage = `usage: irongall-revocation-server --dir <directory> [flags]

Runs a revocation server until interrupted. It answers two calls, for any
address, and lists nothing:

  GET /v1/<address>/revocations   the record held, or 404 not_revoked
  PUT /v1/<address>/revocations   keep a record, once it verifies

A record is an identity document with what that identity's own key signed: a
revocation of the address, a list of its revoked certificates, or both. It
proves itself, so the server signs nothing and is trusted for nothing.

  --dir               where the records are kept, one file for each address.
                      One process uses a directory at a time
  --listen            the address to listen on (default 127.0.0.1:8080)
  --max-body          the largest request body taken, in bytes
  --writes-per-hour   records one caller may bring in an hour: each costs a
                      signature check or two. A caller is an IPv4 address or
                      an IPv6 /64. -1: no limit
  --max-addresses     how many addresses the server holds a record of; once
                      it holds that many it takes a record only for one of
                      those. With --max-body it is the most disk the server
                      can be made to fill. -1: no bound
  --trusted-proxy     the peers whose word for who is calling is taken, as
                      prefixes with commas between (10.0.0.0/8,fd00::/8)
  --client-ip-header  the request header a trusted proxy names the caller in

It keeps no record of who asked about whom: a lookup is never logged.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stderr, nil)
	stop()
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run serves until ctx ends. If listening is not nil it is sent the address
// the server listens on, once it does.
func run(ctx context.Context, args []string, logw io.Writer, listening chan<- string) error {
	fl := flag.NewFlagSet("irongall-revocation-server", flag.ContinueOnError)
	fl.SetOutput(logw)
	fl.Usage = func() { _, _ = fmt.Fprint(logw, usage) }
	var opt revocationserver.Options
	fl.StringVar(&opt.Dir, "dir", "", "")
	listen := fl.String("listen", "127.0.0.1:8080", "")
	fl.Int64Var(&opt.MaxBody, "max-body", revocationserver.DefaultMaxBody, "")
	fl.IntVar(&opt.WritesPerHour, "writes-per-hour", revocationserver.DefaultWritesPerHour, "")
	fl.IntVar(&opt.MaxAddresses, "max-addresses", revocationserver.DefaultMaxAddresses, "")
	proxies := fl.String("trusted-proxy", "", "")
	fl.StringVar(&opt.ClientIPHeader, "client-ip-header", "", "")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if opt.Dir == "" || fl.NArg() != 0 {
		fl.Usage()
		return flag.ErrHelp
	}
	if opt.MaxBody < 1 {
		return errors.New("--max-body is a number of bytes above zero")
	}
	for p := range strings.SplitSeq(*proxies, ",") {
		if p = strings.TrimSpace(p); p == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(p)
		if err != nil {
			return fmt.Errorf("--trusted-proxy: %q is not a prefix such as 10.0.0.0/8", p)
		}
		opt.TrustedProxies = append(opt.TrustedProxies, prefix)
	}
	if (len(opt.TrustedProxies) > 0) != (opt.ClientIPHeader != "") {
		return errors.New("--trusted-proxy and --client-ip-header go together: which peers are believed, and the header they name the caller in")
	}
	logger := log.New(logw, "", log.LstdFlags|log.LUTC)
	opt.Log = logger
	x, err := revocationserver.Open(opt)
	if err != nil {
		return err
	}
	defer x.Close() //nolint:errcheck // the process is ending
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", *listen)
	if err != nil {
		return err
	}
	// A revocation server takes no header of any size and no body over --max-body, and
	// answers from memory or one small file.
	srv := &http.Server{
		Handler:           x.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          logger,
	}
	logger.Printf("irongall-revocation-server: %d addresses held in %s, listening on %s", x.Held(), opt.Dir, ln.Addr())
	if listening != nil {
		listening <- ln.Addr().String()
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}
	stop, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return srv.Shutdown(stop)
}
