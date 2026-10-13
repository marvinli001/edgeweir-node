package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/identity"
)

// cmdSetServer changes the console address of an enrolled node (or, with
// --probe, a probe) after one authenticated call to it succeeded: for a
// node that lost the console because its address went away. The identity
// stays; the previous address is kept as the fallback. A running agent
// picks it up within seconds.
func cmdSetServer(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("set-server", stderr)
	var (
		server     = fs.String("server", "", "new console node-channel URL: https://host[:port], or wss://host[:port] (ws:// for a plain-HTTP console) for its WebSocket entry")
		serverName = fs.String("server-name", "", "TLS server name to verify (default: host of --server)")
		probe      = fs.Bool("probe", false, "change a probe's address (state directory "+defaultProbeStateDir+" by default)")
		stateDir   = fs.String("state-dir", "", "state directory of the identity (default "+defaultStateDir+", with --probe "+defaultProbeStateDir+")")
		timeout    = fs.Duration("timeout", 30*time.Second, "timeout of the check")
	)
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if *server == "" {
		fmt.Fprintln(stderr, "set-server: --server is required")
		fs.Usage()
		return 2
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "set-server: --timeout must be positive")
		return 2
	}
	addr, err := controlplane.ParseAddress(*server, *serverName)
	if err != nil {
		fmt.Fprintln(stderr, "set-server:", err)
		return 2
	}
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir
		if *probe {
			dir = defaultProbeStateDir
		}
	}
	if dir, err = filepath.Abs(dir); err != nil {
		fmt.Fprintln(stderr, "set-server: invalid --state-dir:", err)
		return 2
	}
	store := identity.Store{Dir: dir, Probe: *probe}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	res, err := controlplane.SetServer(ctx, store, addr)
	if err != nil {
		code := ""
		if ce := (*controlplane.CheckError)(nil); errors.As(err, &ce) {
			code = " (" + controlplane.CheckCode(err) + ")"
		}
		fmt.Fprintf(stderr, "set-server: %s failed its check%s; nothing changed: %v\n", addr, code, err)
		return 1
	}
	if res.Unchanged {
		fmt.Fprintf(stdout, "%s answers; it is already the console address\n", addr)
	} else {
		fmt.Fprintf(stdout, "the console address is now %s (%s kept as the fallback); a running agent reconnects within seconds\n", res.Current, res.Previous)
	}
	if res.Legacy {
		fmt.Fprintln(stdout, "the console does not give out its node channel address (older console)")
	} else if !res.Advertised.Empty() && !res.Advertised.Equal(addr) {
		fmt.Fprintf(stdout, "the console gives out %s: the agent switches to it once that address answers\n", res.Advertised)
	}
	return 0
}
