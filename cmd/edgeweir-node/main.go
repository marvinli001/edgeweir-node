// Command edgeweir-node is the Edgeweir edge node agent.
//
//	EDGEWEIR_TOKEN=T edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name N] [--state-dir DIR] [--force]
//	edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...  (--token T also works but shows in ps)
//	edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
//	                  [--lua-dir DIR] [--control-socket PATH] ...
//	edgeweir-node healthcheck [--control-socket PATH]
//	edgeweir-node version
//
// Every flag can also be set with an environment variable
// (EDGEWEIR_<FLAG_NAME>, e.g. EDGEWEIR_STATE_DIR); flags win.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/edgeweir/edgeweir-node/internal/agent"
	"github.com/edgeweir/edgeweir-node/internal/dataplane"
	"github.com/edgeweir/edgeweir-node/internal/engine"
	"github.com/edgeweir/edgeweir-node/internal/enroll"
	"github.com/edgeweir/edgeweir-node/internal/hostinfo"
	"github.com/edgeweir/edgeweir-node/internal/render"
	"github.com/edgeweir/edgeweir-node/internal/version"
)

const (
	defaultStateDir      = "/var/lib/edgeweir-node"
	defaultLuaDir        = "/usr/share/edgeweir-node/lua"
	defaultCacheDir      = "/var/cache/edgeweir-node"
	defaultControlSocket = "/run/edgeweir-node/control.sock"
	defaultOriginSocket  = "/run/edgeweir-node/origin.sock"
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "enroll":
		return cmdEnroll(args[1:], stderr)
	case "run":
		return cmdRun(args[1:], stderr)
	case "healthcheck":
		return cmdHealthcheck(args[1:], stderr)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version.String())
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `edgeweir-node - Edgeweir edge node agent

Usage:
  EDGEWEIR_TOKEN=TOKEN edgeweir-node enroll --server URL --ca-sha256 HEX [flags]
  edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX [flags]
  edgeweir-node run [--manage-nginx] [flags]
  edgeweir-node healthcheck [--control-socket PATH]
  edgeweir-node version

Run "edgeweir-node <command> -h" for the flags of a command. Every flag can
also be set through an environment variable EDGEWEIR_<NAME> (for example
--state-dir -> EDGEWEIR_STATE_DIR); command-line flags take precedence.
`)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envName maps a flag name to its environment variable.
func envName(flagName string) string {
	return "EDGEWEIR_" + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// applyEnv sets every flag that was not given on the command line from its
// environment variable.
func applyEnv(fs *flag.FlagSet) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	var errs []error
	fs.VisitAll(func(f *flag.Flag) {
		if set[f.Name] {
			return
		}
		if v, ok := os.LookupEnv(envName(f.Name)); ok {
			if err := f.Value.Set(v); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", envName(f.Name), err))
			}
		}
	})
	return errors.Join(errs...)
}

func newFlagSet(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

type logFlags struct {
	level  string
	format string
}

func (l *logFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&l.level, "log-level", "info", "log level: debug, info, warn, error")
	fs.StringVar(&l.format, "log-format", "text", "log format: text or json")
}

func (l *logFlags) logger(w io.Writer) (*slog.Logger, error) {
	var level slog.Level
	if err := level.UnmarshalText([]byte(l.level)); err != nil {
		return nil, fmt.Errorf("invalid --log-level %q", l.level)
	}
	opts := &slog.HandlerOptions{Level: level}
	switch l.format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	default:
		return nil, fmt.Errorf("invalid --log-format %q (want text or json)", l.format)
	}
}

func parse(fs *flag.FlagSet, args []string) (ok bool, code int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, 0
		}
		return false, 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(fs.Output(), "unexpected arguments: %v\n", fs.Args())
		return false, 2
	}
	if err := applyEnv(fs); err != nil {
		fmt.Fprintln(fs.Output(), err)
		return false, 2
	}
	return true, 0
}

func cmdEnroll(args []string, stderr io.Writer) int {
	fs := newFlagSet("enroll", stderr)
	var (
		server     = fs.String("server", "", "console node-channel URL, e.g. https://console.example.com:8443 (required)")
		token      = fs.String("token", "", "single-use enrollment token; visible in the process list, prefer the EDGEWEIR_TOKEN environment variable or --token-file")
		tokenFile  = fs.String("token-file", "", "read the single-use enrollment token from this file (surrounding whitespace is ignored)")
		caSHA256   = fs.String("ca-sha256", "", "SHA-256 of the console's internal CA certificate (DER, hex) from the install command (required)")
		serverName = fs.String("server-name", "", "TLS server name to verify (default: host of --server)")
		stateDir   = fs.String("state-dir", defaultStateDir, "state directory for the node identity")
		force      = fs.Bool("force", false, "replace an existing identity (re-enroll)")
		timeout    = fs.Duration("timeout", 30*time.Second, "enrollment RPC timeout")
		lf         logFlags
	)
	lf.register(fs)
	if ok, code := parse(fs, args); !ok {
		return code
	}
	log, err := lf.logger(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	cli := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { cli[f.Name] = true })
	tok, err := enrollToken(*token, *tokenFile, cli["token"], cli["token-file"])
	if err != nil {
		fmt.Fprintln(stderr, "enroll:", err)
		return 2
	}
	// The token must not leak into child processes (openresty -v below).
	_ = os.Unsetenv(envName("token"))
	if cli["token"] {
		log.Warn("--token is visible to other users in the process list; prefer EDGEWEIR_TOKEN or --token-file")
	}
	if *server == "" || tok == "" || *caSHA256 == "" {
		fmt.Fprintln(stderr, "enroll: --server, a token (EDGEWEIR_TOKEN, --token-file or --token) and --ca-sha256 are required")
		fs.Usage()
		return 2
	}
	dir, err := filepath.Abs(*stateDir)
	if err != nil {
		log.Error("invalid --state-dir", "err", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Best effort: report the OpenResty version with the enrollment.
	engineVersion := ""
	vctx, vcancel := context.WithTimeout(ctx, 3*time.Second)
	if v, err := engine.New(engine.Config{Bin: envOr("EDGEWEIR_NGINX_BIN", "openresty")}).Version(vctx); err == nil {
		engineVersion = v
	}
	vcancel()
	if _, err := enroll.Run(ctx, enroll.Options{
		Info:       hostinfo.Collect(engineVersion),
		ServerURL:  *server,
		Token:      tok,
		CASHA256:   *caSHA256,
		ServerName: *serverName,
		StateDir:   dir,
		Force:      *force,
		Timeout:    *timeout,
		Logger:     log,
	}); err != nil {
		log.Error("enrollment failed", "err", err)
		return 1
	}
	return 0
}

// enrollToken picks the enrollment token: from --token or --token-file,
// whichever is set; a command-line flag wins over the environment
// (EDGEWEIR_TOKEN / EDGEWEIR_TOKEN_FILE), and giving both on the same
// level is an error.
func enrollToken(token, tokenFile string, tokenOnCLI, fileOnCLI bool) (string, error) {
	switch {
	case token != "" && tokenFile != "" && tokenOnCLI == fileOnCLI:
		return "", errors.New("give the token either directly (--token / EDGEWEIR_TOKEN) or as a file (--token-file / EDGEWEIR_TOKEN_FILE), not both")
	case tokenFile != "" && (!tokenOnCLI || fileOnCLI):
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return "", fmt.Errorf("read token file: %w", err)
		}
		t := strings.TrimSpace(string(b))
		if t == "" {
			return "", fmt.Errorf("token file %s is empty", tokenFile)
		}
		return t, nil
	default:
		return strings.TrimSpace(token), nil
	}
}

// tristate is an "auto" | "on" | "off" flag.
type tristate string

func (t *tristate) String() string { return string(*t) }
func (t *tristate) Set(v string) error {
	switch strings.ToLower(v) {
	case "auto", "":
		*t = "auto"
	case "on", "true", "1", "yes":
		*t = "on"
	case "off", "false", "0", "no":
		*t = "off"
	default:
		return fmt.Errorf("want auto, on or off")
	}
	return nil
}

func (t tristate) resolve(auto func() bool) bool {
	switch t {
	case "on":
		return true
	case "off":
		return false
	default:
		return auto()
	}
}

// caBundles are the system CA bundle locations of common distributions.
var caBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
	"/etc/pki/tls/certs/ca-bundle.crt",   // RHEL, Fedora, Rocky, Alma
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // Arch, macOS
}

// systemCABundle returns the first existing system CA bundle, or "".
func systemCABundle() string {
	for _, p := range caBundles {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func cmdRun(args []string, stderr io.Writer) int {
	fs := newFlagSet("run", stderr)
	listenIPv6, resolverIPv6 := tristate("auto"), tristate("auto")
	var (
		stateDir      = fs.String("state-dir", defaultStateDir, "state directory (identity, last-known-good config)")
		manage        = fs.Bool("manage-nginx", false, "run OpenResty as a supervised child process")
		nginxBin      = fs.String("nginx-bin", "openresty", "OpenResty/nginx binary")
		nginxPrefix   = fs.String("nginx-prefix", "", "nginx prefix directory (default: <state-dir>/nginx)")
		nginxUser     = fs.String("nginx-user", "", "user for nginx worker processes when the agent runs as root (default: none; prefer running the agent as an unprivileged user)")
		luaDir        = fs.String("lua-dir", defaultLuaDir, "directory containing edgeweir/*.lua")
		cacheDir      = fs.String("cache-dir", defaultCacheDir, "parent directory of the proxy cache zones")
		controlSocket = fs.String("control-socket", defaultControlSocket, "unix socket of the data plane control API")
		originSocket  = fs.String("origin-socket", defaultOriginSocket, "unix socket of the internal origin layer")
		noVerifySock  = fs.String("origin-socket-noverify", "", "unix socket of the origin layer without TLS verification (default: origin-noverify.sock next to --origin-socket)")
		edgeSock      = fs.String("edge-socket", "", "local edge listener for prefetch requests when every listener uses the PROXY protocol (default: edge.sock next to --control-socket)")
		trustedCA     = fs.String("trusted-ca", "", "CA bundle for verifying HTTPS origins (default: the system bundle)")
		resolvConf    = fs.String("resolv-conf", "/etc/resolv.conf", "resolv.conf to take nginx resolvers from")
		resolvers     = fs.String("resolver", "", "comma-separated nginx resolver addresses (overrides --resolv-conf)")
		defaultPort   = fs.Uint("default-port", 80, "HTTP port served before any configuration exists")
		workers       = fs.String("worker-processes", "auto", "nginx worker_processes")
		purgeDictMB   = fs.Int("purge-dict-mb", 32, "size of the purge marker store (lua_shared_dict edgeweir_purge) in MiB")
		purgePerSite  = fs.Int("purge-markers-per-site", agent.DefaultPurgeMarkersPerSite, "URL and prefix purge markers per site before they collapse into one site-level marker")
		prefetchTime  = fs.Duration("prefetch-budget", 4*time.Minute, "time the prefetch tasks of one pulled batch may take (the console hands tasks out again after 5 minutes)")
		lf            logFlags
	)
	fs.Var(&listenIPv6, "listen-ipv6", "also listen on IPv6: auto, on or off")
	fs.Var(&resolverIPv6, "resolver-ipv6", "resolve AAAA records for origins: auto, on or off")
	lf.register(fs)
	if ok, code := parse(fs, args); !ok {
		return code
	}
	log, err := lf.logger(stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if *defaultPort == 0 || *defaultPort > 65535 {
		fmt.Fprintln(stderr, "run: --default-port must be 1-65535")
		return 2
	}
	if *purgeDictMB < 1 || *purgeDictMB > 65536 {
		fmt.Fprintln(stderr, "run: --purge-dict-mb must be 1-65536")
		return 2
	}
	if *prefetchTime <= 0 {
		fmt.Fprintln(stderr, "run: --prefetch-budget must be positive")
		return 2
	}
	if *purgePerSite < 1 {
		fmt.Fprintln(stderr, "run: --purge-markers-per-site must be at least 1")
		return 2
	}

	abs := func(p string) string {
		a, err := filepath.Abs(p)
		if err != nil {
			return p
		}
		return a
	}
	state := abs(*stateDir)
	prefix := *nginxPrefix
	if prefix == "" {
		prefix = filepath.Join(state, "nginx")
	}
	prefix = abs(prefix)
	conf := filepath.Join(prefix, "conf", "nginx.conf")

	var rs []string
	if *resolvers != "" {
		for _, r := range strings.Split(*resolvers, ",") {
			rs = append(rs, strings.TrimSpace(r))
		}
	} else {
		rs = render.Resolvers(*resolvConf)
	}
	// Let nginx workers use the hard open-file limit (os/exec children only
	// inherit the default soft limit) and size worker_connections to fit.
	nofile := min(hostinfo.NofileHardLimit(), 1<<20)
	workerConnections := 4096
	if nofile > 0 && nofile < 2*uint64(workerConnections) {
		workerConnections = max(int(nofile/2), 256)
	}
	caBundle := *trustedCA
	if caBundle == "" {
		caBundle = systemCABundle()
	}
	if caBundle == "" {
		log.Warn("no CA bundle found (set --trusted-ca): HTTPS origins that require certificate verification will fail")
	} else {
		caBundle = abs(caBundle)
	}
	params := render.Params{
		Prefix:             prefix,
		LuaDir:             abs(*luaDir),
		CacheDir:           abs(*cacheDir),
		ControlSocket:      abs(*controlSocket),
		OriginSocket:       abs(*originSocket),
		TrustedCA:          caBundle,
		ResolvConf:         abs(*resolvConf),
		Resolvers:          rs,
		ResolverIPv6:       resolverIPv6.resolve(hostinfo.HasGlobalIPv6),
		ListenIPv6:         listenIPv6.resolve(hostinfo.CanListenIPv6),
		User:               *nginxUser,
		WorkerProcesses:    *workers,
		WorkerRlimitNofile: nofile,
		WorkerConnections:  workerConnections,
		PurgeDictMB:        *purgeDictMB,
	}
	if *noVerifySock != "" {
		params.OriginSocketNoVerify = abs(*noVerifySock)
	}
	if *edgeSock != "" {
		params.EdgeSocket = abs(*edgeSock)
	}
	params = params.WithDefaults()
	if _, err := os.Stat(filepath.Join(params.LuaDir, "edgeweir", "init.lua")); err != nil {
		log.Warn("Lua modules not found; nginx configuration tests will fail", "lua_dir", params.LuaDir, "err", err)
	}
	if os.Geteuid() == 0 && *nginxUser == "" {
		log.Warn("running as root without --nginx-user: nginx workers run as nobody and may not be able to write the cache; " +
			"run the agent as a dedicated unprivileged user instead (see packaging/systemd)")
	}

	log.Info("starting edgeweir-node", "version", version.Version, "commit", version.Commit,
		"state_dir", state, "manage_nginx", *manage, "nginx_bin", *nginxBin, "nginx_prefix", prefix,
		"control_socket", params.ControlSocket, "resolvers", strings.Join(rs, " "))

	eng := engine.New(engine.Config{
		Bin:          *nginxBin,
		Prefix:       prefix,
		Conf:         conf,
		Managed:      *manage,
		StaleSockets: []string{params.ControlSocket, params.OriginSocket, params.OriginSocketNoVerify, params.EdgeSocket},
		Logger:       log,
	})
	a := agent.New(agent.Config{
		StateDir:            state,
		ConfPath:            conf,
		Render:              params,
		DefaultPort:         uint32(*defaultPort),
		PurgeMarkersPerSite: *purgePerSite,
		PrefetchBudget:      *prefetchTime,
	}, eng, dataplane.NewClient(params.ControlSocket), log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		log.Error("agent stopped with an error", "err", err)
		return 1
	}
	return 0
}

func cmdHealthcheck(args []string, stderr io.Writer) int {
	fs := newFlagSet("healthcheck", stderr)
	controlSocket := fs.String("control-socket", defaultControlSocket, "unix socket of the data plane control API")
	timeout := fs.Duration("timeout", 3*time.Second, "timeout")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c := dataplane.NewClient(*controlSocket)
	st, err := c.Status(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "unhealthy:", err)
		return 1
	}
	if st.Version == 0 {
		fmt.Fprintln(stderr, "unhealthy: data plane has no site table yet")
		return 1
	}
	fmt.Fprintln(stderr, "healthy: revision "+strconv.FormatUint(st.Revision, 10)+", "+strconv.Itoa(st.SiteCount)+" sites")
	return 0
}
