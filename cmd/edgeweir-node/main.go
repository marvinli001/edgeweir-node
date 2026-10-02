// Command edgeweir-node is the Edgeweir edge node agent.
//
//	EDGEWEIR_TOKEN=T edgeweir-node enroll --server URL --ca-sha256 HEX [--server-name N] [--state-dir DIR] [--force]
//	edgeweir-node enroll --server URL --token-file PATH --ca-sha256 HEX ...  (--token T also works but shows in ps)
//	edgeweir-node run [--manage-nginx] [--state-dir DIR] [--nginx-bin BIN] [--nginx-prefix DIR]
//	                  [--lua-dir DIR] [--control-socket PATH] [--kernel-bans auto|off] ...
//	EDGEWEIR_TOKEN=T edgeweir-node probe --server URL --ca-sha256 HEX [--server-name N] [--state-dir DIR]
//	edgeweir-node probe [--state-dir DIR]   (once enrolled)
//	edgeweir-node healthcheck [--control-socket PATH]
//	edgeweir-node bans [--control-socket PATH] [--list]
//	edgeweir-node security [--control-socket PATH]
//	edgeweir-node version
//
// Every flag can also be set with an environment variable
// (EDGEWEIR_<FLAG_NAME>, e.g. EDGEWEIR_STATE_DIR); flags win.
package main

import (
	"context"
	"encoding/json"
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

	"github.com/marvinli001/edgeweir-node/internal/agent"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/engine"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	"github.com/marvinli001/edgeweir-node/internal/geoip"
	"github.com/marvinli001/edgeweir-node/internal/hostinfo"
	"github.com/marvinli001/edgeweir-node/internal/nft"
	"github.com/marvinli001/edgeweir-node/internal/probe"
	"github.com/marvinli001/edgeweir-node/internal/render"
	"github.com/marvinli001/edgeweir-node/internal/upgrade"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

const (
	defaultStateDir      = "/var/lib/edgeweir-node"
	defaultProbeStateDir = "/var/lib/edgeweir-probe"
	defaultLuaDir        = "/usr/share/edgeweir-node/lua"
	defaultCacheDir      = "/var/cache/edgeweir-node"
	defaultControlSocket = "/run/edgeweir-node/control.sock"
	defaultOriginSocket  = "/run/edgeweir-node/origin.sock"
	// edgeweirOpenResty is the nginx binary of the edgeweir-openresty
	// package (and the container image).
	edgeweirOpenResty = "/usr/lib/edgeweir-openresty/nginx/sbin/nginx"
)

// defaultNginxBin is edgeweir-openresty's nginx when it is installed,
// otherwise openresty from PATH.
func defaultNginxBin() string {
	if fileExists(edgeweirOpenResty) {
		return edgeweirOpenResty
	}
	return "openresty"
}

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
	case "supervise":
		return cmdRunMode(args[1:], stderr, true)
	case "probe":
		return cmdProbe(args[1:], stderr)
	case "healthcheck":
		return cmdHealthcheck(args[1:], stderr)
	case "bans":
		return cmdBans(args[1:], stdout, stderr)
	case "security":
		return cmdSecurity(args[1:], stdout, stderr)
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
  edgeweir-node supervise --manage-nginx [flags]
  EDGEWEIR_TOKEN=TOKEN edgeweir-node probe --server URL --ca-sha256 HEX [flags]
  edgeweir-node probe [--state-dir DIR]
  edgeweir-node healthcheck [--control-socket PATH]
  edgeweir-node bans [--control-socket PATH] [--list]
  edgeweir-node security [--control-socket PATH]
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
	if v, err := engine.New(engine.Config{Bin: envOr("EDGEWEIR_NGINX_BIN", defaultNginxBin())}).Version(vctx); err == nil {
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

// cmdProbe runs a regional probe: it enrolls with a one-time probe token on
// the first run, then measures the nodes the console names over mTLS. It
// never starts OpenResty.
func cmdProbe(args []string, stderr io.Writer) int {
	fs := newFlagSet("probe", stderr)
	var (
		server     = fs.String("server", "", "console node-channel URL, e.g. https://console.example.com:8443 (first run)")
		token      = fs.String("token", "", "single-use probe token (first run); visible in the process list, prefer the EDGEWEIR_TOKEN environment variable or --token-file")
		tokenFile  = fs.String("token-file", "", "read the single-use probe token from this file (first run)")
		caSHA256   = fs.String("ca-sha256", "", "SHA-256 of the console's internal CA certificate (DER, hex) (first run)")
		serverName = fs.String("server-name", "", "TLS server name to verify (default: host of --server)")
		stateDir   = fs.String("state-dir", defaultProbeStateDir, "state directory for the probe identity (not the node's)")
		timeout    = fs.Duration("timeout", 30*time.Second, "timeout of each console RPC")
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
		fmt.Fprintln(stderr, "probe:", err)
		return 2
	}
	_ = os.Unsetenv(envName("token"))
	if cli["token"] {
		log.Warn("--token is visible to other users in the process list; prefer EDGEWEIR_TOKEN or --token-file")
	}
	if *timeout <= 0 {
		fmt.Fprintln(stderr, "probe: --timeout must be positive")
		return 2
	}
	dir, err := filepath.Abs(*stateDir)
	if err != nil {
		log.Error("invalid --state-dir", "err", err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = probe.Main(ctx, probe.Options{
		ServerURL: *server, Token: tok, CASHA256: *caSHA256, ServerName: *serverName,
		StateDir: dir, Timeout: *timeout, Log: log,
	})
	switch {
	case errors.Is(err, probe.ErrNotEnrolled):
		fmt.Fprintln(stderr, "probe:", err)
		fs.Usage()
		return 2
	case err != nil && ctx.Err() == nil:
		log.Error("probe stopped with an error", "err", err)
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

// fileExists reports whether path is an existing regular file.
func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
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

func cmdRun(args []string, stderr io.Writer) int { return cmdRunMode(args, stderr, false) }
func cmdRunMode(args []string, stderr io.Writer, supervised bool) int {
	fs := newFlagSet("run", stderr)
	listenIPv6, resolverIPv6 := tristate("auto"), tristate("auto")
	var (
		stateDir      = fs.String("state-dir", defaultStateDir, "state directory (identity, last-known-good config)")
		manage        = fs.Bool("manage-nginx", false, "run OpenResty as a supervised child process")
		nginxBin      = fs.String("nginx-bin", defaultNginxBin(), "OpenResty/nginx binary (default: edgeweir-openresty's when installed, otherwise openresty from PATH)")
		nginxPrefix   = fs.String("nginx-prefix", "", "nginx prefix directory (default: <state-dir>/nginx)")
		nginxUser     = fs.String("nginx-user", "", "user for nginx worker processes when the agent runs as root (default: none; prefer running the agent as an unprivileged user)")
		luaDir        = fs.String("lua-dir", defaultLuaDir, "directory containing edgeweir/*.lua")
		cacheDir      = fs.String("cache-dir", defaultCacheDir, "parent directory of the proxy cache zones")
		controlSocket = fs.String("control-socket", defaultControlSocket, "unix socket of the data plane control API")
		originSocket  = fs.String("origin-socket", defaultOriginSocket, "unix socket of the internal origin layer")
		noVerifySock  = fs.String("origin-socket-noverify", "", "unix socket of the origin layer without TLS verification (default: origin-noverify.sock next to --origin-socket)")
		edgeSock      = fs.String("edge-socket", "", "local edge listener for prefetch requests when every listener uses the PROXY protocol (default: edge.sock next to --control-socket)")
		l4Sock        = fs.String("l4-socket", "", "unix socket of the stream subsystem's control relay for layer-4 applications (default: l4.sock next to --control-socket)")
		trustedCA     = fs.String("trusted-ca", "", "CA bundle for verifying HTTPS origins (default: the system bundle)")
		resolvConf    = fs.String("resolv-conf", "/etc/resolv.conf", "resolv.conf to take nginx resolvers from")
		resolvers     = fs.String("resolver", "", "comma-separated nginx resolver addresses (overrides --resolv-conf)")
		defaultPort   = fs.Uint("default-port", 80, "HTTP port served before any configuration exists")
		workers       = fs.String("worker-processes", "auto", "nginx worker_processes")
		cosignBin     = fs.String("cosign-bin", "cosign", "local signature verifier (supervise mode)")
		upgradeSource = fs.String("upgrade-source", upgrade.DefaultSource, "locally trusted release base URL (supervise mode)")
		upgradeKey    = fs.String("upgrade-public-key", "", "operator-provided local release public key; default GitHub OIDC identity")
		upgradeHTTP   = fs.Bool("upgrade-allow-http", false, "allow an explicitly configured plaintext test/air-gap mirror")
		downgrade     = fs.Bool("upgrade-allow-downgrade", false, "let upgrade tasks install an older version than the running one (supervise mode)")
		geoIPinfo     = fs.String("geoip-ipinfo", "auto", "IPinfo Lite MMDB path; auto uses the database bundled at build time if present, off disables it")
		geoCity       = fs.String("geoip-city", "", "operator-provided City MMDB path")
		geoASN        = fs.String("geoip-asn", "", "operator-provided ASN MMDB path")
		sitesDictMB   = fs.Int("sites-dict-mb", render.DefaultSitesDictMB, "size of the site table store (lua_shared_dict edgeweir_sites: the current and the previous site table, error page templates included) in MiB")
		statsDictMB   = fs.Int("stats-dict-mb", render.DefaultStatsDictMB, "size of the statistics counters (lua_shared_dict edgeweir_stats: per site and minute until the agent drains them) in MiB")
		purgeDictMB   = fs.Int("purge-dict-mb", 32, "size of the purge marker store (lua_shared_dict edgeweir_purge) in MiB")
		purgePerSite  = fs.Int("purge-markers-per-site", agent.DefaultPurgeMarkersPerSite, "URL and prefix purge markers per site before they collapse into one site-level marker")
		purgeTags     = fs.Int("purge-tags-per-site", agent.DefaultPurgeTagsPerSite, "tag purge markers per site before the site's markers collapse into one site-level marker")
		prefetchTime  = fs.Duration("prefetch-budget", 4*time.Minute, "time the prefetch tasks of one pulled batch may take (the console hands tasks out again after 5 minutes)")
		banCapacity   = fs.Int("ban-capacity", render.DefaultBanCapacity, "dynamic bans the data plane holds (console and own); the oldest automatic bans make room first")
		banDictMB     = fs.Int("ban-dict-mb", render.DefaultBanDictMB, "size of the ban store (lua_shared_dict edgeweir_bans) in MiB")
		ccDictMB      = fs.Int("cc-dict-mb", render.DefaultCCDictMB, "size of the CC mitigation store (lua_shared_dict edgeweir_cc: counters, levels, events) in MiB")
		challengeMB   = fs.Int("challenge-dict-mb", render.DefaultChallengeDictMB, "size of the challenge store (lua_shared_dict edgeweir_challenge: keys, captcha pool, used challenge nonces) in MiB")
		tagDictMB     = fs.Int("tag-dict-mb", render.DefaultTagDictMB, "size of the Cache-Tag index (lua_shared_dict edgeweir_tags: tags and key epoch of cached objects, for purges by tag) in MiB")
		rateDictKB    = fs.Int("rate-limit-dict-kb", render.DefaultRateLimitDictKB, "size of each published site's rate-limit counter store (lua_shared_dict edgeweir_rate_<hex site id>) in KiB")
		l4DictMB      = fs.Int("l4-dict-mb", render.DefaultL4DictMB, "size of the layer-4 table store (lua_shared_dict edgeweir_l4: the current and the previous table of layer-4 applications with their IP lists) in MiB")
		shutdownAfter = fs.Duration("stream-shutdown-timeout", 0, "close the connections a reload's old workers still serve after this long (worker_shutdown_timeout; 0: they serve them until they end)")
		kernelBans    = fs.String("kernel-bans", "auto", "also drop platform bans in the kernel with nftables: auto (when nft works; needs CAP_NET_ADMIN) or off")
		nftBin        = fs.String("nft-bin", "nft", "nftables binary for kernel bans")
		modsecModule  = fs.String("modsecurity-module", "auto", "ModSecurity-nginx dynamic module for sites that run the OWASP CRS: auto (the edgeweir-openresty-modsecurity package next to --nginx-bin), a path, or off")
		crsDir        = fs.String("crs-dir", render.DefaultCRSDir, "OWASP CRS directory (crs-setup.conf and rules/); unicode.mapping is read from ../modsecurity/")
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
	if *sitesDictMB < 1 || *sitesDictMB > 65536 {
		fmt.Fprintln(stderr, "run: --sites-dict-mb must be 1-65536")
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
	if *purgeTags < 1 {
		fmt.Fprintln(stderr, "run: --purge-tags-per-site must be at least 1")
		return 2
	}
	if *banCapacity < 1 || *banCapacity > render.MaxBanCapacity {
		fmt.Fprintf(stderr, "run: --ban-capacity must be 1-%d\n", render.MaxBanCapacity)
		return 2
	}
	if *banDictMB < 1 || *banDictMB > 65536 {
		fmt.Fprintln(stderr, "run: --ban-dict-mb must be 1-65536")
		return 2
	}
	if *ccDictMB < 1 || *ccDictMB > 65536 {
		fmt.Fprintln(stderr, "run: --cc-dict-mb must be 1-65536")
		return 2
	}
	if *challengeMB < 1 || *challengeMB > 65536 {
		fmt.Fprintln(stderr, "run: --challenge-dict-mb must be 1-65536")
		return 2
	}
	if *tagDictMB < 1 || *tagDictMB > 65536 {
		fmt.Fprintln(stderr, "run: --tag-dict-mb must be 1-65536")
		return 2
	}
	if *rateDictKB < render.MinRateLimitDictKB || *rateDictKB > render.MaxRateLimitDictKB {
		fmt.Fprintf(stderr, "run: --rate-limit-dict-kb must be %d-%d\n", render.MinRateLimitDictKB, render.MaxRateLimitDictKB)
		return 2
	}
	if *kernelBans != "auto" && *kernelBans != "off" {
		fmt.Fprintln(stderr, "run: --kernel-bans must be auto or off")
		return 2
	}
	if *crsDir == "" {
		fmt.Fprintln(stderr, "run: --crs-dir must not be empty")
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
	if caBundle != "" {
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
		SitesDictMB:        *sitesDictMB,
		StatsDictMB:        *statsDictMB,
		PurgeDictMB:        *purgeDictMB,
		BanDictMB:          *banDictMB,
		BanCapacity:        *banCapacity,
		CCDictMB:           *ccDictMB,
		ChallengeDictMB:    *challengeMB,
		TagDictMB:          *tagDictMB,
		RateLimitDictKB:    *rateDictKB,
		L4DictMB:           *l4DictMB,
		// Reloads keep old workers serving their connections (layer-4
		// sessions, WebSockets) until they end unless this is set.
		WorkerShutdownTimeout: *shutdownAfter,
	}
	switch *modsecModule {
	case "off":
	case "auto":
		params.ModSecurityModule = engine.DefaultModSecurityModule(*nginxBin)
	default:
		params.ModSecurityModule = abs(*modsecModule)
	}
	params.CRSDir = abs(*crsDir)
	if m := filepath.Join(filepath.Dir(params.CRSDir), "modsecurity", "unicode.mapping"); fileExists(m) {
		params.ModSecurityUnicodeMap = m
	}
	if *noVerifySock != "" {
		params.OriginSocketNoVerify = abs(*noVerifySock)
	}
	if *edgeSock != "" {
		params.EdgeSocket = abs(*edgeSock)
	}
	if *l4Sock != "" {
		params.L4Socket = abs(*l4Sock)
	}
	params = params.WithDefaults()
	// Every local setting is checked now, not at the first render: a
	// mistake ends the process with exit status 2 (the supervisor and the
	// systemd unit do not restart it then).
	if err := params.Validate(); err != nil {
		fmt.Fprintln(stderr, "run:", err)
		return 2
	}
	if supervised {
		if !*manage {
			fmt.Fprintln(stderr, "supervise requires --manage-nginx")
			return 2
		}
		executable, err := os.Executable()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		key := *upgradeKey
		if key != "" {
			key = abs(key)
		}
		// OpenResty runs under the supervisor: replacing the node process
		// (an upgrade, a restart) does not restart it.
		engineConfig := engineConfig(*nginxBin, prefix, conf, params, log)
		err = upgrade.Run(ctx, upgrade.Options{Trust: upgrade.Trust{StateDir: state, Source: *upgradeSource, Cosign: *cosignBin, PublicKey: key, AllowHTTP: *upgradeHTTP}, Executable: executable, LuaDir: abs(*luaDir), Version: version.Version, RunArgs: args, Log: log, Output: stderr,
			Engine: &engineConfig, AllowDowngrade: *downgrade})
		if errors.Is(err, upgrade.ErrUsage) {
			log.Error("supervisor stopped", "err", err)
			return 2
		}
		if err != nil {
			log.Error("supervisor stopped", "err", err)
			return 1
		}
		return 0
	}
	if caBundle == "" {
		log.Warn("no CA bundle found (set --trusted-ca): HTTPS origins that require certificate verification will fail")
	}
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

	engineConfig := engineConfig(*nginxBin, prefix, conf, params, log)
	engineConfig.Managed = *manage
	local := engine.New(engineConfig)
	var eng agent.Engine = local
	if sock := os.Getenv("EDGEWEIR_SUPERVISOR_SOCKET"); sock != "" && *manage {
		cctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if upgrade.NewClient(sock).Engine(cctx) {
			log.Info("OpenResty runs under the supervisor")
			eng = upgrade.NewRemoteEngine(sock, local)
		}
		cancel()
	}
	var kernel nft.Executor
	if *kernelBans == "auto" {
		kernel = nft.Command{Bin: *nftBin}
	}
	ipinfoPath, ipinfoOptional, err := geoip.ResolveIPinfo(*geoIPinfo)
	if err != nil {
		log.Error("cannot resolve --geoip-ipinfo", "err", err)
		return 1
	}
	a := agent.New(agent.Config{
		StateDir:            state,
		SupervisorSocket:    os.Getenv("EDGEWEIR_SUPERVISOR_SOCKET"),
		ConfPath:            conf,
		Render:              params,
		DefaultPort:         uint32(*defaultPort),
		PurgeMarkersPerSite: *purgePerSite,
		PurgeTagsPerSite:    *purgeTags,
		PrefetchBudget:      *prefetchTime,
		GeoIP:               geoip.Paths{IPinfo: ipinfoPath, IPinfoOptional: ipinfoOptional, City: *geoCity, ASN: *geoASN},
		BanCapacity:         *banCapacity,
		Kernel:              kernel,
	}, eng, dataplane.NewClient(params.ControlSocket), log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		log.Error("agent stopped with an error", "err", err)
		return 1
	}
	return 0
}

// engineConfig is OpenResty's process configuration (managed).
func engineConfig(bin, prefix, conf string, params render.Params, log *slog.Logger) engine.Config {
	return engine.Config{
		Bin:          bin,
		Prefix:       prefix,
		Conf:         conf,
		Managed:      true,
		StaleSockets: []string{params.ControlSocket, params.OriginSocket, params.OriginSocketNoVerify, params.EdgeSocket, params.EdgeTLSSocket, params.L4Socket},
		Logger:       log,
	}
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

// cmdBans prints the data plane's ban status as JSON (with --list also up
// to 1000 bans it holds).
func cmdBans(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("bans", stderr)
	controlSocket := fs.String("control-socket", defaultControlSocket, "unix socket of the data plane control API")
	list := fs.Bool("list", false, "also list the bans held (at most 1000)")
	timeout := fs.Duration("timeout", 3*time.Second, "timeout")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c := dataplane.NewClient(*controlSocket)
	out := struct {
		*dataplane.BanStatus
		Bans *[]dataplane.BanEntry `json:"bans,omitempty"`
	}{}
	var err error
	if *list {
		var entries []dataplane.BanEntry
		out.BanStatus, entries, err = c.ListBans(ctx)
		entries = append([]dataplane.BanEntry{}, entries...)
		out.Bans = &entries
	} else {
		out.BanStatus, err = c.BanStatus(ctx)
	}
	if err != nil {
		fmt.Fprintln(stderr, "bans:", err)
		return 1
	}
	if out.UnappliedIDs == nil {
		out.UnappliedIDs = []string{}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(stderr, "bans:", err)
		return 1
	}
	return 0
}

// cmdSecurity prints the data plane's challenge state (key ids, captcha
// pool) and CC state (levels, escalated paths, last rates, queued events)
// as JSON. It never drains events: those belong to the agent.
func cmdSecurity(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("security", stderr)
	controlSocket := fs.String("control-socket", defaultControlSocket, "unix socket of the data plane control API")
	timeout := fs.Duration("timeout", 3*time.Second, "timeout")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c := dataplane.NewClient(*controlSocket)
	ch, err := c.ChallengeStatus(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "security:", err)
		return 1
	}
	cc, err := c.SecurityStatus(ctx)
	if err != nil {
		fmt.Fprintln(stderr, "security:", err)
		return 1
	}
	if ch.Keys == nil {
		ch.Keys = dataplane.List[string]{}
	}
	if cc.Sites == nil {
		cc.Sites = dataplane.List[dataplane.SecuritySite]{}
	}
	for i := range cc.Sites {
		if cc.Sites[i].Paths == nil {
			cc.Sites[i].Paths = dataplane.List[dataplane.SecurityPath]{}
		}
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Challenge *dataplane.ChallengeStatus `json:"challenge"`
		CC        *dataplane.SecurityStatus  `json:"cc"`
	}{ch, cc}); err != nil {
		fmt.Fprintln(stderr, "security:", err)
		return 1
	}
	return 0
}
