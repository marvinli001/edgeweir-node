package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/diag"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/pki"
)

// Results of a diagnose check.
const (
	checkOK   = "ok"
	checkWarn = "warn"
	checkFail = "fail"
	checkSkip = "skip"
)

// Clock offsets at which diagnose warns, and fails (the console's default
// alert threshold).
const (
	clockWarn = time.Second
	clockFail = 30 * time.Second
)

type checkResult struct {
	Name   string `json:"name"`
	Result string `json:"result"`
	Detail string `json:"detail"`
}

// cmdDiagnose checks the node from where it runs: its identity and
// certificate, the console (one authenticated call, which also measures
// the clock), the running agent (its diagnostics socket) and the data
// plane. Exit code 1 when a check fails.
func cmdDiagnose(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("diagnose", stderr)
	var (
		stateDir      = fs.String("state-dir", defaultStateDir, "state directory of the identity")
		controlSocket = fs.String("control-socket", defaultControlSocket, "unix socket of the data plane control API")
		diagSocket    = fs.String("diag-socket", defaultDiagSocket, "unix socket of the agent's diagnostics")
		asJSON        = fs.Bool("json", false, "print the checks and the agent's status as JSON")
		timeout       = fs.Duration("timeout", 15*time.Second, "timeout of the console check")
	)
	if ok, code := parse(fs, args); !ok {
		return code
	}
	dir, err := filepath.Abs(*stateDir)
	if err != nil {
		fmt.Fprintln(stderr, "diagnose: invalid --state-dir:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var checks []checkResult
	add := func(name, result, detail string) {
		checks = append(checks, checkResult{Name: name, Result: result, Detail: detail})
	}

	store := identity.Store{Dir: dir}
	var id *identity.Loaded
	switch {
	case !store.Enrolled():
		add("identity", checkFail, "not enrolled ("+store.Path(store.IdentityFile())+" missing): run `edgeweir-node enroll`")
	default:
		if id, err = store.Load(); err != nil {
			add("identity", checkFail, err.Error())
		} else {
			add("identity", checkOK, fmt.Sprintf("node %s (%s), cluster %s", id.NodeID, id.NodeName, id.ClusterID))
		}
	}

	now := time.Now()
	switch {
	case id == nil:
		add("certificate", checkSkip, "no identity")
	case !now.Before(id.Certificate.NotAfter):
		add("certificate", checkFail, "expired at "+id.Certificate.NotAfter.UTC().Format(time.RFC3339)+": re-enroll with `edgeweir-node enroll --force`")
	case pki.NeedsRenewal(id.Certificate, now):
		add("certificate", checkWarn, "valid until "+id.Certificate.NotAfter.UTC().Format(time.RFC3339)+"; renewal is due (the agent renews it while it reaches the console)")
	default:
		add("certificate", checkOK, "valid until "+id.Certificate.NotAfter.UTC().Format(time.RFC3339))
	}

	var measured *controlplane.CheckResult
	if id == nil {
		add("console", checkSkip, "no identity")
	} else {
		addr := controlplane.CurrentAddress(id.Identity)
		sent := time.Now()
		res, err := controlplane.CheckWithClock(ctx, id, func() *tls.Certificate { return &id.TLS }, addr)
		took := time.Since(sent)
		switch {
		case err != nil:
			add("console", checkFail, fmt.Sprintf("%s: %s: %v", addr, controlplane.CheckCode(err), err))
		case res.Legacy:
			add("console", checkOK, fmt.Sprintf("%s answered in %s (an older console)", addr, millis(took)))
		default:
			add("console", checkOK, fmt.Sprintf("%s answered in %s", addr, millis(took)))
			measured = &res
		}
	}

	agentStatus, agentErr := diag.Fetch(ctx, *diagSocket)
	switch {
	case agentErr != nil:
		add("agent", checkFail, fmt.Sprintf("no answer on %s (agent not running, or started with another --diag-socket): %v", *diagSocket, agentErr))
	case agentStatus.NodeID == "":
		add("agent", checkWarn, "edgeweir-node "+agentStatus.Version+" is waiting for enrollment")
	case agentStatus.Report.LastOK.IsZero():
		add("agent", checkFail, "edgeweir-node "+agentStatus.Version+" has not reached the console since it started"+lastError(agentStatus))
	default:
		age := now.Sub(agentStatus.Report.LastOK)
		interval := time.Duration(max(agentStatus.Report.IntervalSeconds, 1)) * time.Second
		detail := fmt.Sprintf("edgeweir-node %s, last report %s ago", agentStatus.Version, age.Round(time.Second))
		if age > 3*interval {
			add("agent", checkFail, detail+lastError(agentStatus))
		} else {
			add("agent", checkOK, detail)
		}
	}

	if agentStatus == nil {
		add("configuration", checkSkip, "no agent")
	} else {
		c := agentStatus.Config
		rev := "revision " + strconv.FormatUint(c.AppliedRevision, 10)
		switch {
		case c.State == "failed":
			add("configuration", checkFail, rev+" in use; the latest failed: "+c.Message)
		case c.AppliedRevision == 0:
			add("configuration", checkWarn, c.Message)
		case c.LatestRevision > c.AppliedRevision:
			add("configuration", checkWarn, fmt.Sprintf("%s applied, the console has %d (%s)", rev, c.LatestRevision, c.State))
		case c.CertificateFailures > 0:
			add("configuration", checkWarn, fmt.Sprintf("%s applied; %d certificate(s) did not load", rev, c.CertificateFailures))
		default:
			add("configuration", checkOK, rev+" applied")
		}
	}

	dpCtx, dpCancel := context.WithTimeout(context.Background(), 3*time.Second)
	st, err := dataplane.NewClient(*controlSocket).Status(dpCtx)
	dpCancel()
	switch {
	case err != nil:
		add("data plane", checkFail, err.Error())
	case st.Version == 0:
		add("data plane", checkFail, "no site table yet")
	default:
		add("data plane", checkOK, fmt.Sprintf("revision %d, %d sites", st.Revision, st.SiteCount))
	}

	switch {
	case measured != nil && measured.ClockKnown:
		add(clockCheck(measured.ClockOffset, measured.ClockRTT, "now"))
	case agentStatus != nil && agentStatus.Clock != nil:
		c := agentStatus.Clock
		add(clockCheck(time.Duration(c.OffsetMillis)*time.Millisecond, time.Duration(c.RTTMillis)*time.Millisecond,
			"as the agent measured "+now.Sub(c.MeasuredAt).Round(time.Second).String()+" ago"))
	default:
		add("clock", checkSkip, "the console does not tell its time (before v1.5.0's console)")
	}

	failed := false
	for _, c := range checks {
		failed = failed || c.Result == checkFail
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			Checks []checkResult `json:"checks"`
			Agent  *diag.Status  `json:"agent"`
		}{checks, agentStatus}); err != nil {
			fmt.Fprintln(stderr, "diagnose:", err)
			return 1
		}
	} else {
		for _, c := range checks {
			fmt.Fprintf(stdout, "%-5s %-14s %s\n", c.Result, c.Name, c.Detail)
		}
	}
	if failed {
		return 1
	}
	return 0
}

// clockCheck judges an offset measured with a round trip of rtt.
func clockCheck(offset, rtt time.Duration, when string) (string, string, string) {
	abs := offset.Abs()
	side := "ahead of"
	if offset < 0 {
		side = "behind"
	}
	detail := fmt.Sprintf("%s %s the console (±%s, %s)", millis(abs), side, millis(rtt/2), when)
	if abs < time.Millisecond {
		detail = fmt.Sprintf("in sync with the console (±%s, %s)", millis(rtt/2), when)
	}
	switch {
	case abs >= clockFail:
		return "clock", checkFail, detail + ": enable time synchronization (NTP)"
	case abs >= clockWarn:
		return "clock", checkWarn, detail
	}
	return "clock", checkOK, detail
}

func millis(d time.Duration) string {
	switch {
	case d >= 10*time.Second:
		return d.Round(time.Second).String()
	case d < time.Millisecond:
		return "<1ms"
	}
	return d.Round(time.Millisecond).String()
}

func lastError(st *diag.Status) string {
	if st.Report.LastError == "" {
		return ""
	}
	return "; last error " + st.Report.LastErrorAt.UTC().Format(time.RFC3339) + ": " + st.Report.LastError
}

// cmdPprof writes one of the running agent's Go profiles (diag.Profiles)
// from its diagnostics socket, for `go tool pprof` / `go tool trace`.
func cmdPprof(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("pprof", stderr)
	var (
		diagSocket = fs.String("diag-socket", defaultDiagSocket, "unix socket of the agent's diagnostics")
		seconds    = fs.Int("seconds", 30, "length of a CPU profile or trace, at most "+strconv.Itoa(diag.MaxSeconds))
		output     = fs.String("output", "", "file to write (default: standard output, unless it is a terminal)")
	)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: edgeweir-node pprof PROFILE [flags]\n\nPROFILE is one of %v (profile: CPU).\n\n", diag.Profiles)
		fs.PrintDefaults()
	}
	profile := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		profile, args = args[0], args[1:]
	}
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if profile == "" {
		fs.Usage()
		return 2
	}
	var w io.Writer = stdout
	if *output != "" {
		f, err := os.OpenFile(*output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "pprof:", err)
			return 1
		}
		defer f.Close()
		w = f
	} else if f, ok := stdout.(*os.File); ok {
		if fi, err := f.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintln(stderr, "pprof: standard output is a terminal: redirect it or use --output FILE")
			return 2
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*seconds+30)*time.Second)
	defer cancel()
	if err := diag.Profile(ctx, *diagSocket, profile, *seconds, w); err != nil {
		fmt.Fprintln(stderr, "pprof:", err)
		return 1
	}
	return 0
}
