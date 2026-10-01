package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func TestEnvName(t *testing.T) {
	cases := map[string]string{
		"state-dir":      "EDGEWEIR_STATE_DIR",
		"ca-sha256":      "EDGEWEIR_CA_SHA256",
		"manage-nginx":   "EDGEWEIR_MANAGE_NGINX",
		"control-socket": "EDGEWEIR_CONTROL_SOCKET",
	}
	for in, want := range cases {
		if got := envName(in); got != want {
			t.Errorf("envName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestApplyEnvFlagsWin(t *testing.T) {
	t.Setenv("EDGEWEIR_STATE_DIR", "/from/env")
	t.Setenv("EDGEWEIR_TOKEN", "env-token")
	t.Setenv("EDGEWEIR_MANAGE_NGINX", "true")
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	stateDir := fs.String("state-dir", "/default", "")
	token := fs.String("token", "", "")
	manage := fs.Bool("manage-nginx", false, "")
	if err := fs.Parse([]string{"--state-dir", "/from/flag"}); err != nil {
		t.Fatal(err)
	}
	if err := applyEnv(fs); err != nil {
		t.Fatal(err)
	}
	if *stateDir != "/from/flag" || *token != "env-token" || !*manage {
		t.Fatalf("state-dir=%q token=%q manage=%v", *stateDir, *token, *manage)
	}

	t.Setenv("EDGEWEIR_MANAGE_NGINX", "maybe")
	fs2 := flag.NewFlagSet("y", flag.ContinueOnError)
	fs2.Bool("manage-nginx", false, "")
	_ = fs2.Parse(nil)
	if err := applyEnv(fs2); err == nil {
		t.Fatal("invalid boolean env var accepted")
	}
}

func TestRealMain(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := realMain([]string{"version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "edgeweir-node ") {
		t.Fatalf("version: code=%d out=%q", code, out.String())
	}
	if code := realMain(nil, io.Discard, io.Discard); code != 2 {
		t.Fatalf("no args: code=%d", code)
	}
	if code := realMain([]string{"bogus"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("unknown command: code=%d", code)
	}
	errOut.Reset()
	if code := realMain([]string{"enroll", "--server", "https://x"}, io.Discard, &errOut); code != 2 ||
		!strings.Contains(errOut.String(), "required") {
		t.Fatalf("enroll without token: code=%d stderr=%q", code, errOut.String())
	}
	if code := realMain([]string{"run", "--default-port", "0"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("run with invalid port: code=%d", code)
	}
	if code := realMain([]string{"run", "--purge-dict-mb", "0"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("run with invalid purge dict size: code=%d", code)
	}
	for _, size := range []string{"0", "65537"} {
		errOut.Reset()
		if code := realMain([]string{"run", "--sites-dict-mb", size}, io.Discard, &errOut); code != 2 ||
			!strings.Contains(errOut.String(), "--sites-dict-mb must be 1-65536") {
			t.Fatalf("run with sites dict size %s: code=%d stderr=%q", size, code, errOut.String())
		}
	}
	if code := realMain([]string{"run", "--prefetch-budget", "0s"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("run with invalid prefetch budget: code=%d", code)
	}
	if code := realMain([]string{"run", "--purge-markers-per-site", "0"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("run with invalid purge marker cap: code=%d", code)
	}
	errOut.Reset()
	if code := realMain([]string{"run", "--purge-tags-per-site", "0"}, io.Discard, &errOut); code != 2 ||
		!strings.Contains(errOut.String(), "--purge-tags-per-site must be at least 1") {
		t.Fatalf("run with invalid tag marker cap: code=%d stderr=%q", code, errOut.String())
	}
	if code := realMain([]string{"run", "--listen-ipv6", "sometimes"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("run with invalid tristate: code=%d", code)
	}
	if code := realMain([]string{"healthcheck", "--control-socket", "/nonexistent/control.sock", "--timeout", "100ms"}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("healthcheck against missing socket: code=%d", code)
	}
}

func TestEnrollTokenSources(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name              string
		token, tokenFile  string
		tokenCLI, fileCLI bool
		want              string
		wantErr           string
	}{
		{name: "env token", token: "env-token", want: "env-token"},
		{name: "flag token", token: "cli-token", tokenCLI: true, want: "cli-token"},
		{name: "token file", tokenFile: file, fileCLI: true, want: "file-token"},
		{name: "token file from env", tokenFile: file, want: "file-token"},
		{name: "file flag beats env token", token: "env-token", tokenFile: file, fileCLI: true, want: "file-token"},
		{name: "token flag beats env file", token: "cli-token", tokenFile: file, tokenCLI: true, want: "cli-token"},
		{name: "both flags", token: "cli-token", tokenFile: file, tokenCLI: true, fileCLI: true, wantErr: "not both"},
		{name: "both env", token: "env-token", tokenFile: file, wantErr: "not both"},
		{name: "missing file", tokenFile: filepath.Join(dir, "nope"), fileCLI: true, wantErr: "read token file"},
		{name: "empty file", tokenFile: empty, fileCLI: true, wantErr: "is empty"},
		{name: "none"},
	}
	for _, c := range cases {
		got, err := enrollToken(c.token, c.tokenFile, c.tokenCLI, c.fileCLI)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%s: err = %v, want %q", c.name, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: token = %q, %v; want %q", c.name, got, err, c.want)
		}
	}
}

// TestEnrollReadsTokenFromEnvAndFile (N-H1): `enroll` takes the token from
// EDGEWEIR_TOKEN (as install.sh passes it) or --token-file, so it never
// has to appear in the process list; the variable is not passed on.
func TestEnrollReadsTokenFromEnvAndFile(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-cli"})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	t.Setenv("EDGEWEIR_NGINX_BIN", filepath.Join(t.TempDir(), "no-openresty"))

	console.AddToken("env-token")
	t.Setenv("EDGEWEIR_TOKEN", "env-token")
	var stderr bytes.Buffer
	dir := filepath.Join(t.TempDir(), "state-env")
	if code := realMain([]string{"enroll", "--server", srv.URL, "--ca-sha256", console.CA.Pin(), "--state-dir", dir}, io.Discard, &stderr); code != 0 {
		t.Fatalf("enroll with EDGEWEIR_TOKEN: code=%d stderr=%s", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "identity.json")); err != nil {
		t.Fatal("not enrolled:", err)
	}
	if _, set := os.LookupEnv("EDGEWEIR_TOKEN"); set {
		t.Fatal("EDGEWEIR_TOKEN is still set for child processes")
	}
	if strings.Contains(stderr.String(), "process list") {
		t.Fatal("warned about --token although the token came from the environment")
	}

	console.AddToken("file-token")
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stderr.Reset()
	dir = filepath.Join(t.TempDir(), "state-file")
	if code := realMain([]string{"enroll", "--server", srv.URL, "--ca-sha256", console.CA.Pin(), "--state-dir", dir, "--token-file", tokenFile}, io.Discard, &stderr); code != 0 {
		t.Fatalf("enroll with --token-file: code=%d stderr=%s", code, stderr.String())
	}

	// --token keeps working, with a warning.
	console.AddToken("flag-token")
	stderr.Reset()
	dir = filepath.Join(t.TempDir(), "state-flag")
	if code := realMain([]string{"enroll", "--server", srv.URL, "--ca-sha256", console.CA.Pin(), "--state-dir", dir, "--token", "flag-token"}, io.Discard, &stderr); code != 0 {
		t.Fatalf("enroll with --token: code=%d stderr=%s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "process list") {
		t.Fatalf("no warning for --token: %s", stderr.String())
	}
	if enrollments, _, _, _ := console.Counters(); enrollments != 3 {
		t.Fatalf("enrollments = %d, want 3", enrollments)
	}
}

func TestBansCommand(t *testing.T) {
	srv := fakedataplane.Start(t)
	c := dataplane.NewClient(srv.Socket)
	if _, err := c.PutBans(context.Background(), &dataplane.BanTable{Sequence: 42, Bans: []dataplane.Ban{
		{ID: "p1", CIDR: "198.51.100.0/24", Scope: "platform", Kind: "m", ExpiresAt: 1790000000},
	}}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := realMain([]string{"bans", "--control-socket", srv.Socket, "--list"}, &out, io.Discard); code != 0 {
		t.Fatalf("bans --list: code %d", code)
	}
	var got struct {
		Sequence     string               `json:"sequence"`
		Entries      int                  `json:"entries"`
		UnappliedIDs []string             `json:"unapplied_ids"`
		Bans         []dataplane.BanEntry `json:"bans"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("%v: %s", err, out.String())
	}
	if got.Sequence != "42" || got.Entries != 1 || got.UnappliedIDs == nil || len(got.Bans) != 1 || got.Bans[0].CIDR != "198.51.100.0/24" {
		t.Fatalf("bans --list printed %s", out.String())
	}
	out.Reset()
	if code := realMain([]string{"bans", "--control-socket", srv.Socket}, &out, io.Discard); code != 0 || strings.Contains(out.String(), `"bans"`) {
		t.Fatalf("bans: code %d, %s", code, out.String())
	}
	if code := realMain([]string{"bans", "--control-socket", "/nonexistent/control.sock", "--timeout", "100ms"}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("bans against a missing socket: code %d", code)
	}
}

func TestSecurityCommand(t *testing.T) {
	srv := fakedataplane.Start(t)
	srv.SetSecurity(dataplane.SecuritySite{SiteID: "site-a", Level: "js", EscalatedPaths: 1,
		Paths: dataplane.List[dataplane.SecurityPath]{{Path: "/login", Level: "pow"}}, SiteQPS: 1234.5})
	c := dataplane.NewClient(srv.Socket)
	if _, err := c.PutChallengeKeys(context.Background(), &dataplane.ChallengeKeys{ID: "set", Current: "k2",
		Keys: []dataplane.ChallengeKey{{ID: "k1", Secret: "c2VjcmV0MQ=="}, {ID: "k2", Secret: "c2VjcmV0Mg=="}}}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := realMain([]string{"security", "--control-socket", srv.Socket}, &out, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var got struct {
		Challenge dataplane.ChallengeStatus `json:"challenge"`
		CC        dataplane.SecurityStatus  `json:"cc"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Challenge.Current != "k2" || len(got.Challenge.Keys) != 2 || len(got.CC.Sites) != 1 ||
		got.CC.Sites[0].Level != "js" || got.CC.Sites[0].Paths[0].Path != "/login" {
		t.Fatalf("output = %s", out.String())
	}
	if strings.Contains(out.String(), "c2VjcmV0") {
		t.Fatal("secrets printed")
	}
	if code := realMain([]string{"security", "--control-socket", "/nonexistent/control.sock", "--timeout", "100ms"}, io.Discard, io.Discard); code != 1 {
		t.Fatal("unreachable data plane must exit 1")
	}
}
