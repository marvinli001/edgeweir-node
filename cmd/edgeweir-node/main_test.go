package main

import (
	"bytes"
	"flag"
	"io"
	"strings"
	"testing"
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
	if code := realMain([]string{"run", "--prefetch-budget", "0s"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("run with invalid prefetch budget: code=%d", code)
	}
	if code := realMain([]string{"run", "--purge-markers-per-site", "0"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("run with invalid purge marker cap: code=%d", code)
	}
	if code := realMain([]string{"run", "--listen-ipv6", "sometimes"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("run with invalid tristate: code=%d", code)
	}
	if code := realMain([]string{"healthcheck", "--control-socket", "/nonexistent/control.sock", "--timeout", "100ms"}, io.Discard, io.Discard); code != 1 {
		t.Fatalf("healthcheck against missing socket: code=%d", code)
	}
}
