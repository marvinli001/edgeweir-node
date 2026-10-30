package main

import (
	"bytes"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/enroll"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// enrollResult runs `edgeweir-node enroll args...` and returns its exit
// status and the one result line it wrote to stdout.
func enrollResult(t *testing.T, args ...string) (int, enroll.Result) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := realMain(append([]string{"enroll"}, args...), &stdout, &stderr)
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], enroll.ResultPrefix) {
		t.Fatalf("enroll %v: stdout = %q, want one result line (stderr %s)", args, stdout.String(), stderr.String())
	}
	var r enroll.Result
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[0], enroll.ResultPrefix)), &r); err != nil {
		t.Fatal(err)
	}
	if r.V != 1 || r.Step != "enroll" || r.Exit != code {
		t.Fatalf("enroll %v: exit %d, result %+v", args, code, r)
	}
	return code, r
}

// The exit statuses and result lines a caller over SSH relies on
// (README "Unattended installs").
func TestEnrollResultContract(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-r", NodeName: "edge-r", ClusterID: "cl-r"})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	t.Setenv("EDGEWEIR_NGINX_BIN", filepath.Join(t.TempDir(), "no-openresty"))
	pin := console.CA.Pin()
	other, err := fakeconsole.New(fakeconsole.Options{})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "state")
	base := []string{"--server", srv.URL, "--ca-sha256", pin, "--state-dir", dir}

	// Usage: still one result line.
	if code, r := enrollResult(t, "--server", srv.URL, "--state-dir", dir); code != 2 || r.Status != "usage" {
		t.Fatalf("usage: %d %+v", code, r)
	}
	if code, r := enrollResult(t, append(base, "--force", "--if-not-enrolled")...); code != 2 || r.Status != "usage" {
		t.Fatalf("--force with --if-not-enrolled: %d %+v", code, r)
	}
	// Unknown token.
	t.Setenv("EDGEWEIR_TOKEN", "unknown")
	if code, r := enrollResult(t, base...); code != 12 || r.Status != "token_rejected" || r.Retry {
		t.Fatalf("unknown token: %d %+v", code, r)
	}
	// Wrong pin: the token is not sent.
	console.AddToken("tok-1")
	t.Setenv("EDGEWEIR_TOKEN", "tok-1")
	if code, r := enrollResult(t, "--server", srv.URL, "--ca-sha256", other.CA.Pin(), "--state-dir", dir); code != 14 || r.Status != "ca_mismatch" {
		t.Fatalf("wrong pin: %d %+v", code, r)
	}
	// Nothing listens.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "https://" + l.Addr().String()
	_ = l.Close()
	// enroll removes EDGEWEIR_TOKEN from its environment.
	t.Setenv("EDGEWEIR_TOKEN", "tok-1")
	if code, r := enrollResult(t, "--server", closed, "--ca-sha256", pin, "--state-dir", dir, "--timeout", "2s"); code != 13 || r.Status != "unreachable" || !r.Retry {
		t.Fatalf("unreachable: %d %+v", code, r)
	}
	// --if-not-enrolled on a new host enrolls like enroll.
	t.Setenv("EDGEWEIR_TOKEN", "tok-1")
	code, r := enrollResult(t, append(base, "--if-not-enrolled")...)
	if code != 0 || r.Status != "enrolled" || r.NodeID != "node-r" || r.NodeName != "edge-r" || r.ClusterID != "cl-r" || r.NotAfter == "" {
		t.Fatalf("enroll: %d %+v", code, r)
	}
	// Enrolled: a second enrollment is refused and names the node.
	console.AddToken("tok-2")
	t.Setenv("EDGEWEIR_TOKEN", "tok-2")
	if code, r := enrollResult(t, base...); code != 10 || r.Status != "already_enrolled" || r.NodeID != "node-r" {
		t.Fatalf("already enrolled: %d %+v", code, r)
	}
	// With --if-not-enrolled that is success, without a token.
	t.Setenv("EDGEWEIR_TOKEN", "")
	if code, r := enrollResult(t, append(base, "--if-not-enrolled")...); code != 0 || r.Status != "already_enrolled" || r.NodeID != "node-r" {
		t.Fatalf("--if-not-enrolled: %d %+v", code, r)
	}
	// ... unless the identity belongs to another console.
	if code, r := enrollResult(t, "--server", srv.URL, "--ca-sha256", other.CA.Pin(), "--state-dir", dir, "--if-not-enrolled"); code != 11 ||
		r.Status != "enrolled_elsewhere" || r.NodeID != "node-r" || r.CASHA256 != pin {
		t.Fatalf("enrolled elsewhere: %d %+v", code, r)
	}
	if enrollments, _, _, _ := console.Counters(); enrollments != 1 {
		t.Fatalf("enrollments = %d, want 1", enrollments)
	}
	// -h prints help, no result line.
	var stdout bytes.Buffer
	if code := realMain([]string{"enroll", "-h"}, &stdout, &bytes.Buffer{}); code != 0 || stdout.Len() != 0 {
		t.Fatalf("-h: %d %q", code, stdout.String())
	}
}
