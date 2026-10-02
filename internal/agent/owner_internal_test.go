//go:build unix

package agent

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// TestLetWorkersIn (P1-62): as root with --nginx-user, the worker user can
// enter the 0700 state directory on the way to the prefix and the 0750
// socket directory; directories everyone may enter and those of other
// owners keep their mode and group. Runs as root only (in a container).
func TestLetWorkersIn(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no user nobody")
	}
	gid, _ := strconv.Atoi(u.Gid)
	root := t.TempDir()
	mk := func(p string, mode os.FileMode) string {
		p = filepath.Join(root, p)
		if err := os.MkdirAll(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	state := mk("state", 0o700)
	prefix := mk("state/nginx", 0o750)
	tmp := mk("state/nginx/tmp", 0o750)
	conf := mk("state/nginx/conf", 0o750)
	run := mk("run", 0o755)
	sockets := mk("run/edgeweir-node", 0o750)
	other := mk("other", 0o700)
	if err := os.Chown(other, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := chownToUser("nobody", tmp); err != nil {
		t.Fatal(err)
	}
	if err := letWorkersIn("nobody", tmp, sockets, filepath.Join(other, "x")); err == nil {
		t.Fatal("a missing directory was accepted")
	}
	if err := letWorkersIn("nobody", tmp, sockets); err != nil {
		t.Fatal(err)
	}
	check := func(p string, mode os.FileMode, group int) {
		t.Helper()
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != mode || int(st.Sys().(*syscall.Stat_t).Gid) != group {
			t.Errorf("%s: mode %v group %d, want %v %d", p, st.Mode().Perm(), st.Sys().(*syscall.Stat_t).Gid, mode, group)
		}
	}
	check(state, 0o710, gid)
	check(prefix, 0o750, gid)
	check(sockets, 0o750, gid)
	check(run, 0o755, 0)
	check(conf, 0o750, 0)
	check(other, 0o700, 1)
}
