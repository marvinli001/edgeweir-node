//go:build unix

package agent

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// chownToUser hands directories nginx workers write to (temp files, cache)
// to the nginx worker user when the agent runs as root with --nginx-user.
// It is a no-op otherwise: in the recommended setup agent, master and
// workers all run as the same unprivileged user.
func chownToUser(spec string, paths ...string) error {
	if spec == "" || os.Geteuid() != 0 {
		return nil
	}
	uid, gid, err := lookupUser(spec)
	if err != nil {
		return err
	}
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

func lookupUser(spec string) (uid, gid int, err error) {
	name := strings.Fields(spec)[0]
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("nginx user %q: %w", name, err)
	}
	uid, _ = strconv.Atoi(u.Uid)
	gid, _ = strconv.Atoi(u.Gid)
	return uid, gid, nil
}

// letWorkersIn lets the nginx worker user enter every directory on the way
// to paths (unix sockets workers connect to, the prefix of their temp
// files) when the agent runs as root with --nginx-user: a directory owned
// by root that others may not enter (the 0700 state directory, a 0750
// socket directory) takes the worker's group with the group's search bit.
// Directories others may enter, and those of other owners, are left alone.
// A no-op otherwise.
func letWorkersIn(spec string, paths ...string) error {
	if spec == "" || os.Geteuid() != 0 {
		return nil
	}
	_, gid, err := lookupUser(spec)
	if err != nil {
		return err
	}
	done := map[string]bool{}
	for _, p := range paths {
		for dir := filepath.Clean(p); !done[dir]; dir = filepath.Dir(dir) {
			done[dir] = true
			st, err := os.Stat(dir)
			if err != nil {
				return err
			}
			sys, ok := st.Sys().(*syscall.Stat_t)
			mode := st.Mode().Perm()
			if ok && sys.Uid == 0 && mode&0o001 == 0 && (int(sys.Gid) != gid || mode&0o010 == 0) {
				if err := os.Chown(dir, -1, gid); err != nil {
					return err
				}
				if err := os.Chmod(dir, st.Mode()&(os.ModePerm|os.ModeSetuid|os.ModeSetgid|os.ModeSticky)|0o010); err != nil {
					return err
				}
			}
			if dir == filepath.Dir(dir) {
				break
			}
		}
	}
	return nil
}
