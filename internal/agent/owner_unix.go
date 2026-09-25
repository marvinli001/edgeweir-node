//go:build unix

package agent

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// chownToUser hands directories nginx workers write to (temp files, cache)
// to the nginx worker user when the agent runs as root with --nginx-user.
// It is a no-op otherwise: in the recommended setup agent, master and
// workers all run as the same unprivileged user.
func chownToUser(spec string, paths ...string) error {
	if spec == "" || os.Geteuid() != 0 {
		return nil
	}
	name := strings.Fields(spec)[0]
	u, err := user.Lookup(name)
	if err != nil {
		return fmt.Errorf("nginx user %q: %w", name, err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	for _, p := range paths {
		if err := os.Chown(p, uid, gid); err != nil {
			return err
		}
	}
	return nil
}
