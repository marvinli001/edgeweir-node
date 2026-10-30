// Package sidecar starts an extension's sidecar (extension version 1.1,
// docs/reference/extensions.md in the console repository) in its sandbox:
// the agent runs `edgeweir-node sidecar-exec` (ChildCommand) with a Spec in
// the environment; the child moves itself into the sidecar's cgroup, sets
// the resource limits, switches to the sidecar user, sets no_new_privs and
// a seccomp filter, and executes the binary with only the Spec's
// environment.
package sidecar

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// ChildCommand is the hidden subcommand of the sandbox helper.
const ChildCommand = "sidecar-exec"

// SpecEnv carries the Spec (JSON) from the agent to the helper.
const SpecEnv = "EDGEWEIR_SIDECAR_EXEC_SPEC"

// Spec is how the helper starts one sidecar.
type Spec struct {
	Binary string   `json:"binary"`
	Args   []string `json:"args"`
	Env    []string `json:"env"`
	Dir    string   `json:"dir"`
	UID    int      `json:"uid"`
	GID    int      `json:"gid"`
	// Cgroup is the sidecar's cgroup v2 directory ("": none; the limits
	// then come from rlimits only).
	Cgroup string `json:"cgroup,omitempty"`
	// MemoryBytes and Tasks become RLIMIT_DATA and RLIMIT_NPROC without a
	// cgroup (RLIMIT_NPROC counts the sidecar user's tasks).
	MemoryBytes uint64 `json:"memory_bytes"`
	Tasks       uint64 `json:"tasks"`
}

// RunChild is the helper's main: it only returns on failure.
func RunChild(_ []string, stderr io.Writer) int {
	raw := os.Getenv(SpecEnv)
	var s Spec
	if err := json.Unmarshal([]byte(raw), &s); err != nil || s.Binary == "" {
		fmt.Fprintln(stderr, "sidecar-exec: invalid specification")
		return 2
	}
	if err := execSandboxed(&s); err != nil {
		fmt.Fprintln(stderr, "sidecar-exec:", err)
		return 1
	}
	return 0
}

// ErrUnsupported: this platform cannot isolate a sidecar.
var ErrUnsupported = errors.New("sidecars need Linux")
