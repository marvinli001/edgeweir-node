//go:build linux

package upgrade

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	"github.com/marvinli001/edgeweir-node/internal/sidecar"
	"github.com/marvinli001/edgeweir-node/internal/testutil/childproc"
	"golang.org/x/sys/unix"
)

func init() {
	inspectUpgradeChild = inspectLinuxUpgradeChild
}

func checkCapabilityStatus(raw []byte, want uint64) error {
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok && (key == "CapEff" || key == "CapPrm" || key == "CapInh" || key == "CapAmb") {
			n, err := strconv.ParseUint(strings.TrimSpace(value), 16, 64)
			if err != nil {
				return err
			}
			values[key] = n
		}
	}
	if len(values) != 4 || values["CapEff"] != want || values["CapPrm"] != want || values["CapInh"] != 0 || values["CapAmb"] != 0 {
		return fmt.Errorf("capabilities %v; want effective/permitted=%x and inheritable/ambient=0", values, want)
	}
	return nil
}

func inspectLinuxUpgradeChild() error {
	if os.Getenv("EDGEWEIR_UPGRADE_TEST_FILECAPS") != "1" {
		return nil
	}
	tasks, err := filepath.Glob("/proc/self/task/*/status")
	if err != nil {
		return err
	}
	for _, path := range tasks {
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := checkCapabilityStatus(raw, 0xe0); err != nil {
			return fmt.Errorf("agent thread %s: %w", path, err)
		}
	}
	// Like nginx and ordinary helpers: no capability bridge on this exec.
	raw, err := exec.Command("/bin/cat", "/proc/self/status").Output()
	if err != nil {
		return err
	}
	if err := checkCapabilityStatus(raw, 0); err != nil {
		return fmt.Errorf("ordinary child: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	spec, err := json.Marshal(sidecar.Spec{Binary: "/bin/cat", Args: []string{"/proc/self/status"}, Dir: "/tmp", UID: 10002, GID: 10002})
	if err != nil {
		return err
	}
	cmd := exec.Command(self, sidecar.ChildCommand)
	cmd.Env = []string{sidecar.SpecEnv + "=" + string(spec)}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := sidecar.InheritCapabilities(cmd); err != nil {
		return err
	}
	raw, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sidecar bootstrap: %w: %s", err, raw)
	}
	if !strings.Contains(string(raw), "Uid:\t10002\t10002\t10002\t10002") || !strings.Contains(string(raw), "NoNewPrivs:\t1") || !strings.Contains(string(raw), "Seccomp:\t2") {
		return fmt.Errorf("sidecar sandbox did not switch user and set no_new_privs/seccomp: %s", raw)
	}
	if err := checkCapabilityStatus(raw, 0); err != nil {
		return fmt.Errorf("sidecar executable: %w", err)
	}
	return nil
}

func TestLinuxFileCapabilityUpgradeAndRollback(t *testing.T) {
	if os.Getenv("EDGEWEIR_UPGRADE_TEST_FILECAPS") == "1" {
		// Exercise real copied candidates, successful commit, supervisor restart,
		// failed startup and rollback under the installed binary's filecaps.
		TestUpgradeResultSurvivesRestartAndFailedAckThenRollsBackStartupFailure(t)
		t.Run("legacy candidate is rejected before privileged exec", testLegacyCapabilityCandidate)
		t.Run("lost capabilities cannot report healthy", testLostCapabilityHealth)
		return
	}
	if os.Geteuid() != 0 || !sidecar.CapabilityHandoffSupported() {
		t.Skip("requires Linux root and a non-cgo test binary to seed real filecaps")
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		t.Fatal(err)
	}
	const setupCaps = 0xe0 | 1<<unix.CAP_SETFCAP
	if data[0].Effective&setupCaps != setupCaps {
		t.Skip("requires CAP_SETFCAP, CAP_KILL, CAP_SETGID and CAP_SETUID to seed deployment")
	}
	dir, err := os.MkdirTemp("", "ew-filecaps-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(dir, "edgeweir-node")
	if err := os.WriteFile(base, raw, 0755); err != nil {
		t.Fatal(err)
	}
	var caps [20]byte
	binary.LittleEndian.PutUint32(caps[:4], 0x02000001)
	binary.LittleEndian.PutUint32(caps[4:8], 0xe0)
	if err := unix.Setxattr(base, "security.capability", caps[:], 0); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(childproc.Context(t), base, "-test.run=^TestLinuxFileCapabilityUpgradeAndRollback$", "-test.v", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), "EDGEWEIR_UPGRADE_TEST_FILECAPS=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 10001, Gid: 10001}}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("filecap deployment: %v\n%s", err, out)
	} else {
		t.Logf("%s", out)
	}
}

func testLegacyCapabilityCandidate(t *testing.T) {
	opts, client := fixture(t)
	prepare := opts.prepare
	probeStatus := filepath.Join(opts.Trust.StateDir, "legacy-probe-status")
	privilegedStart := filepath.Join(opts.Trust.StateDir, "legacy-run-started")
	opts.prepare = func(ctx context.Context, trust Trust, task Task) (Bundle, error) {
		b, err := prepare(ctx, trust, task)
		if err != nil {
			return b, err
		}
		legacy := "#!/bin/sh\nif [ \"$1\" = version ]; then\n/bin/cat /proc/self/status > " + probeStatus + "\necho 'edgeweir-node 1.7.0'\nexit 0\nfi\ntouch " + privilegedStart + "\nexit 1\n"
		err = fsutil.WriteFileAtomic(filepath.Join(b.Dir, "edgeweir-node"), []byte(legacy), 0700)
		return b, err
	}
	stop := launch(t, opts, client)
	id := "88888888-8888-4888-8888-888888888888"
	if err := client.Stage(context.Background(), Task{ID: id, Version: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	wait(t, func() bool {
		r, err := client.Result(context.Background())
		return err == nil && r != nil && r.TaskID == id
	})
	r, err := client.Result(context.Background())
	if err != nil || r.Success || !r.RolledBack || !strings.Contains(r.Message, "safe sidecar capability handoff") {
		t.Fatalf("legacy candidate did not preserve the previous agent: %+v %v", r, err)
	}
	if _, err := os.Stat(privilegedStart); !os.IsNotExist(err) {
		t.Fatalf("legacy candidate reached privileged run: %v", err)
	}
	raw, err := os.ReadFile(probeStatus)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCapabilityStatus(raw, 0); err != nil {
		t.Fatalf("legacy query received agent privileges: %v", err)
	}
	stop()
}

func testLostCapabilityHealth(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	s := &Supervisor{child: cmd, healthPID: cmd.Process.Pid}
	body := fmt.Sprintf(`{"pid":%d,"version":"0.1.0","healthy":true}`, cmd.Process.Pid)
	w := logsCall(t, s, http.MethodPost, "/health", body)
	if w.Code != http.StatusServiceUnavailable || !s.healthFirst.IsZero() || !s.healthLast.IsZero() {
		t.Fatalf("missing capabilities counted as healthy: status=%d body=%s", w.Code, w.Body.String())
	}
}
