//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLimitSelf runs Limit in a child (it changes the process for good)
// and reads what the kernel reports: no capabilities in any set (on every
// thread, or on the conversion's thread for builds whose runtime counts as
// cgo) and the resource limits.
func TestLimitSelf(t *testing.T) {
	if os.Getenv("SANDBOX_LIMIT_CHILD") == "1" {
		if err := Limit(64 << 20); err != nil {
			t.Fatal(err)
		}
		// Every thread in a release build; else the thread this goroutine
		// is now locked to, where the conversion runs.
		tasks, _ := filepath.Glob("/proc/self/task/*/status")
		if !droppedEveryThread {
			tasks = []string{"/proc/thread-self/status"}
		}
		for _, task := range tasks {
			status, err := os.ReadFile(task)
			if err != nil {
				t.Fatal(err)
			}
			for _, line := range strings.Split(string(status), "\n") {
				for _, set := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"} {
					if strings.HasPrefix(line, set) && strings.TrimSpace(strings.TrimPrefix(line, set)) != "0000000000000000" {
						t.Fatalf("%s: %s", task, line)
					}
				}
			}
		}
		limits, err := os.ReadFile("/proc/self/limits")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"Max data size", "Max file size", "Max open files", "Max core file size"} {
			for _, line := range strings.Split(string(limits), "\n") {
				if strings.HasPrefix(line, want) && strings.Contains(line, "unlimited") {
					t.Fatalf("still unlimited: %s", line)
				}
			}
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLimitSelf$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SANDBOX_LIMIT_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// TestLimitSelfNoNewPrivs runs Limit in a child and reads NoNewPrivs
// from the kernel: set on every thread (or on the conversion's thread for
// builds whose runtime counts as cgo), and still set in a process the child
// starts (it cannot be unset).
func TestLimitSelfNoNewPrivs(t *testing.T) {
	if os.Getenv("SANDBOX_NNP_CHILD") == "1" {
		if err := Limit(64 << 20); err != nil {
			t.Fatal(err)
		}
		tasks, _ := filepath.Glob("/proc/self/task/*/status")
		if !droppedEveryThread {
			tasks = []string{"/proc/thread-self/status"}
		}
		for _, task := range tasks {
			status, err := os.ReadFile(task)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(status), "\nNoNewPrivs:\t1\n") {
				t.Fatalf("%s: no_new_privs not set", task)
			}
		}
		// On the locked thread, so that the fallback's thread starts it.
		out, err := exec.Command("/bin/sh", "-c", "grep NoNewPrivs /proc/self/status").Output()
		if err != nil || strings.TrimSpace(string(out)) != "NoNewPrivs:\t1" {
			t.Fatalf("a process the child starts: %q %v", out, err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLimitSelfNoNewPrivs$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SANDBOX_NNP_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

// TestLimitSelfKeepsLowerLimits: a child without CAP_SYS_RESOURCE whose
// inherited data limit is below what Limit would set keeps the lower
// one instead of failing (every conversion would). The converters' children
// depend on it too: VmData grows between conversions.
func TestLimitSelfKeepsLowerLimits(t *testing.T) {
	if os.Getenv("SANDBOX_LOWER_CHILD") == "1" {
		if err := dropCapabilities(); err != nil {
			t.Fatal(err)
		}
		lower := dataInUse() + 32<<20
		if err := unix.Setrlimit(unix.RLIMIT_DATA, &unix.Rlimit{Cur: lower, Max: lower}); err != nil {
			t.Fatal(err)
		}
		if err := Limit(64 << 20); err != nil {
			t.Fatalf("Limit under a lower inherited limit: %v", err)
		}
		var got unix.Rlimit
		if err := unix.Getrlimit(unix.RLIMIT_DATA, &got); err != nil || got.Cur != lower || got.Max != lower {
			t.Fatalf("data limit %+v %v, want %d", got, err, lower)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLimitSelfKeepsLowerLimits$", "-test.count=1")
	cmd.Env = append(os.Environ(), "SANDBOX_LOWER_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
