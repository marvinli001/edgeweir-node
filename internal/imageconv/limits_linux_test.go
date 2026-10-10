//go:build linux

package imageconv

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestLimitSelf runs limitSelf in a child (it changes the process for good)
// and reads what the kernel reports: no capabilities in any set (on every
// thread, or on the conversion's thread for builds whose runtime counts as
// cgo) and the resource limits.
func TestLimitSelf(t *testing.T) {
	if os.Getenv("IMAGECONV_LIMIT_CHILD") == "1" {
		if err := limitSelf(64 << 20); err != nil {
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
	cmd.Env = append(os.Environ(), "IMAGECONV_LIMIT_CHILD=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}
