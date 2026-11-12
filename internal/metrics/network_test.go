package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNetworkExactCounters(t *testing.T) {
	raw := "lo: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0\neth0: 18446744073709551000 0 0 0 0 0 0 0 9007199254740993 0 0 0 0 0 0 0\n"
	values, err := ParseNetwork(strings.NewReader(raw), func(name string) bool { return name == "lo" })
	if err != nil || len(values) != 1 {
		t.Fatalf("counters=%v err=%v", values, err)
	}
	if values[0].BytesReceived != 18446744073709551000 || values[0].BytesSent != 9007199254740993 {
		t.Fatalf("precision lost: %v", values[0])
	}
	root := t.TempDir()
	if err = os.MkdirAll(filepath.Join(root, "sys/kernel/random"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(root, "net"), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "sys/kernel/random/boot_id"), []byte("11111111-1111-4111-8111-111111111111\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "net/dev"), []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	c := &Collector{Root: root}
	at := time.Now()
	snapshot, err := c.readNetwork(at, func(name string) bool { return name == "lo" })
	if err != nil || snapshot.BootId != "11111111-1111-4111-8111-111111111111" || !snapshot.SampledAt.AsTime().Equal(at) {
		t.Fatalf("snapshot=%v err=%v", snapshot, err)
	}
	if err = os.Remove(filepath.Join(root, "net/dev")); err != nil {
		t.Fatal(err)
	}
	if snapshot, err = c.readNetwork(at, func(string) bool { return false }); err == nil || snapshot != nil {
		t.Fatalf("missing data became zero: %v %v", snapshot, err)
	}
}

func TestNetworkRejectsBrokenCounters(t *testing.T) {
	for _, raw := range []string{"eth0: 1 2 3\n", "eth0: x 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n", "eth0: 1 0 0 0 0 0 0 0 -1 0 0 0 0 0 0 0\n"} {
		if _, err := ParseNetwork(strings.NewReader(raw), func(string) bool { return false }); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
