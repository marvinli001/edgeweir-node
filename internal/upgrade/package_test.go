package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestTaskCannotChangeLocalSourceOrArtifactIdentity(t *testing.T) {
	trust := Trust{Source: DefaultSource}
	base := DefaultSource + "/v0.2.0/"
	task := Task{ID: "11111111-1111-4111-8111-111111111111", Version: "0.2.0", SHA256: strings.Repeat("a", 64), ArchiveURL: base + "edgeweir-node_0.2.0_linux_" + runtime.GOARCH + ".tar.gz", ChecksumsURL: base + "checksums.txt", SignatureURL: base + "checksums.txt.sigstore.json"}
	if _, err := trust.validate(task); err != nil {
		t.Fatal(err)
	}
	for _, alter := range []func(*Task){func(t *Task) { t.ArchiveURL = "http://169.254.169.254/metadata" }, func(t *Task) { t.ChecksumsURL = "https://attacker.test/checksums.txt" }, func(t *Task) { t.SignatureURL = base + "../keys.json" }, func(t *Task) { t.Version = "../../elsewhere" }, func(t *Task) { t.ID = "../../../../../../../../../../../../" }, func(t *Task) { t.SHA256 = "short" }} {
		next := task
		alter(&next)
		if _, err := trust.validate(next); err == nil {
			t.Fatalf("accepted altered task: %+v", next)
		}
	}
}
func TestExtractionRejectsTraversalLinksAndOversizedMembers(t *testing.T) {
	for _, header := range []*tar.Header{{Name: "release/../../outside", Mode: 0600}, {Name: "/absolute", Mode: 0600}, {Name: "release/lua/edgeweir/init.lua", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, {Name: "release/edgeweir-node", Size: 129 << 20, Mode: 0700}} {
		t.Run(header.Name+string(header.Typeflag), func(t *testing.T) {
			root := t.TempDir()
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(header); err != nil {
				t.Fatal(err)
			}
			_ = tw.Close()
			_ = gz.Close()
			archive := filepath.Join(root, "archive.tar.gz")
			if err := os.WriteFile(archive, buf.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			if err := extract(archive, filepath.Join(root, "unpacked"), "release"); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}
func TestSubprocessOutputCapCannotBeBypassedByReaderFrom(t *testing.T) {
	out := &cappedOutput{limit: 8}
	_, err := io.Copy(out, strings.NewReader(strings.Repeat("x", 1024)))
	if err != nil {
		t.Fatal(err)
	}
	if len(out.String()) != 8 {
		t.Fatal("output was not bounded")
	}
	if _, ok := any(out).(io.ReaderFrom); ok {
		t.Fatal("embedded ReaderFrom bypasses the limit")
	}
}
func TestSecondSupervisorCannotRollBackALiveTrial(t *testing.T) {
	opts, client := fixture(t)
	opts.StableWindow = 2 * time.Second
	opts.TrialTimeout = 6 * time.Second
	stop := launch(t, opts, client)
	defer stop()
	id := "44444444-4444-4444-8444-444444444444"
	if err := client.Stage(context.Background(), Task{ID: id, Version: "0.2.0"}); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(opts.Trust.StateDir, "upgrades", "state.json")
	wait(t, func() bool { raw, _ := os.ReadFile(state); return bytes.Contains(raw, []byte(`"phase":"trial"`)) })
	before, err := os.ReadFile(state)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = Run(ctx, opts); err == nil {
		t.Fatal("second supervisor acquired the live directory")
	}
	after, _ := os.ReadFile(state)
	if !bytes.Equal(before, after) {
		t.Fatal("second supervisor modified the live trial")
	}
	wait(t, func() bool { r, err := client.Result(context.Background()); return err == nil && r != nil && r.Success })
}
