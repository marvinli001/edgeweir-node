package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// releaseTags are the build tags of every release build (ADR-0043): the
// WebP / AVIF encoders as transpiled Go only.
const releaseTags = "nodynamic,wasm2go"

// TestReleaseBuildsUseTheImageTags: goreleaser, the Dockerfile and `make
// build` all build with the tags; without nodynamic the encoders would load
// system libraries, without wasm2go every conversion would compile
// WebAssembly first.
func TestReleaseBuildsUseTheImageTags(t *testing.T) {
	root := filepath.Join("..", "..")
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	if g := read(".goreleaser.yaml"); !strings.Contains(g, "    tags:\n      - nodynamic\n      - wasm2go\n") {
		t.Error(".goreleaser.yaml builds without the tags nodynamic and wasm2go")
	}
	if d := read("Dockerfile"); !strings.Contains(d, "go build -trimpath -tags "+releaseTags+" ") {
		t.Error("the Dockerfile builds edgeweir-node without -tags " + releaseTags)
	}
	if m := read("Makefile"); !strings.Contains(m, "GO_TAGS := "+releaseTags) || !strings.Contains(m, "go build -trimpath -tags $(GO_TAGS)") {
		t.Error("make build does not use the release tags")
	}
	for _, name := range []string{".goreleaser.yaml", "Dockerfile"} {
		if !strings.Contains(read(name), "NOTICE") {
			t.Errorf("%s does not ship NOTICE", name)
		}
	}
}

// TestNoticeListsTheBinarysModules: every module compiled into the release
// binary is in NOTICE with its version (scripts/notice.sh after go.mod
// changes), and so are the C libraries inside the WebP / AVIF encoders.
func TestNoticeListsTheBinarysModules(t *testing.T) {
	notice, err := os.ReadFile(filepath.Join("..", "..", "NOTICE"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "list", "-deps", "-tags", releaseTags, "-f", "{{with .Module}}{{if not .Main}}{{.Path}} {{.Version}}{{end}}{{end}}", ".")
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOFLAGS=-mod=mod")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	mods := strings.Fields(strings.TrimSpace(string(out)))
	if len(mods) < 2 {
		t.Fatalf("go list found no modules: %q", out)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if line != "" && !strings.Contains(string(notice), "  "+line+": ") {
			t.Errorf("NOTICE does not list %q: run scripts/notice.sh", line)
		}
	}
	for _, lib := range []string{"libwebp", "libavif", "aom", "dav1d", "libyuv"} {
		if !strings.Contains(string(notice), "\n"+lib+": LICENSE\n") {
			t.Errorf("NOTICE lacks the license text of %s", lib)
		}
	}
}
