package main

import (
	"regexp"
	"strings"
	"testing"
)

// The node image builds edgeweir-openresty itself (compose builds it from
// this repository alone) with the same stages as the packages: the blocks
// between the openresty-build markers of both Dockerfiles must be equal,
// so that the image and the packages hold the same OpenResty and BuildKit
// builds it once.
func TestOpenRestyBuildStagesMatch(t *testing.T) {
	block := regexp.MustCompile(`(?s)# BEGIN openresty-build\n.*# END openresty-build\n`)
	image := block.FindString(readDoc(t, "Dockerfile"))
	packages := block.FindString(readDoc(t, "packaging/openresty/Dockerfile"))
	if image == "" || packages == "" {
		t.Fatal("openresty-build markers missing")
	}
	if image != packages {
		t.Fatalf("the openresty-build stages differ between Dockerfile and packaging/openresty/Dockerfile\n--- Dockerfile ---\n%s\n--- packaging/openresty/Dockerfile ---\n%s", image, packages)
	}
	// Both build from the same pinned builder image.
	arg := regexp.MustCompile(`(?m)^ARG OPENRESTY_BUILDER_IMAGE=(\S+)$`)
	a, b := arg.FindStringSubmatch(readDoc(t, "Dockerfile")), arg.FindStringSubmatch(readDoc(t, "packaging/openresty/Dockerfile"))
	if a == nil || b == nil || a[1] != b[1] || !strings.Contains(a[1], "@sha256:") {
		t.Fatalf("OPENRESTY_BUILDER_IMAGE differs or is not pinned: %v %v", a, b)
	}
}
