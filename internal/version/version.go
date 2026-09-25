// Package version exposes build metadata injected at link time.
//
// Release builds set these with:
//
//	-ldflags "-X github.com/edgeweir/edgeweir-node/internal/version.Version=... \
//	          -X github.com/edgeweir/edgeweir-node/internal/version.Commit=... \
//	          -X github.com/edgeweir/edgeweir-node/internal/version.Date=..."
package version

import (
	"fmt"
	"runtime"
)

// These variables are overwritten by the linker in release builds.
var (
	// Version is the semantic version of the agent, "dev" for local builds.
	Version = "dev"
	// Commit is the full git commit hash the binary was built from.
	Commit = "none"
	// Date is the commit date (RFC 3339) of the build, kept stable for
	// reproducible builds.
	Date = "unknown"
)

// String returns a single human-readable line describing the build.
func String() string {
	return fmt.Sprintf("edgeweir-node %s (commit %s, built %s, %s %s/%s)",
		Version, Commit, Date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
