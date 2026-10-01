//go:build !linux

package metrics

// defaultRoot is empty: other platforms report no metrics.
const defaultRoot = ""
