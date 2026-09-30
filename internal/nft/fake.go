package nft

import (
	"context"
	"slices"
	"strings"
	"sync"
)

// Fake is an Executor for tests: it records every script and fails the
// scripts Fail selects.
type Fake struct {
	mu      sync.Mutex
	scripts []string
	// Fail, when set, decides whether a script fails (and with what).
	Fail func(script string) error
}

// Run implements Executor.
func (f *Fake) Run(_ context.Context, script string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, script)
	if f.Fail != nil {
		return f.Fail(script)
	}
	return nil
}

// Scripts returns the scripts run so far.
func (f *Fake) Scripts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.scripts)
}

// Last returns the last script whose text contains substr ("" if none).
func (f *Fake) Last(substr string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := len(f.scripts) - 1; i >= 0; i-- {
		if strings.Contains(f.scripts[i], substr) {
			return f.scripts[i]
		}
	}
	return ""
}
