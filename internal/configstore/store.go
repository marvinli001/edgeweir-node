// Package configstore persists the last-known-good (LKG) NodeConfig so the
// node keeps serving its last applied configuration across restarts, even
// when the console is unreachable.
//
// Layout (inside <state-dir>/config):
//
//	current.binpb   the applied configuration (binary protobuf)
//	previous.binpb  the configuration applied before it (backup)
//
// Writes are atomic (temp file + fsync + rename + dir fsync). Load verifies
// the content hash and falls back to the backup if current is corrupt.
package configstore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	"github.com/edgeweir/edgeweir-node/internal/configir"
	"github.com/edgeweir/edgeweir-node/internal/fsutil"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// File names inside the store directory.
const (
	CurrentFile  = "current.binpb"
	PreviousFile = "previous.binpb"
)

// ErrNoConfig is returned by Load when no configuration has been saved.
var ErrNoConfig = errors.New("no last-known-good configuration")

// Store is a directory holding the LKG configuration.
type Store struct {
	Dir string
}

// Save persists cfg as the current configuration and keeps the former
// current file as the backup.
func (s Store) Save(cfg *nodev1.NodeConfig) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	cur := filepath.Join(s.Dir, CurrentFile)
	if old, err := os.ReadFile(cur); err == nil {
		if err := fsutil.WriteFileAtomic(filepath.Join(s.Dir, PreviousFile), old, 0o600); err != nil {
			return fmt.Errorf("write backup: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return fsutil.WriteFileAtomic(cur, data, 0o600)
}

// Load returns the current configuration, or the backup if the current
// file is missing or fails verification. The second return value names the
// file that was used.
func (s Store) Load() (*nodev1.NodeConfig, string, error) {
	var errs []error
	for _, name := range []string{CurrentFile, PreviousFile} {
		cfg, err := s.loadFile(name)
		if err == nil {
			return cfg, name, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	if len(errs) == 0 {
		return nil, "", ErrNoConfig
	}
	return nil, "", errors.Join(append([]error{ErrNoConfig}, errs...)...)
}

func (s Store) loadFile(name string) (*nodev1.NodeConfig, error) {
	data, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return nil, err
	}
	cfg := &nodev1.NodeConfig{}
	if err := proto.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	if err := configir.VerifyHash(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
