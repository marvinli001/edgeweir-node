package agent

import (
	"encoding/json"
	"errors"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"os"
	"path/filepath"
)

type revisionReceipt struct {
	Revision uint64 `json:"revision"`
	Hash     string `json:"hash"`
	Token    string `json:"token"`
}
type receiptFile struct {
	NodeID    string          `json:"node_id"`
	Active    revisionReceipt `json:"active"`
	Previous  revisionReceipt `json:"previous"`
	Candidate revisionReceipt `json:"candidate"`
}

func (a *Agent) receiptsPath() string { return filepath.Join(a.lkg.Dir, "receipts.json") }
func (a *Agent) readReceipts() receiptFile {
	var state receiptFile
	if a.channel == nil {
		return state
	}
	info, err := os.Stat(a.receiptsPath())
	if err != nil || info.Size() > 16384 {
		return state
	}
	raw, err := os.ReadFile(a.receiptsPath())
	if err != nil || json.Unmarshal(raw, &state) != nil {
		return receiptFile{}
	}
	if id := a.channel.Identity(); id == nil || state.NodeID != id.NodeID {
		return receiptFile{}
	}
	return state
}
func (s receiptFile) forConfig(revision uint64, hash string) revisionReceipt {
	for _, r := range []revisionReceipt{s.Candidate, s.Active, s.Previous} {
		if r.Revision == revision && r.Hash == hash && len(r.Token) <= 4096 {
			return r
		}
	}
	return revisionReceipt{}
}
func (a *Agent) receiptFor(revision uint64, hash string) string {
	return a.readReceipts().forConfig(revision, hash).Token
}

// Save before applying. Active and previous receipts remain available on a bad
// candidate/disk failure, and the supervisor backs this file up with the LKG.
func (a *Agent) rememberReceipt(resp *nodev1.GetConfigResponse) error {
	if resp.GetRevisionReceipt() == "" {
		return nil
	} // Older consoles remain usable.
	if len(resp.RevisionReceipt) > 4096 {
		return errors.New("configuration receipt exceeds limit")
	}
	var revision uint64
	var hash string
	if c := resp.GetSnapshot(); c != nil {
		revision = c.Revision
		hash = c.ContentHash
	} else if d := resp.GetDiff(); d != nil {
		revision = d.Revision
		hash = d.ContentHash
	} else {
		return nil
	}
	state := a.readReceipts()
	current := a.appliedConfig()
	active := state.forConfig(current.GetRevision(), current.GetContentHash())
	if active.Token != "" {
		if active.Revision != state.Active.Revision {
			state.Previous = state.Active
		}
		state.Active = active
	}
	if state.NodeID == "" {
		state.NodeID = a.channel.Identity().NodeID
	}
	state.Candidate = revisionReceipt{Revision: revision, Hash: hash, Token: resp.RevisionReceipt}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(a.lkg.Dir, 0700); err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(a.receiptsPath(), raw, 0600)
}
