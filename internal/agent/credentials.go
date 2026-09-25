package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"connectrpc.com/connect"

	"github.com/edgeweir/edgeweir-node/internal/configir"
	"github.com/edgeweir/edgeweir-node/internal/fsutil"
	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// credentialsFile keeps the S3 credentials of the current configuration so
// that the node can serve S3 origins after a restart while the console is
// unreachable. Same protection as the node's private key: 0600 in the
// state directory (0700).
const credentialsFile = "credentials.json"

type storedCredential struct {
	ID        string `json:"id"`
	Version   uint64 `json:"version"`
	AccessKey string `json:"access_key"`
	SecretKey string `json:"secret_key"`
}

func (a *Agent) credentialsPath() string { return filepath.Join(a.cfg.StateDir, credentialsFile) }

// loadCredentials reads the persisted credentials (missing file: none).
func (a *Agent) loadCredentials() {
	raw, err := os.ReadFile(a.credentialsPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("cannot read stored origin credentials", "err", err)
		}
		return
	}
	var list []storedCredential
	if err := json.Unmarshal(raw, &list); err != nil {
		a.log.Warn("ignoring unreadable origin credentials file", "err", err)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range list {
		a.creds[c.ID] = configir.Credential{Version: c.Version, AccessKey: c.AccessKey, SecretKey: c.SecretKey}
	}
}

// saveCredentialsLocked persists the credentials; a.mu must be held.
func (a *Agent) saveCredentialsLocked() error {
	list := make([]storedCredential, 0, len(a.creds))
	for id, c := range a.creds {
		list = append(list, storedCredential{ID: id, Version: c.Version, AccessKey: c.AccessKey, SecretKey: c.SecretKey})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(a.credentialsPath(), raw, 0o600)
}

// ensureCredentials fetches every credential the plan references that is
// missing or older than required, over the mTLS channel, and forgets the
// ones no longer referenced. Transport errors are returned (the apply is
// retried); credentials the console does not hand out are left missing and
// their origins are dropped by AttachCredentials.
func (a *Agent) ensureCredentials(ctx context.Context, plan *configir.Plan) error {
	refs := plan.CredentialRefs()
	a.mu.Lock()
	var missing []string
	for id, version := range refs {
		if c, ok := a.creds[id]; !ok || c.Version < version {
			missing = append(missing, id)
		}
	}
	a.mu.Unlock()
	sort.Strings(missing)

	if len(missing) > 0 && a.channel != nil {
		cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
		resp, err := a.channel.Client().GetOriginCredentials(cctx, connect.NewRequest(&nodev1.GetOriginCredentialsRequest{Ids: missing}))
		cancel()
		if err != nil {
			return fmt.Errorf("fetch origin credentials: %w", err)
		}
		a.mu.Lock()
		for _, c := range resp.Msg.GetCredentials() {
			a.creds[c.GetId()] = configir.Credential{Version: c.GetVersion(), AccessKey: c.GetAccessKeyId(), SecretKey: c.GetSecretAccessKey()}
		}
		a.mu.Unlock()
		a.log.Info("origin credentials fetched", "requested", len(missing), "received", len(resp.Msg.GetCredentials()))
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	changed := len(missing) > 0
	for id := range a.creds {
		if _, used := refs[id]; !used {
			delete(a.creds, id)
			changed = true
		}
	}
	if changed {
		if err := a.saveCredentialsLocked(); err != nil {
			a.log.Warn("cannot persist origin credentials", "err", err)
		}
	}
	return nil
}

// attachCredentials fills the plan's S3 origins from the stored credentials.
func (a *Agent) attachCredentials(plan *configir.Plan) {
	a.mu.Lock()
	creds := make(map[string]configir.Credential, len(a.creds))
	for id, c := range a.creds {
		creds[id] = c
	}
	a.mu.Unlock()
	plan.AttachCredentials(creds)
}
