package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"connectrpc.com/connect"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/render"
)

// sessionTicketKeysFile keeps the TLS session ticket keys of the current
// and the previous configuration (secrets, 0600): a restart without the
// console renders the same keys.
const sessionTicketKeysFile = "session-ticket-keys.json"

// ticketKeySize is the size of an nginx ssl_session_ticket_key file with
// AES-256: 16 bytes key name, 32 bytes AES key, 32 bytes HMAC key.
const ticketKeySize = 80

func (a *Agent) ticketKeysPath() string { return filepath.Join(a.cfg.StateDir, sessionTicketKeysFile) }

func validTicketKey(id string, secret []byte) bool {
	return configir.ValidID(id) && len(secret) == ticketKeySize
}

// loadSessionTicketKeys reads the persisted keys (missing file: none).
func (a *Agent) loadSessionTicketKeys() {
	raw, err := os.ReadFile(a.ticketKeysPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("cannot read stored session ticket keys", "err", err)
		}
		return
	}
	var list []storedKey
	if err := json.Unmarshal(raw, &list); err != nil {
		a.log.Warn("ignoring unreadable session ticket keys file", "err", err)
		return
	}
	a.ticketMu.Lock()
	defer a.ticketMu.Unlock()
	for _, k := range list {
		if validTicketKey(k.ID, k.Secret) {
			a.ticketKeys[k.ID] = k.Secret
		}
	}
}

// saveSessionTicketKeysLocked persists the keys; ticketMu must be held.
func (a *Agent) saveSessionTicketKeysLocked() error {
	list := make([]storedKey, 0, len(a.ticketKeys))
	for id, secret := range a.ticketKeys {
		list = append(list, storedKey{ID: id, Secret: secret})
	}
	slices.SortFunc(list, func(x, y storedKey) int { return strings.Compare(x.ID, y.ID) })
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return fsutil.WriteFileAtomic(a.ticketKeysPath(), raw, 0o600)
}

// missingSessionTicketKeys returns the ids plan names that the node does
// not hold.
func (a *Agent) missingSessionTicketKeys(plan *configir.Plan) []string {
	a.ticketMu.Lock()
	defer a.ticketMu.Unlock()
	var missing []string
	for _, k := range plan.SessionTicketKeys {
		if _, ok := a.ticketKeys[k.ID]; !ok {
			missing = append(missing, k.ID)
		}
	}
	slices.Sort(missing)
	return missing
}

// ensureSessionTicketKeys fetches the keys plan names that the node does
// not hold (GetSessionTicketKeys over mTLS) and persists them, before
// nginx.conf is rendered. Transport errors are returned (the apply is
// retried); keys the console does not hand out stay missing, and the
// listeners use the others (no tickets without any).
func (a *Agent) ensureSessionTicketKeys(ctx context.Context, plan *configir.Plan) error {
	missing := a.missingSessionTicketKeys(plan)
	ch := a.connectedCh.Load()
	if len(missing) == 0 || ch == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, a.cfg.RPCTimeout)
	resp, err := ch.Client().GetSessionTicketKeys(cctx, connect.NewRequest(&nodev1.GetSessionTicketKeysRequest{Ids: missing}))
	cancel()
	if err != nil {
		return fmt.Errorf("fetch session ticket keys: %w", err)
	}
	a.ticketMu.Lock()
	defer a.ticketMu.Unlock()
	received := 0
	for _, k := range resp.Msg.GetKeys() {
		if !slices.Contains(missing, k.GetId()) || !validTicketKey(k.GetId(), k.GetSecret()) {
			a.log.Warn("ignoring a session ticket key the node did not ask for or that is not 80 bytes", "id", k.GetId())
			continue
		}
		a.ticketKeys[k.GetId()] = slices.Clone(k.GetSecret())
		received++
	}
	a.log.Info("session ticket keys fetched", "requested", len(missing), "received", received)
	if received > 0 {
		if err := a.saveSessionTicketKeysLocked(); err != nil {
			return fmt.Errorf("persist session ticket keys: %w", err)
		}
	}
	return nil
}

// attachSessionTicketKeys names the keys the HTTPS listeners use: the
// plan's keys the node holds, current first (it encrypts), then previous
// and next.
func (a *Agent) attachSessionTicketKeys(plan *configir.Plan) {
	a.ticketMu.Lock()
	defer a.ticketMu.Unlock()
	plan.TicketKeys = nil
	for _, id := range plan.SessionTicketKeyIDs() {
		if _, ok := a.ticketKeys[id]; ok {
			plan.TicketKeys = append(plan.TicketKeys, id)
		}
	}
	if missing := len(plan.SessionTicketKeys) - len(plan.TicketKeys); missing > 0 {
		a.log.Warn("session ticket keys missing; the HTTPS listeners use the others", "missing", missing, "held", len(plan.TicketKeys))
	}
}

func (a *Agent) ticketKeyDir() string {
	return filepath.Dir(render.TicketKeyPath(a.cfg.Render.Prefix, "x"))
}

// writeTicketKeyFiles writes the key files plan's nginx.conf names (80
// bytes each, 0600) before `openresty -t` reads them. nginx reads them
// only when it loads a configuration: the file names follow the key ids,
// so a rotation changes nginx.conf and reloads.
func (a *Agent) writeTicketKeyFiles(plan *configir.Plan) error {
	if len(plan.TicketKeys) == 0 {
		return nil
	}
	dir := a.ticketKeyDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create session ticket key directory: %w", err)
	}
	a.ticketMu.Lock()
	defer a.ticketMu.Unlock()
	for _, id := range plan.TicketKeys {
		secret, ok := a.ticketKeys[id]
		if !ok {
			return fmt.Errorf("session ticket key %s missing", id)
		}
		path := render.TicketKeyPath(a.cfg.Render.Prefix, id)
		if old, err := os.ReadFile(path); err == nil && bytes.Equal(old, secret) {
			if info, err := os.Stat(path); err == nil && info.Mode().Perm() == 0o600 {
				continue
			}
		}
		if err := fsutil.WriteFileAtomic(path, secret, 0o600); err != nil {
			return fmt.Errorf("write session ticket key: %w", err)
		}
	}
	return nil
}

// removeStaleTicketKeyFiles deletes the key files the installed nginx.conf
// no longer names (after it loaded; a restored previous file still finds
// its keys until then).
func (a *Agent) removeStaleTicketKeyFiles(plan *configir.Plan) {
	entries, err := os.ReadDir(a.ticketKeyDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ".key")
		if ok && slices.Contains(plan.TicketKeys, id) {
			continue
		}
		if err := os.Remove(filepath.Join(a.ticketKeyDir(), e.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
			a.log.Warn("cannot remove a stale session ticket key file", "file", e.Name(), "err", err)
		}
	}
}

// pruneSessionTicketKeys forgets keys that neither the current nor the
// previous configuration (of the same cluster) names.
func (a *Agent) pruneSessionTicketKeys(current, previous *nodev1.NodeConfig) {
	keep := map[string]bool{}
	for _, config := range []*nodev1.NodeConfig{current, previous} {
		if config == nil || config.GetClusterId() != current.GetClusterId() {
			continue
		}
		for _, k := range config.GetSessionTicketKeys() {
			keep[k.GetId()] = true
		}
	}
	a.ticketMu.Lock()
	defer a.ticketMu.Unlock()
	changed := false
	for id := range a.ticketKeys {
		if !keep[id] {
			delete(a.ticketKeys, id)
			changed = true
		}
	}
	if changed {
		if err := a.saveSessionTicketKeysLocked(); err != nil {
			a.log.Warn("session ticket key cleanup will retry", "err", err)
		}
	}
}
