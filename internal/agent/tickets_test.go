package agent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// ticketSecret is an 80-byte key that names its id.
func ticketSecret(id string) []byte { return bytes.Repeat([]byte(id[len(id)-1:]), 80) }

// ticketConfig has an HTTPS listener and the ticket keys next, current,
// previous (any of them may be "").
func ticketConfig(next, current, previous string) *nodev1.NodeConfig {
	c := baseConfig(demoSite("site-t", "t.test"))
	c.Listeners = append(c.Listeners, &nodev1.Listener{Port: 443, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS})
	for role, id := range map[string]string{"next": next, "current": current, "previous": previous} {
		if id != "" {
			c.SessionTicketKeys = append(c.SessionTicketKeys, &nodev1.SessionTicketKeyRef{Id: id, Role: role})
		}
	}
	return c
}

func storedTicketKeyIDs(t *testing.T, stateDir string) []string {
	t.Helper()
	path := filepath.Join(stateDir, "session-ticket-keys.json")
	st, err := os.Stat(path)
	if err != nil {
		return nil
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("session-ticket-keys.json mode %v", st.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var list []struct {
		ID     string `json:"id"`
		Secret []byte `json:"secret"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, k := range list {
		if !bytes.Equal(k.Secret, ticketSecret(k.ID)) {
			t.Fatalf("stored secret of %s differs", k.ID)
		}
		ids = append(ids, k.ID)
	}
	return ids
}

// ticketLines returns the ticket key files nginx.conf names, in order, and
// whether it turns tickets off.
func ticketLines(t *testing.T, confPath string) ([]string, bool) {
	t.Helper()
	raw, err := os.ReadFile(confPath)
	if err != nil {
		return nil, false
	}
	var files []string
	for line := range strings.Lines(string(raw)) {
		if file, ok := strings.CutPrefix(strings.TrimSpace(line), "ssl_session_ticket_key "); ok {
			files = append(files, filepath.Base(strings.TrimSuffix(file, ";")))
		}
	}
	return files, strings.Contains(string(raw), "    ssl_session_tickets off;\n")
}

// keyFiles lists conf/tls-tickets, checking that every file holds its
// key's 80 bytes with mode 0600.
func keyFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		id := strings.TrimSuffix(e.Name(), ".key")
		if st.Mode().Perm() != 0o600 || len(raw) != 80 || !bytes.Equal(raw, ticketSecret(id)) {
			t.Fatalf("%s: mode %v, %d bytes", e.Name(), st.Mode().Perm(), len(raw))
		}
		out = append(out, e.Name())
	}
	return out
}

// TestSessionTicketKeys follows the cluster's ticket keys from
// GetSessionTicketKeys to disk and nginx.conf through two rotations: files
// of exactly 80 bytes (0600) written before the reload, named current,
// previous, next; stale files removed; keys the console does not hand out
// left out; the store pruned to what the current and previous
// configurations name; tickets off without keys.
func TestSessionTicketKeys(t *testing.T) {
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-t", ClusterID: "cl-t", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	for _, id := range []string{"t1", "t2", "t3", "t4"} {
		console.SetSessionTicketKey(id, ticketSecret(id))
	}
	rev := console.Publish(ticketConfig("t3", "t2", "t1"))
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	stop := startAgent(t, cfg, newFakeEngine(), dataplane.NewClient(dp.Socket))
	defer stop()
	console.AddToken("t-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "t-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	dir := filepath.Join(cfg.Render.Prefix, "conf", "tls-tickets")
	if files, off := ticketLines(t, cfg.ConfPath); off || !slices.Equal(files, []string{"t2.key", "t1.key", "t3.key"}) {
		t.Fatalf("nginx.conf ticket keys %v (off %v)", files, off)
	}
	if got := keyFiles(t, dir); !slices.Equal(got, []string{"t1.key", "t2.key", "t3.key"}) {
		t.Fatalf("key files %v", got)
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("key directory: %v", err)
	}
	if got := storedTicketKeyIDs(t, h.stateDir); !slices.Equal(got, []string{"t1", "t2", "t3"}) {
		t.Fatalf("stored keys %v", got)
	}
	if reqs := console.SessionTicketKeyRequests(); len(reqs) != 1 || !slices.Equal(reqs[0], []string{"t1", "t2", "t3"}) {
		t.Fatalf("GetSessionTicketKeys calls %v", reqs)
	}

	// Rotation: only the new next key is fetched; t1's file goes.
	rev = console.Publish(ticketConfig("t4", "t3", "t2"))
	eventually(t, "rotated", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if files, _ := ticketLines(t, cfg.ConfPath); !slices.Equal(files, []string{"t3.key", "t2.key", "t4.key"}) {
		t.Fatalf("nginx.conf ticket keys %v", files)
	}
	if got := keyFiles(t, dir); !slices.Equal(got, []string{"t2.key", "t3.key", "t4.key"}) {
		t.Fatalf("key files %v", got)
	}
	// The previous configuration still names t1.
	if got := storedTicketKeyIDs(t, h.stateDir); !slices.Equal(got, []string{"t1", "t2", "t3", "t4"}) {
		t.Fatalf("stored keys %v", got)
	}
	if reqs := console.SessionTicketKeyRequests(); len(reqs) != 2 || !slices.Equal(reqs[1], []string{"t4"}) {
		t.Fatalf("GetSessionTicketKeys calls %v", reqs)
	}

	// A key the console does not hand out is left out; the others serve.
	rev = console.Publish(ticketConfig("t5", "t4", "t3"))
	eventually(t, "rotated again", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if files, _ := ticketLines(t, cfg.ConfPath); !slices.Equal(files, []string{"t4.key", "t3.key"}) {
		t.Fatalf("nginx.conf ticket keys %v", files)
	}
	if got := storedTicketKeyIDs(t, h.stateDir); !slices.Equal(got, []string{"t2", "t3", "t4"}) {
		t.Fatalf("stored keys %v", got)
	}

	// No keys: no tickets, no files.
	rev = console.Publish(ticketConfig("", "", ""))
	eventually(t, "without keys", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if files, off := ticketLines(t, cfg.ConfPath); len(files) != 0 || !off {
		t.Fatalf("nginx.conf ticket keys %v (off %v)", files, off)
	}
	if got := keyFiles(t, dir); len(got) != 0 {
		t.Fatalf("key files %v", got)
	}
}
