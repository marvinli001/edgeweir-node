package configir

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v0150Vector reads testdata/content_hash_vector_v0150.json, a copy of the
// console's fixture (packages/config-compiler/test/fixtures): the M2
// vector plus three unsorted collection IP lists and three unsorted
// layer-4 applications (a TCP application accepting the PROXY protocol
// and sending v2 with every limit and both list kinds, a TCP application
// sending v1 with the extreme values of the ranges, a UDP application
// with a backup origin and a block list); application and origin ids
// beyond ASCII (U+FF01, U+1F600) whose UTF-8 byte order differs from
// UTF-16 order. Its canonical_hex and content_hash come from protobuf-es.
func v0150Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v0150.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v hashVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	cfg := &nodev1.NodeConfig{}
	if err := protojson.Unmarshal(v.Config, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, v
}

func l4AppByID(c *nodev1.NodeConfig, id string) *nodev1.L4App {
	for _, a := range c.GetL4Apps() {
		if a.GetId() == id {
			return a
		}
	}
	return nil
}

// TestContentHashVectorV0150 checks the proto v0.15.0 vector shared with
// the console: Go's canonical form of the unsorted configuration encodes
// to the console's canonical bytes and hash, applications and their
// origins sort by the bytes of their ids, list ids sort as sets, and every
// layer-4 field counts.
func TestContentHashVectorV0150(t *testing.T) {
	cfg, v := v0150Vector(t)
	var order []string
	for _, a := range cfg.L4Apps {
		order = append(order, a.GetId())
	}
	if !slices.Equal(order, []string{"\U0001F600-voice", "！-game", "db"}) {
		t.Fatalf("vector applications are already sorted: %q", order)
	}
	b, err := CanonicalBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h, err := ContentHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.CanonicalHex != hex.EncodeToString(b) {
		t.Fatalf("canonical bytes differ from the console\n got %x\nwant %s", b, v.CanonicalHex)
	}
	if v.ContentHash != h {
		t.Fatalf("vector hash %s, Go computes %s", v.ContentHash, h)
	}

	Canonicalize(cfg)
	order = nil
	for _, a := range cfg.L4Apps {
		order = append(order, a.GetId())
	}
	// Bytes: "db" < "！-game" (EF BC 81) < "😀-voice" (F0 9F 98 80); UTF-16
	// order would put the emoji (surrogate D83D) before U+FF01.
	if want := []string{"db", "！-game", "\U0001F600-voice"}; !slices.Equal(order, want) {
		t.Errorf("canonical application order %q, want %q", order, want)
	}
	game := l4AppByID(cfg, "！-game")
	var origins []string
	for _, o := range game.GetOrigins() {
		origins = append(origins, o.GetId())
	}
	if want := []string{"o1", "o！", "o\U0001F600"}; !slices.Equal(origins, want) {
		t.Errorf("canonical origin order %q, want %q", origins, want)
	}
	if !slices.Equal(game.GetAllowListIds(), []string{"l-a", "l-b"}) || !slices.Equal(game.GetBlockListIds(), []string{"l-c"}) {
		t.Errorf("canonical list ids %v %v", game.GetAllowListIds(), game.GetBlockListIds())
	}
	if hc, _ := ContentHash(cfg); hc != h {
		t.Fatalf("canonical config hashes to %s, want %s", hc, h)
	}

	// Every layer-4 field is part of the canonical bytes.
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"l4_apps":                    func(c *nodev1.NodeConfig) { c.L4Apps = nil },
		"protocol":                   func(c *nodev1.NodeConfig) { l4AppByID(c, "db").Protocol = nodev1.L4Protocol_L4_PROTOCOL_UDP },
		"port":                       func(c *nodev1.NodeConfig) { l4AppByID(c, "db").Port++ },
		"accept_proxy_protocol":      func(c *nodev1.NodeConfig) { l4AppByID(c, "！-game").AcceptProxyProtocol = false },
		"proxy_protocol_version":     func(c *nodev1.NodeConfig) { l4AppByID(c, "db").ProxyProtocolVersion = 0 },
		"origin address":             func(c *nodev1.NodeConfig) { l4AppByID(c, "db").Origins[0].Address = "other.example" },
		"origin port":                func(c *nodev1.NodeConfig) { l4AppByID(c, "db").Origins[0].Port++ },
		"origin weight":              func(c *nodev1.NodeConfig) { l4AppByID(c, "db").Origins[0].Weight++ },
		"origin backup":              func(c *nodev1.NodeConfig) { l4AppByID(c, "db").Origins[0].Backup = true },
		"max_fails":                  func(c *nodev1.NodeConfig) { l4AppByID(c, "db").MaxFails++ },
		"fail_timeout_seconds":       func(c *nodev1.NodeConfig) { l4AppByID(c, "db").FailTimeoutSeconds-- },
		"connect_timeout_ms":         func(c *nodev1.NodeConfig) { l4AppByID(c, "db").ConnectTimeoutMs++ },
		"idle_timeout_seconds":       func(c *nodev1.NodeConfig) { l4AppByID(c, "db").IdleTimeoutSeconds-- },
		"allow_list_ids":             func(c *nodev1.NodeConfig) { l4AppByID(c, "！-game").AllowListIds = nil },
		"block_list_ids":             func(c *nodev1.NodeConfig) { l4AppByID(c, "！-game").BlockListIds = nil },
		"max_connections":            func(c *nodev1.NodeConfig) { l4AppByID(c, "db").MaxConnections-- },
		"new_connections_per_second": func(c *nodev1.NodeConfig) { l4AppByID(c, "db").NewConnectionsPerSecond++ },
	} {
		c, _ := v0150Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	// The node takes only [A-Za-z0-9_-] ids (the console uses UUIDs): the
	// vector's ids beyond ASCII are refused, the same applications with
	// plain ids are accepted.
	if _, err := Build(cfg, Options{ClusterID: "c1"}); !errors.Is(err, ErrRejected) {
		t.Fatalf("ids beyond ASCII: err = %v, want rejection", err)
	}
	for _, a := range cfg.L4Apps {
		switch a.GetId() {
		case "！-game":
			a.Id = "game"
			for _, o := range a.Origins {
				o.Id = map[string]string{"o1": "o1", "o！": "o2", "o\U0001F600": "o3"}[o.GetId()]
			}
		case "\U0001F600-voice":
			a.Id = "voice"
		}
	}
	p, err := Build(cfg, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.L4Apps) != 3 || p.L4Apps[1].ID != "game" || !p.L4Apps[1].Relay() || p.L4Apps[1].MaxConnections != 1000 ||
		p.L4Apps[0].MaxConnections != 4294967295 || p.L4Apps[2].Protocol != L4UDP || len(p.L4Lists()) != 3 {
		t.Fatalf("plan applications %+v", p.L4Apps)
	}
}
