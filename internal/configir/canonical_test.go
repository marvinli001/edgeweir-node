package configir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
)

var update = flag.Bool("update", false, "rewrite golden files")

// vectorConfig is the cross-language content hash test vector. The same
// message is stored as protojson in testdata/content_hash_vector.json so
// the console (protobuf-es) can assert the identical hash.
func vectorConfig() *nodev1.NodeConfig {
	return &nodev1.NodeConfig{
		Revision:    7,         // ignored by the hash
		ContentHash: "ignored", // ignored by the hash
		ClusterId:   "c1",
		Listeners: []*nodev1.Listener{
			{Port: 80, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTP},
		},
		CacheZones: []*nodev1.CacheZone{
			{Name: "default", MaxSizeMb: 1024, KeysZoneMb: 10, InactiveSeconds: 600},
		},
		Sites: []*nodev1.Site{{
			Id:      "s1",
			Name:    "demo",
			Enabled: true,
			Domains: []*nodev1.Domain{{Name: "demo.test"}},
			OriginPool: &nodev1.OriginPool{
				Id:     "p1",
				Policy: nodev1.LoadBalancePolicy_LOAD_BALANCE_POLICY_WEIGHTED_RANDOM,
				Origins: []*nodev1.Origin{{
					Id: "o1", Address: "whoami", Port: 80,
					Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1,
				}},
			},
			CacheRules: []*nodev1.CacheRule{{
				Id: "r1", Priority: 10,
				Match:              &nodev1.CacheRuleMatch{PathPrefixes: []string{"/"}},
				Action:             nodev1.CacheAction_CACHE_ACTION_CACHE,
				EdgeTtlSeconds:     60,
				OriginCacheControl: nodev1.OriginCacheControl_ORIGIN_CACHE_CONTROL_OVERRIDE,
			}},
			CacheZone:       "default",
			CacheGeneration: 1,
		}},
	}
}

// handEncoded builds the expected canonical bytes of vectorConfig field by
// field with protowire, independently of proto.Marshal, to pin the wire
// layout (field-number order, proto3 defaults omitted).
func handEncoded() []byte {
	str := func(b []byte, n protowire.Number, s string) []byte {
		b = protowire.AppendTag(b, n, protowire.BytesType)
		return protowire.AppendString(b, s)
	}
	vint := func(b []byte, n protowire.Number, v uint64) []byte {
		b = protowire.AppendTag(b, n, protowire.VarintType)
		return protowire.AppendVarint(b, v)
	}
	msg := func(b []byte, n protowire.Number, m []byte) []byte {
		b = protowire.AppendTag(b, n, protowire.BytesType)
		return protowire.AppendBytes(b, m)
	}

	var listener []byte
	listener = vint(listener, 1, 80)
	listener = vint(listener, 2, 1)

	var zone []byte
	zone = str(zone, 1, "default")
	zone = vint(zone, 2, 1024)
	zone = vint(zone, 3, 10)
	zone = vint(zone, 4, 600)

	var domain []byte
	domain = str(domain, 1, "demo.test")

	var origin []byte
	origin = str(origin, 1, "o1")
	origin = str(origin, 2, "whoami")
	origin = vint(origin, 3, 80)
	origin = vint(origin, 4, 1)
	origin = vint(origin, 5, 1)

	var pool []byte
	pool = str(pool, 1, "p1")
	pool = vint(pool, 2, 1)
	pool = msg(pool, 3, origin)

	var match []byte
	match = str(match, 1, "/")

	var rule []byte
	rule = str(rule, 1, "r1")
	rule = vint(rule, 2, 10)
	rule = msg(rule, 3, match)
	rule = vint(rule, 4, 1)
	rule = vint(rule, 5, 60)
	rule = vint(rule, 6, 1)

	var site []byte
	site = str(site, 1, "s1")
	site = str(site, 2, "demo")
	site = vint(site, 3, 1)
	site = msg(site, 4, domain)
	site = msg(site, 5, pool)
	site = msg(site, 6, rule)
	site = str(site, 7, "default")
	site = vint(site, 8, 1)

	var cfg []byte
	cfg = str(cfg, 3, "c1")
	cfg = msg(cfg, 4, listener)
	cfg = msg(cfg, 5, zone)
	cfg = msg(cfg, 6, site)
	return cfg
}

// Expected hash of the test vector. If this changes, the wire format or
// canonicalization changed and the console must be updated in lockstep.
const vectorHash = "e08d8586cc3b832c54d536dd5faadc87b1afe26be7e47ee8194e450ee1e2867e"

type hashVector struct {
	Description  string          `json:"description"`
	Config       json.RawMessage `json:"config"`
	CanonicalHex string          `json:"canonical_hex"`
	ContentHash  string          `json:"content_hash"`
}

func TestContentHashVector(t *testing.T) {
	cfg := vectorConfig()
	b, err := CanonicalBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := handEncoded()
	if hex.EncodeToString(b) != hex.EncodeToString(want) {
		t.Fatalf("canonical bytes differ from hand encoding\n got %x\nwant %x", b, want)
	}
	sum := sha256.Sum256(want)
	if hex.EncodeToString(sum[:]) != vectorHash {
		t.Fatalf("sha256(hand encoding) = %x, want %s", sum, vectorHash)
	}
	got, err := ContentHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != vectorHash {
		t.Fatalf("ContentHash = %s, want %s", got, vectorHash)
	}

	// The golden JSON is what the console repository can load with
	// protobuf-es (fromJson) to assert the same hash.
	path := filepath.Join("testdata", "content_hash_vector.json")
	if *update {
		cj, err := protojson.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		v := hashVector{
			Description:  "NodeConfig content_hash test vector: sha256(deterministic binary encoding with revision=0 and content_hash=\"\") after canonical sorting",
			Config:       cj,
			CanonicalHex: hex.EncodeToString(want),
			ContentHash:  vectorHash,
		}
		out, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read vector (run with -update to create): %v", err)
	}
	var v hashVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	fromJSON := &nodev1.NodeConfig{}
	if err := protojson.Unmarshal(v.Config, fromJSON); err != nil {
		t.Fatal(err)
	}
	h, err := ContentHash(fromJSON)
	if err != nil {
		t.Fatal(err)
	}
	if h != v.ContentHash || h != vectorHash {
		t.Fatalf("hash of golden JSON config = %s, golden says %s, want %s", h, v.ContentHash, vectorHash)
	}
	if v.CanonicalHex != hex.EncodeToString(want) {
		t.Fatal("golden canonical_hex is stale")
	}
}

func TestCanonicalizeOrdering(t *testing.T) {
	cfg := &nodev1.NodeConfig{
		Listeners:    []*nodev1.Listener{{Port: 8080}, {Port: 80}},
		CacheZones:   []*nodev1.CacheZone{{Name: "b"}, {Name: "a"}},
		Certificates: []*nodev1.CertificateRef{{Id: "c2"}, {Id: "c1"}},
		Sites: []*nodev1.Site{
			{
				Id:         "s2",
				Domains:    []*nodev1.Domain{{Name: "z.test"}, {Name: "a.test"}},
				OriginPool: &nodev1.OriginPool{Origins: []*nodev1.Origin{{Id: "o2"}, {Id: "o1"}}},
				CacheRules: []*nodev1.CacheRule{
					{Id: "r3", Priority: 2},
					{Id: "r2", Priority: 1},
					{Id: "r1", Priority: 2},
				},
			},
			{Id: "s1"},
		},
	}
	Canonicalize(cfg)
	if cfg.Listeners[0].Port != 80 || cfg.CacheZones[0].Name != "a" || cfg.Certificates[0].Id != "c1" || cfg.Sites[0].Id != "s1" {
		t.Fatalf("top-level ordering wrong: %v", cfg)
	}
	s := cfg.Sites[1]
	if s.Domains[0].Name != "a.test" || s.OriginPool.Origins[0].Id != "o1" {
		t.Fatalf("site ordering wrong: %v", s)
	}
	var ids []string
	for _, r := range s.CacheRules {
		ids = append(ids, r.Id)
	}
	if want := []string{"r2", "r1", "r3"}; !equalStrings(ids, want) {
		t.Fatalf("cache rule order = %v, want %v", ids, want)
	}
}

func TestContentHashIndependentOfOrderAndRevision(t *testing.T) {
	a := vectorConfig()
	b := vectorConfig()
	b.Revision = 99
	b.ContentHash = "something else"
	b.Listeners = append(b.Listeners, &nodev1.Listener{Port: 8080})
	a.Listeners = append([]*nodev1.Listener{{Port: 8080}}, a.Listeners...)
	ha, _ := ContentHash(a)
	hb, _ := ContentHash(b)
	if ha != hb {
		t.Fatalf("hash depends on order or revision: %s vs %s", ha, hb)
	}
	// ContentHash must not mutate its input.
	if a.Listeners[0].Port != 8080 {
		t.Fatal("ContentHash reordered its input")
	}
	b.Sites[0].CacheGeneration = 2
	hc, _ := ContentHash(b)
	if hc == hb {
		t.Fatal("hash did not change with content")
	}
}

func TestVerifyHash(t *testing.T) {
	cfg := vectorConfig()
	cfg.ContentHash = vectorHash
	if err := VerifyHash(cfg); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	cfg.ContentHash = "00" + vectorHash[2:]
	if err := VerifyHash(cfg); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("err = %v, want ErrHashMismatch", err)
	}
	cfg.ContentHash = ""
	if err := VerifyHash(cfg); !errors.Is(err, ErrHashMismatch) {
		t.Fatalf("missing hash: err = %v, want ErrHashMismatch", err)
	}
}

func TestEmptyConfigHash(t *testing.T) {
	h, err := ContentHash(nil)
	if err != nil {
		t.Fatal(err)
	}
	// sha256 of the empty string: an empty NodeConfig encodes to zero bytes.
	if h != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty config hash = %s", h)
	}
	_ = proto.Size(&nodev1.NodeConfig{})
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
