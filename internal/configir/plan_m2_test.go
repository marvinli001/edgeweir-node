package configir

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/edgeweir/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func m2VectorConfig(t *testing.T) *nodev1.NodeConfig {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_m2.json"))
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
	return cfg
}

func TestBuildDefaultsForPhase0Configs(t *testing.T) {
	p, err := Build(vectorConfig(), Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	s := p.Sites[0]
	if !s.TLSVerify || !s.WebSocket || s.Slice {
		t.Fatalf("defaults: tls_verify=%v websocket=%v slice=%v", s.TLSVerify, s.WebSocket, s.Slice)
	}
	if s.Health != (HealthCheck{MaxFails: 3, RecoverySeconds: 30}) {
		t.Fatalf("health = %+v", s.Health)
	}
	want := Connection{ConnectTimeoutMS: 10_000, SendTimeoutMS: 60_000, ReadTimeoutMS: 60_000, Keepalive: true, KeepaliveIdle: 60, KeepaliveRequests: 1000}
	if s.Conn != want {
		t.Fatalf("conn = %+v", s.Conn)
	}
	if !reflect.DeepEqual(s.CacheKey, CacheKey{Query: QueryAll}) {
		t.Fatalf("cache key = %+v", s.CacheKey)
	}
	if refs := p.CredentialRefs(); len(refs) != 0 {
		t.Fatalf("credential refs = %v", refs)
	}
}

func TestBuildM2Fields(t *testing.T) {
	cfg := m2VectorConfig(t)
	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Warnings) != 0 {
		t.Fatalf("warnings: %v", p.Warnings)
	}
	var bucket *Site
	for i := range p.Sites {
		if p.Sites[i].ID == "s2" {
			bucket = &p.Sites[i]
		}
	}
	if bucket == nil {
		t.Fatal("site s2 missing")
	}
	if bucket.LoadBalance != LBConsistent || bucket.TLSVerify || bucket.WebSocket || !bucket.Slice {
		t.Fatalf("site flags = %+v", bucket)
	}
	if bucket.Health != (HealthCheck{MaxFails: 2, RecoverySeconds: 15}) {
		t.Fatalf("health = %+v", bucket.Health)
	}
	if bucket.Conn != (Connection{ConnectTimeoutMS: 1500, SendTimeoutMS: 60000, ReadTimeoutMS: 90000, Keepalive: false, KeepaliveIdle: 30, KeepaliveRequests: 500}) {
		t.Fatalf("conn = %+v", bucket.Conn)
	}
	wantKey := CacheKey{Query: QueryInclude, QueryParams: []string{"lang", "v"}, SortQuery: true, Headers: []string{"accept-language"}, Cookies: []string{"ab"}, Device: true, ExcludeHost: true}
	if !reflect.DeepEqual(bucket.CacheKey, wantKey) {
		t.Fatalf("cache key = %+v", bucket.CacheKey)
	}
	var s3 *S3Auth
	for _, o := range bucket.Origins {
		if o.ID == "o3" {
			s3 = o.S3
		}
		if o.ID == "o2" && (o.SNI != "origin.example.com" || o.HostHeader != "www.example.com" || !o.Backup) {
			t.Fatalf("origin o2 = %+v", o)
		}
	}
	if s3 == nil || *s3 != (S3Auth{Region: "us-east-1", Bucket: "media", CredentialID: "cred-1", CredentialVersion: 2}) {
		t.Fatalf("s3 = %+v", s3)
	}
	if refs := p.CredentialRefs(); !reflect.DeepEqual(refs, map[string]uint64{"cred-1": 2}) {
		t.Fatalf("credential refs = %v", refs)
	}
	// Rules keep (priority, id) order: r2 (10) before r3 (20).
	r2, r3 := bucket.CacheRules[0], bucket.CacheRules[1]
	if r2.ID != "r2" || r2.Action != ActionBypass || !reflect.DeepEqual(r2.Paths, []string{"/index.html"}) || !reflect.DeepEqual(r2.PathPrefixes, []string{"/static/"}) {
		t.Fatalf("r2 = %+v", r2)
	}
	if r3.ID != "r3" || !reflect.DeepEqual(r3.StatusCodes, []uint32{200, 404}) || r3.MinSize != 1 || r3.MaxSize != 10485760 ||
		r3.StaleWhileRevalidate != 30 || r3.StaleIfError != 86400 || r3.Mode != ModeRespect {
		t.Fatalf("r3 = %+v", r3)
	}
	// Secrets are never serialized from the configuration itself.
	b, _ := json.Marshal(bucket)
	if strings.Contains(string(b), "secret_key") || strings.Contains(string(b), "access_key") {
		t.Fatalf("site table leaks key fields before credentials are attached: %s", b)
	}
}

func TestBuildDropsInvalidM2Parts(t *testing.T) {
	cfg := vectorConfig()
	site := cfg.Sites[0]
	site.CacheKey = &nodev1.CacheKeyPolicy{
		Query:       nodev1.CacheKeyQuery_CACHE_KEY_QUERY_INCLUDE,
		QueryParams: []string{"ok", "a&b"},
		Headers:     []string{"X-Ok", "cookie", "bad header"},
		Cookies:     []string{"sid", "bad;cookie"},
	}
	site.OriginPool.Origins = append(site.OriginPool.Origins,
		&nodev1.Origin{Id: "bad-region", Address: "s3.test", Port: 443, S3: &nodev1.S3Auth{Region: "Bad Region", CredentialId: "c"}},
		&nodev1.Origin{Id: "no-cred", Address: "s3.test", Port: 443, S3: &nodev1.S3Auth{Region: "us-east-1"}},
	)
	site.CacheRules = append(site.CacheRules,
		&nodev1.CacheRule{Id: "bad-status", Priority: 20, Action: nodev1.CacheAction_CACHE_ACTION_CACHE, Match: &nodev1.CacheRuleMatch{StatusCodes: []uint32{42}}},
		&nodev1.CacheRule{Id: "bad-size", Priority: 21, Action: nodev1.CacheAction_CACHE_ACTION_CACHE, Match: &nodev1.CacheRuleMatch{MinSizeBytes: 10, MaxSizeBytes: 5}},
		&nodev1.CacheRule{Id: "bad-path", Priority: 22, Action: nodev1.CacheAction_CACHE_ACTION_CACHE, Match: &nodev1.CacheRuleMatch{Paths: []string{"relative"}}},
	)
	p, err := Build(cfg, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	s := p.Sites[0]
	if !reflect.DeepEqual(s.CacheKey, CacheKey{Query: QueryInclude, QueryParams: []string{"ok"}, Headers: []string{"x-ok"}, Cookies: []string{"sid"}}) {
		t.Fatalf("cache key = %+v", s.CacheKey)
	}
	if len(s.Origins) != 1 || len(s.CacheRules) != 1 {
		t.Fatalf("origins = %+v rules = %+v", s.Origins, s.CacheRules)
	}
	joined := strings.Join(p.Warnings, "\n")
	for _, want := range []string{`"a&b"`, `"cookie"`, `"bad header"`, `"bad;cookie"`, "invalid S3 region", "S3 origin without credential", "no valid status code", "maximum size below minimum size", "no valid path"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings do not mention %s:\n%s", want, joined)
		}
	}
}
