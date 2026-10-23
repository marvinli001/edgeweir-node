package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// v160Vector reads testdata/content_hash_vector_v160.json, a copy of the
// console's fixture: site a sends PROXY protocol v2 to origin o-a1 and v1
// to o-a2 and checks them with grpc.health.v1 for the service e2e.Echo,
// site b checks the server's overall gRPC health, site c keeps an HTTP
// check. Sites, their origins and the required features are reversed.
func v160Vector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_v160.json"))
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

// TestContentHashVectorV160 checks the proto v1.6.0 vector shared with
// the console: the origins' PROXY protocol versions and the checks' type
// and service in the hash, and the plan.
func TestContentHashVectorV160(t *testing.T) {
	cfg, v := v160Vector(t)
	if cfg.GetSites()[0].GetId() != "c" {
		t.Fatalf("vector is already canonical")
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
	if err := VerifyHash(cfg); err != nil {
		t.Fatal(err)
	}
	check := func(c *nodev1.NodeConfig, id string) *nodev1.ActiveHealthCheck {
		return vectorSite(c, id).GetOriginPool().GetActiveHealthCheck()
	}
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"proxy protocol": func(c *nodev1.NodeConfig) { vectorSite(c, "a").OriginPool.Origins[0].ProxyProtocolVersion = 0 },
		"type":           func(c *nodev1.NodeConfig) { check(c, "b").Type = nodev1.ActiveHealthCheckType_ACTIVE_HEALTH_CHECK_TYPE_HTTP },
		"service":        func(c *nodev1.NodeConfig) { check(c, "a").GrpcService = "e2e.Other" },
	} {
		c, _ := v160Vector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: cfg.GetClusterId(), ExtraFeatures: []string{FeatureOriginProxyProtocol}})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 3 {
		t.Fatalf("plan sites %+v", p.Sites)
	}
	a, b2, c := p.Sites[0], p.Sites[1], p.Sites[2]
	if a.Origins[0].ID != "o-a1" || a.Origins[0].ProxyProtocol != 2 || a.Origins[1].ProxyProtocol != 1 {
		t.Fatalf("site a origins %+v", a.Origins)
	}
	if !a.ActiveHealthCheck.GRPC || a.ActiveHealthCheck.GRPCService != "e2e.Echo" {
		t.Fatalf("site a check %+v", a.ActiveHealthCheck)
	}
	if !b2.ActiveHealthCheck.GRPC || b2.ActiveHealthCheck.GRPCService != "" || b2.Origins[0].ProxyProtocol != 0 {
		t.Fatalf("site b %+v", b2)
	}
	if c.ActiveHealthCheck.GRPC {
		t.Fatalf("site c check %+v", c.ActiveHealthCheck)
	}
	// A node whose OpenResty cannot send PROXY protocol to origins keeps its
	// last-known-good configuration.
	if _, err := Build(cfg, Options{ClusterID: cfg.GetClusterId()}); err == nil || !strings.Contains(err.Error(), FeatureOriginProxyProtocol) {
		t.Fatalf("a node without proxy_protocol_header accepted the configuration: %v", err)
	}
}

// TestProxyProtocolAndGRPCCheckValidation: versions above 2 and PROXY
// protocol to S3 origins skip the origin; a service without the gRPC type
// or with spaces rejects the configuration.
func TestProxyProtocolAndGRPCCheckValidation(t *testing.T) {
	base := nodev1.Origin{Id: "o", Address: "origin.test", Port: 80, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP}
	o := &base
	o.ProxyProtocolVersion = 3
	if _, err := buildOrigin(o); err == nil {
		t.Error("version 3 accepted")
	}
	o.ProxyProtocolVersion = 1
	o.S3 = &nodev1.S3Auth{Region: "us-east-1", CredentialId: "c"}
	if _, err := buildOrigin(o); err == nil {
		t.Error("PROXY protocol to an S3 origin accepted")
	}
	o.S3 = nil
	if got, err := buildOrigin(o); err != nil || got.ProxyProtocol != 1 {
		t.Errorf("v1 origin %+v, %v", got, err)
	}

	grpc := nodev1.ActiveHealthCheckType_ACTIVE_HEALTH_CHECK_TYPE_GRPC
	for _, tc := range []struct {
		check *nodev1.ActiveHealthCheck
		ok    bool
	}{
		{&nodev1.ActiveHealthCheck{Type: grpc}, true},
		{&nodev1.ActiveHealthCheck{Type: grpc, GrpcService: "grpc.health.v1.Health"}, true},
		{&nodev1.ActiveHealthCheck{Type: grpc, GrpcService: strings.Repeat("s", 255)}, true},
		{&nodev1.ActiveHealthCheck{Type: grpc, GrpcService: strings.Repeat("s", 256)}, false},
		{&nodev1.ActiveHealthCheck{Type: grpc, GrpcService: "a b"}, false},
		{&nodev1.ActiveHealthCheck{GrpcService: "a"}, false},
		{&nodev1.ActiveHealthCheck{Type: nodev1.ActiveHealthCheckType_ACTIVE_HEALTH_CHECK_TYPE_HTTP}, true},
	} {
		got, err := buildActiveHealthCheck(tc.check)
		if (err == nil) != tc.ok {
			t.Errorf("%v: %v", tc.check, err)
		}
		if err == nil && got.GRPC != (tc.check.GetType() == grpc) {
			t.Errorf("%v: GRPC %v", tc.check, got.GRPC)
		}
	}
}
