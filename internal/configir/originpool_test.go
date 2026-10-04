package configir

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// keys are the challenge keys a configuration with session affinity
// carries.
func keys() []*nodev1.ChallengeKeyRef {
	return []*nodev1.ChallengeKeyRef{{Id: "k-current", Role: "current"}, {Id: "k-next", Role: "next"}}
}

func activeConfig(check *nodev1.ActiveHealthCheck) *nodev1.NodeConfig {
	s := site("site-a", "a.test")
	s.OriginPool.ActiveHealthCheck = check
	return &nodev1.NodeConfig{Sites: []*nodev1.Site{s}}
}

func TestBuildActiveHealthCheck(t *testing.T) {
	extra := Options{ExtraFeatures: []string{FeatureActiveHealth}}
	check := &nodev1.ActiveHealthCheck{
		Path: "/healthz?deep=1", Method: "HEAD", ExpectedStatusMin: 200, ExpectedStatusMax: 204, Host: "health.example.com",
		IntervalSeconds: 10, TimeoutSeconds: 3, HealthyThreshold: 1, UnhealthyThreshold: 5,
	}
	p, err := Build(activeConfig(check), extra)
	if err != nil {
		t.Fatal(err)
	}
	got := p.Sites[0]
	want := ActiveHealthCheck{Path: "/healthz?deep=1", Method: "HEAD", ExpectedStatusMin: 200, ExpectedStatusMax: 204,
		Host: "health.example.com", Interval: 10 * time.Second, Timeout: 3 * time.Second, HealthyThreshold: 1, UnhealthyThreshold: 5}
	if !got.ActiveHealth || got.ActiveHealthCheck == nil || *got.ActiveHealthCheck != want {
		t.Fatalf("active health = %v %+v, want %+v", got.ActiveHealth, got.ActiveHealthCheck, want)
	}
	// Zero values take the defaults.
	p, err = Build(activeConfig(&nodev1.ActiveHealthCheck{}), extra)
	if err != nil {
		t.Fatal(err)
	}
	want = ActiveHealthCheck{Path: "/", Method: "GET", ExpectedStatusMin: 200, ExpectedStatusMax: 399,
		Interval: 30 * time.Second, Timeout: 5 * time.Second, HealthyThreshold: 2, UnhealthyThreshold: 3}
	if *p.Sites[0].ActiveHealthCheck != want {
		t.Fatalf("defaults = %+v, want %+v", *p.Sites[0].ActiveHealthCheck, want)
	}
	// A pool without an active check: passive checks only.
	p, err = Build(activeConfig(nil), Options{})
	if err != nil || p.Sites[0].ActiveHealth || p.Sites[0].ActiveHealthCheck != nil {
		t.Fatalf("without a check: %+v, %v", p.Sites[0], err)
	}

	for name, c := range map[string]*nodev1.ActiveHealthCheck{
		"relative path":      {Path: "healthz"},
		"space in path":      {Path: "/a b"},
		"control in path":    {Path: "/a\x01"},
		"long path":          {Path: "/" + strings.Repeat("p", 1024)},
		"method POST":        {Method: "POST"},
		"lowercase method":   {Method: "get"},
		"status below 100":   {ExpectedStatusMin: 99},
		"status above 599":   {ExpectedStatusMax: 600},
		"empty range":        {ExpectedStatusMin: 300, ExpectedStatusMax: 200},
		"interval 4":         {IntervalSeconds: 4},
		"interval 301":       {IntervalSeconds: 301},
		"timeout 61":         {IntervalSeconds: 300, TimeoutSeconds: 61},
		"timeout > interval": {IntervalSeconds: 5, TimeoutSeconds: 6},
		"healthy 11":         {HealthyThreshold: 11},
		"unhealthy 11":       {UnhealthyThreshold: 11},
		"bad host":           {Host: "bad host"},
	} {
		if _, err := Build(activeConfig(c), extra); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
	}
	if !validHealthPath("/"+strings.Repeat("p", 1023)) || validHealthPath("") {
		t.Fatal("path length bounds")
	}

	// This agent runs active checks (active-health-v1): a served site
	// with one needs no extra feature; a disabled one only valid settings.
	if p, err := Build(activeConfig(check), Options{}); err != nil || !p.Sites[0].ActiveHealth {
		t.Fatalf("active check without extra features: %v", err)
	}
	off := activeConfig(check)
	off.Sites[0].Enabled = false
	if _, err := Build(off, Options{}); err != nil {
		t.Fatalf("disabled site with an active check: %v", err)
	}
}

func TestBuildSessionAffinity(t *testing.T) {
	affinityConfig := func(ttl uint32) *nodev1.NodeConfig {
		s := site("site-a", "a.test")
		s.OriginPool.SessionAffinity = &nodev1.SessionAffinity{TtlSeconds: ttl}
		return &nodev1.NodeConfig{Sites: []*nodev1.Site{s}, ChallengeKeys: keys()}
	}
	for ttl, want := range map[uint32]uint32{0: DefaultAffinityTTL, 60: 60, 604800: 604800} {
		p, err := Build(affinityConfig(ttl), Options{})
		if err != nil || p.Sites[0].Affinity == nil || p.Sites[0].Affinity.TTL != want {
			t.Fatalf("ttl %d: %+v, %v", ttl, p.Sites[0].Affinity, err)
		}
	}
	for _, ttl := range []uint32{59, 604801} {
		if _, err := Build(affinityConfig(ttl), Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("ttl %d: %v", ttl, err)
		}
	}
	// The cookies are signed with the challenge keys: a served site with
	// affinity needs them.
	c := affinityConfig(3600)
	c.ChallengeKeys = nil
	if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "challenge keys") {
		t.Fatalf("affinity without keys: %v", err)
	}
	c.Sites[0].Enabled = false
	if _, err := Build(c, Options{}); err != nil {
		t.Fatalf("disabled site with affinity and no keys: %v", err)
	}
}

// TestBuildOriginProtocol: HTTP/2 towards the origins and gRPC reach the
// site table (omitted for HTTP/1.1); gRPC without HTTP/2 and unknown
// protocols reject the configuration, also for a disabled site.
func TestBuildOriginProtocol(t *testing.T) {
	protocolConfig := func(protocol nodev1.OriginProtocol, grpc bool) *nodev1.NodeConfig {
		s := site("site-a", "a.test")
		s.OriginPool.Protocol, s.OriginPool.Grpc = protocol, grpc
		return &nodev1.NodeConfig{Sites: []*nodev1.Site{s}, RequiredFeatures: []string{FeatureOriginHTTP2}}
	}
	for _, tc := range []struct {
		protocol    nodev1.OriginProtocol
		grpc        bool
		http2, json string
	}{
		{nodev1.OriginProtocol_ORIGIN_PROTOCOL_UNSPECIFIED, false, "", ""},
		{nodev1.OriginProtocol_ORIGIN_PROTOCOL_HTTP1, false, "", ""},
		{nodev1.OriginProtocol_ORIGIN_PROTOCOL_HTTP2, false, "h2", `"origin_http2":true`},
		{nodev1.OriginProtocol_ORIGIN_PROTOCOL_HTTP2, true, "h2", `"origin_http2":true,"grpc":true`},
	} {
		p, err := Build(protocolConfig(tc.protocol, tc.grpc), Options{})
		if err != nil {
			t.Fatalf("%v grpc=%v: %v", tc.protocol, tc.grpc, err)
		}
		got := p.Sites[0]
		if got.OriginHTTP2 != (tc.http2 != "") || got.GRPC != tc.grpc {
			t.Errorf("%v grpc=%v: origin_http2=%v grpc=%v", tc.protocol, tc.grpc, got.OriginHTTP2, got.GRPC)
		}
		b, err := json.Marshal(got)
		if err != nil {
			t.Fatal(err)
		}
		if tc.json == "" && (strings.Contains(string(b), "origin_http2") || strings.Contains(string(b), `"grpc"`)) {
			t.Errorf("%v: HTTP/1.1 site table entry carries protocol fields: %s", tc.protocol, b)
		}
		if tc.json != "" && !strings.Contains(string(b), tc.json) {
			t.Errorf("%v grpc=%v: site table entry lacks %s: %s", tc.protocol, tc.grpc, tc.json, b)
		}
	}
	for _, protocol := range []nodev1.OriginProtocol{nodev1.OriginProtocol_ORIGIN_PROTOCOL_UNSPECIFIED, nodev1.OriginProtocol_ORIGIN_PROTOCOL_HTTP1} {
		c := protocolConfig(protocol, true)
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), "gRPC requires HTTP/2") {
			t.Errorf("gRPC over %v: %v", protocol, err)
		}
		c.Sites[0].Enabled = false
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("disabled site, gRPC over %v: %v", protocol, err)
		}
	}
	if _, err := Build(protocolConfig(nodev1.OriginProtocol(7), false), Options{}); !errors.Is(err, ErrRejected) {
		t.Errorf("unknown protocol: %v", err)
	}
	if !slices.Contains(SupportedFeatures, FeatureOriginHTTP2) {
		t.Errorf("SupportedFeatures lacks %s", FeatureOriginHTTP2)
	}
}

func TestSupportedFeaturesG4(t *testing.T) {
	g4 := []string{FeatureErrorPages, FeatureSessionAffinity, FeatureActiveHealth, FeaturePurgeTag, FeaturePrefetch}
	for _, f := range g4 {
		if !slices.Contains(SupportedFeatures, f) {
			t.Errorf("SupportedFeatures lacks %s", f)
		}
	}
	c := &nodev1.NodeConfig{Sites: []*nodev1.Site{site("site-a", "a.test")}, RequiredFeatures: g4}
	if _, err := Build(c, Options{}); err != nil {
		t.Fatalf("required %v: %v", g4, err)
	}
}
