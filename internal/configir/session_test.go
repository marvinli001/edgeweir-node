package configir

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// sessionVector reads testdata/content_hash_vector_session_detection.json,
// a copy of the console's fixture: site a enforces with the interstitial
// off and two rules (on for www.a.test/checkout, off for api.a.test), site
// b monitors with the interstitial on, site c has none.
func sessionVector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_session_detection.json"))
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

func TestContentHashVectorSessionDetection(t *testing.T) {
	cfg, v := sessionVector(t)
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
	if !slices.Contains(cfg.GetRequiredFeatures(), FeatureSessionDetection) || !slices.Contains(SupportedFeatures, FeatureSessionDetection) {
		t.Fatalf("feature %s not required or not supported", FeatureSessionDetection)
	}
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"mode":         func(c *nodev1.NodeConfig) { vectorSite(c, "a").SessionDetection.Mode = "monitor" },
		"interstitial": func(c *nodev1.NodeConfig) { vectorSite(c, "b").SessionDetection.Interstitial = false },
		"rule order": func(c *nodev1.NodeConfig) {
			r := vectorSite(c, "a").SessionDetection.InterstitialRules
			r[0], r[1] = r[1], r[0]
		},
	} {
		c, _ := sessionVector(t)
		change(c)
		if hc, _ := ContentHash(c); hc == h {
			t.Errorf("%s does not change the hash", name)
		}
	}

	Canonicalize(cfg)
	p, err := Build(cfg, Options{ClusterID: cfg.GetClusterId()})
	if err != nil {
		t.Fatal(err)
	}
	sites := map[string]Site{}
	for _, s := range p.Sites {
		sites[s.ID] = s
	}
	a := sites["a"].SessionDetection
	if a == nil || a.Mode != "enforce" || a.Interstitial || len(a.Rules) != 2 ||
		a.Rules[0] != (InterstitialRule{Host: "www.a.test", PathPrefix: "/checkout", Interstitial: true}) ||
		a.Rules[1] != (InterstitialRule{Host: "api.a.test"}) {
		t.Fatalf("site a %+v", a)
	}
	if b := sites["b"].SessionDetection; b == nil || b.Mode != "monitor" || !b.Interstitial {
		t.Fatalf("site b %+v", b)
	}
	if sites["c"].SessionDetection != nil {
		t.Fatalf("site c %+v", sites["c"].SessionDetection)
	}
}

func TestSessionDetectionValidation(t *testing.T) {
	rule := func(host, path string) *nodev1.InterstitialRule {
		return &nodev1.InterstitialRule{Host: host, PathPrefix: path, Interstitial: true}
	}
	many := make([]*nodev1.InterstitialRule, MaxInterstitialRules+1)
	for i := range many {
		many[i] = rule("", "")
	}
	for _, tc := range []struct {
		d  *nodev1.SessionDetection
		ok bool
	}{
		{&nodev1.SessionDetection{Mode: "monitor"}, true},
		{&nodev1.SessionDetection{Mode: "enforce", InterstitialRules: []*nodev1.InterstitialRule{rule("*.a.test", "/x"), rule("", "")}}, true},
		{&nodev1.SessionDetection{Mode: "off"}, false},
		{&nodev1.SessionDetection{Mode: "armed"}, false},
		{&nodev1.SessionDetection{Mode: "enforce", InterstitialRules: []*nodev1.InterstitialRule{rule("A.test", "")}}, false},
		{&nodev1.SessionDetection{Mode: "enforce", InterstitialRules: []*nodev1.InterstitialRule{rule("*.*.a.test", "")}}, false},
		{&nodev1.SessionDetection{Mode: "enforce", InterstitialRules: []*nodev1.InterstitialRule{rule("a.test", "x")}}, false},
		{&nodev1.SessionDetection{Mode: "enforce", InterstitialRules: []*nodev1.InterstitialRule{rule("a.test", "/a b")}}, false},
		{&nodev1.SessionDetection{Mode: "enforce", InterstitialRules: []*nodev1.InterstitialRule{rule("a.test", "/"+strings.Repeat("a", 256))}}, false},
		{&nodev1.SessionDetection{Mode: "enforce", InterstitialRules: many}, false},
	} {
		_, err := buildSessionDetection(&nodev1.Site{SessionDetection: tc.d})
		if (err == nil) != tc.ok {
			t.Errorf("%+v: err %v, want ok %v", tc.d, err, tc.ok)
		}
	}
	if d, err := buildSessionDetection(&nodev1.Site{}); d != nil || err != nil {
		t.Errorf("unset: %+v %v", d, err)
	}
}

// TestBotScoreFields: the score fields are typed and only request phases
// read them.
func TestBotScoreFields(t *testing.T) {
	if fieldTypes["http.request.bot.score"] != "number" || fieldTypes["http.request.bot.automated"] != "boolean" {
		t.Fatal("bot score field types")
	}
	if !requestOnlyFields["http.request.bot.score"] || !requestOnlyFields["http.request.bot.automated"] {
		t.Fatal("bot score fields readable outside the request phases")
	}
}
