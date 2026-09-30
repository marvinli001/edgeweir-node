package configir

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

var allModules = []string{FeatureBrotli, FeatureZstd, FeatureModSecurity}

func tlsOptions() *nodev1.TlsOptions {
	return &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Gzip: true, GzipMinLength: 256, GzipTypes: []string{"text/css"}}
}

func compressedConfig() *nodev1.NodeConfig {
	s := site("site-a", "a.test")
	s.Tls = tlsOptions()
	s.Tls.Brotli, s.Tls.BrotliMinLength, s.Tls.BrotliTypes = true, 100, []string{"application/json", "text/css"}
	s.Tls.Zstd, s.Tls.ZstdLevel, s.Tls.ZstdMinLength, s.Tls.ZstdTypes = true, 19, 1000, []string{"text/css"}
	return &nodev1.NodeConfig{Sites: []*nodev1.Site{s}, RequiredFeatures: []string{FeatureBrotli, FeatureZstd}}
}

func TestBuildCompression(t *testing.T) {
	p, err := Build(compressedConfig(), Options{ExtraFeatures: allModules})
	if err != nil {
		t.Fatal(err)
	}
	got := *p.Sites[0].TLS
	if !got.Brotli || got.BrotliLevel != DefaultBrotliLevel || got.BrotliMinLength != 100 ||
		!slices.Equal(got.BrotliTypes, []string{"application/json", "text/css"}) {
		t.Fatalf("brotli = %+v", got)
	}
	if !got.Zstd || got.ZstdLevel != 19 || got.ZstdMinLength != 1000 || !slices.Equal(got.ZstdTypes, []string{"text/css"}) {
		t.Fatalf("zstd = %+v", got)
	}
	if !got.Gzip || got.GzipMinLength != 256 {
		t.Fatalf("gzip = %+v", got)
	}

	c := compressedConfig()
	c.Sites[0].Tls.ZstdLevel = 0
	c.Sites[0].Tls.BrotliLevel = 11
	p, err = Build(c, Options{ExtraFeatures: allModules})
	if err != nil || p.Sites[0].TLS.ZstdLevel != DefaultZstdLevel || p.Sites[0].TLS.BrotliLevel != 11 {
		t.Fatalf("levels: %+v, %v", p.Sites[0].TLS, err)
	}

	// Settings of an algorithm that is off do not reach the site table.
	c = compressedConfig()
	c.Sites[0].Tls.Brotli = false
	c.RequiredFeatures = []string{FeatureZstd}
	p, err = Build(c, Options{ExtraFeatures: []string{FeatureZstd}})
	if err != nil {
		t.Fatal(err)
	}
	if tls := p.Sites[0].TLS; tls.Brotli || tls.BrotliLevel != 0 || tls.BrotliTypes != nil || tls.BrotliMinLength != 0 {
		t.Fatalf("brotli off: %+v", tls)
	}
}

func TestBuildRejectsInvalidCompression(t *testing.T) {
	cases := map[string]func(*nodev1.TlsOptions){
		"brotli level":    func(o *nodev1.TlsOptions) { o.BrotliLevel = 12 },
		"zstd level":      func(o *nodev1.TlsOptions) { o.ZstdLevel = 20 },
		"brotli type":     func(o *nodev1.TlsOptions) { o.BrotliTypes = []string{"text/html; charset=utf-8"} },
		"zstd type":       func(o *nodev1.TlsOptions) { o.ZstdTypes = []string{"*"} },
		"gzip type":       func(o *nodev1.TlsOptions) { o.GzipTypes = []string{"Text/CSS"} },
		"unquoted syntax": func(o *nodev1.TlsOptions) { o.BrotliTypes = []string{"text/css;zstd"} },
	}
	for name, mutate := range cases {
		c := compressedConfig()
		mutate(c.Sites[0].Tls)
		if _, err := Build(c, Options{ExtraFeatures: allModules}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
	}
}

func TestBuildRequiresTheModules(t *testing.T) {
	for _, missing := range allModules {
		var others []string
		for _, f := range allModules {
			if f != missing {
				others = append(others, f)
			}
		}
		c := compressedConfig()
		c.Sites[0].Waf = &nodev1.SiteWaf{Mode: "detect", ParanoiaLevel: 1, AnomalyThreshold: 5}
		c.RequiredFeatures = nil // an older console would not require them
		_, err := Build(c, Options{ExtraFeatures: others})
		if !errors.Is(err, ErrRejected) || !strings.Contains(err.Error(), missing) || !strings.Contains(err.Error(), `"site-a"`) {
			t.Errorf("without %s: err = %v", missing, err)
		}
		// The console requires the features of the sites that use them.
		c.RequiredFeatures = []string{missing}
		if _, err := Build(c, Options{ExtraFeatures: others}); !errors.Is(err, ErrRejected) {
			t.Errorf("required %s: err = %v", missing, err)
		}
	}
	// Disabled sites and sites skipped for want of origins need nothing.
	c := compressedConfig()
	c.Sites[0].Enabled = false
	c.RequiredFeatures = nil
	if _, err := Build(c, Options{}); err != nil {
		t.Fatalf("disabled site: %v", err)
	}
	c = compressedConfig()
	c.Sites[0].OriginPool.Origins = nil
	c.RequiredFeatures = nil
	if _, err := Build(c, Options{}); err != nil {
		t.Fatalf("site without origins: %v", err)
	}
}

func wafConfig() *nodev1.NodeConfig {
	a := site("site-a", "a.test")
	a.Waf = &nodev1.SiteWaf{Mode: "block", ParanoiaLevel: 2, AnomalyThreshold: 10, ExcludedRuleIds: []uint32{920350, 942100}, RequestBodyLimit: 131072}
	b := site("site-b", "b.test")
	b.Waf = &nodev1.SiteWaf{Mode: "detect", ParanoiaLevel: 1, AnomalyThreshold: 5}
	c := site("site-c", "c.test")
	return &nodev1.NodeConfig{Sites: []*nodev1.Site{a, b, c}, RequiredFeatures: []string{FeatureModSecurity}}
}

func TestBuildWAF(t *testing.T) {
	p, err := Build(wafConfig(), Options{ExtraFeatures: allModules})
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := p.Sites[0].WAF, p.Sites[1].WAF, p.Sites[2].WAF
	if a == nil || a.Mode != WAFModeBlock || a.ParanoiaLevel != 2 || a.AnomalyThreshold != 10 || a.RequestBodyLimit != 131072 ||
		!slices.Equal(a.ExcludedRuleIDs, []uint32{920350, 942100}) {
		t.Fatalf("site-a waf = %+v", a)
	}
	if b == nil || b.Mode != WAFModeDetect || b.RequestBodyLimit != 0 || c != nil {
		t.Fatalf("site-b waf = %+v, site-c waf = %+v", b, c)
	}
	if !p.UsesWAF() || !slices.Equal(p.WAFBodyLimits(), []uint32{0, 131072}) {
		t.Fatalf("UsesWAF = %v, WAFBodyLimits = %v", p.UsesWAF(), p.WAFBodyLimits())
	}
	p.Sites = p.Sites[2:]
	if p.UsesWAF() || p.WAFBodyLimits() != nil {
		t.Fatal("a plan without CRS sites uses CRS")
	}
}

func TestBuildRejectsInvalidWAF(t *testing.T) {
	many := make([]uint32, MaxWAFExcludedRuleIDs+1)
	for i := range many {
		many[i] = uint32(MinWAFRuleID + i)
	}
	cases := map[string]func(*nodev1.SiteWaf){
		"mode":              func(w *nodev1.SiteWaf) { w.Mode = "off" },
		"empty mode":        func(w *nodev1.SiteWaf) { w.Mode = "" },
		"paranoia 0":        func(w *nodev1.SiteWaf) { w.ParanoiaLevel = 0 },
		"paranoia 5":        func(w *nodev1.SiteWaf) { w.ParanoiaLevel = 5 },
		"threshold 0":       func(w *nodev1.SiteWaf) { w.AnomalyThreshold = 0 },
		"threshold 1001":    func(w *nodev1.SiteWaf) { w.AnomalyThreshold = 1001 },
		"body limit":        func(w *nodev1.SiteWaf) { w.RequestBodyLimit = MaxWAFBodyLimit + 1 },
		"rule id below":     func(w *nodev1.SiteWaf) { w.ExcludedRuleIds = []uint32{899999} },
		"rule id above":     func(w *nodev1.SiteWaf) { w.ExcludedRuleIds = []uint32{1000000} },
		"too many rules":    func(w *nodev1.SiteWaf) { w.ExcludedRuleIds = many },
		"unsorted rule ids": func(w *nodev1.SiteWaf) { w.ExcludedRuleIds = []uint32{942100, 920350} },
		"duplicate ids":     func(w *nodev1.SiteWaf) { w.ExcludedRuleIds = []uint32{942100, 942100} },
	}
	for name, mutate := range cases {
		c := wafConfig()
		mutate(c.Sites[0].Waf)
		if _, err := Build(c, Options{ExtraFeatures: allModules}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
		// Disabled sites are checked too.
		c = wafConfig()
		mutate(c.Sites[0].Waf)
		c.Sites[0].Enabled = false
		if _, err := Build(c, Options{ExtraFeatures: allModules}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s on a disabled site: err = %v, want rejection", name, err)
		}
	}
	// Bounds are inclusive.
	c := wafConfig()
	w := c.Sites[0].Waf
	w.ParanoiaLevel, w.AnomalyThreshold, w.RequestBodyLimit = 4, 1000, MaxWAFBodyLimit
	w.ExcludedRuleIds = many[:MaxWAFExcludedRuleIDs]
	w.ExcludedRuleIds[len(w.ExcludedRuleIds)-1] = MaxWAFRuleID
	if _, err := Build(c, Options{ExtraFeatures: allModules}); err != nil {
		t.Fatalf("bounds: %v", err)
	}
}

// The console sorts and deduplicates brotli_types, zstd_types and
// excluded_rule_ids before hashing; so does the canonical form.
func TestCanonicalizeCompressionAndWAF(t *testing.T) {
	a := compressedConfig()
	a.Sites[0].Waf = &nodev1.SiteWaf{Mode: "block", ParanoiaLevel: 1, AnomalyThreshold: 5, ExcludedRuleIds: []uint32{942100, 920350, 942100}}
	a.Sites[0].Tls.BrotliTypes = []string{"text/css", "application/json", "text/css"}
	a.Sites[0].Tls.ZstdTypes = []string{"text/plain", "text/css", "text/plain"}
	b := proto.CloneOf(a)
	b.Sites[0].Waf.ExcludedRuleIds = []uint32{920350, 942100}
	b.Sites[0].Tls.BrotliTypes = []string{"application/json", "text/css"}
	b.Sites[0].Tls.ZstdTypes = []string{"text/css", "text/plain"}
	ab, err := CanonicalBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	bb, err := CanonicalBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, bb) {
		t.Fatal("canonical bytes depend on the order or duplicates of the new repeated fields")
	}
	ha, _ := ContentHash(a)
	hb, _ := ContentHash(b)
	if ha != hb {
		t.Fatalf("content hashes differ: %s %s", ha, hb)
	}
	Canonicalize(a)
	if !proto.Equal(a, b) {
		t.Fatalf("canonical form:\n%v\nwant\n%v", a, b)
	}
	// The new fields are part of the hash.
	c := proto.CloneOf(b)
	c.Sites[0].Waf.ParanoiaLevel = 2
	if hc, _ := ContentHash(c); hc == hb {
		t.Fatal("SiteWaf is not part of the content hash")
	}
	c = proto.CloneOf(b)
	c.Sites[0].Tls.ZstdLevel = 3
	if hc, _ := ContentHash(c); hc == hb {
		t.Fatal("zstd_level is not part of the content hash")
	}
}
