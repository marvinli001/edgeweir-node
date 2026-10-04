package render

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

func tlsSite(id, domain string, tls configir.TLSOptions) configir.Site {
	tls.MinimumVersion, tls.CipherProfile = "1.2", "modern"
	return configir.Site{ID: id, CertificateID: "cert-" + id, Domains: []configir.Domain{{Name: domain}}, TLS: &tls}
}

func compressionPlan() *configir.Plan {
	return &configir.Plan{
		Listeners:  []configir.Listener{{Port: 80}, {Port: 443, TLS: true, HTTP2: true}},
		CacheZones: []configir.CacheZone{{Name: "default", MaxSizeMB: 1024, KeysZoneMB: 16, InactiveSeconds: 3600}},
		Sites: []configir.Site{
			tlsSite("all", "all.test", configir.TLSOptions{
				HTTP2: true, Gzip: true, GzipMinLength: 256, GzipTypes: []string{"application/json", "text/css"},
				Brotli: true, BrotliLevel: 6, BrotliMinLength: 256, BrotliTypes: []string{"application/json", "text/css"},
				Zstd: true, ZstdLevel: 3, ZstdMinLength: 1024, ZstdTypes: []string{"text/css"},
			}),
			tlsSite("brotli-only", "br.test", configir.TLSOptions{Brotli: true, BrotliLevel: 11}),
			tlsSite("none", "none.test", configir.TLSOptions{}),
		},
	}
}

func TestRenderCompressionGolden(t *testing.T) {
	got, err := Render(params(), compressionPlan())
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "compression.conf.golden", got)
	conf := string(got)
	for _, want := range []string{
		"brotli on;\n        brotli_comp_level 6;\n        brotli_min_length 256;\n        brotli_types application/json text/css;",
		"zstd on;\n        zstd_comp_level 3;\n        zstd_min_length 1024;\n        zstd_types text/css;",
		// Brotli without gzip still sends Vary: Accept-Encoding.
		"server_name br.test;",
		"brotli_comp_level 11;\n        brotli_min_length 1;",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx.conf lacks %q", want)
		}
	}
	block := regexp.MustCompile(`(?s)server \{[^{}]*server_name br\.test;`).FindString(conf)
	if !strings.Contains(block, "gzip_vary on;") || strings.Contains(block, "gzip on;") {
		t.Errorf("Brotli-only server block:\n%s", block)
	}
	block = regexp.MustCompile(`(?s)server \{[^{}]*server_name none\.test;`).FindString(conf)
	if strings.Contains(block, "gzip_vary") || strings.Contains(block, "brotli") || strings.Contains(block, "zstd") {
		t.Errorf("a site without compression got compression settings:\n%s", block)
	}
	// Static directives: changing a level changes nginx.conf (reload).
	plan := compressionPlan()
	plan.Sites[0].TLS.ZstdLevel = 4
	other, _ := Render(params(), plan)
	if bytes.Equal(got, other) {
		t.Fatal("a Zstandard level change did not change nginx.conf")
	}
}

func TestRenderRejectsInvalidCompression(t *testing.T) {
	for name, mutate := range map[string]func(*configir.TLSOptions){
		"brotli level": func(o *configir.TLSOptions) { o.BrotliLevel = 12 },
		"zstd level":   func(o *configir.TLSOptions) { o.ZstdLevel = 20 },
		"no level":     func(o *configir.TLSOptions) { o.ZstdLevel = 0 },
		"brotli type":  func(o *configir.TLSOptions) { o.BrotliTypes = []string{"text/css; include /etc/passwd"} },
		"zstd type":    func(o *configir.TLSOptions) { o.ZstdTypes = []string{"text/css;"} },
		"gzip type":    func(o *configir.TLSOptions) { o.GzipTypes = []string{"text/css }"} },
	} {
		plan := compressionPlan()
		mutate(plan.Sites[0].TLS)
		if _, err := Render(params(), plan); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func wafParams() Params {
	p := params()
	p.ModSecurityModule = "/usr/lib/edgeweir-openresty/modules/ngx_http_modsecurity_module.so"
	p.ModSecurityUnicodeMap = "/usr/share/edgeweir-openresty/modsecurity/unicode.mapping"
	return p
}

func wafPlan() *configir.Plan {
	return &configir.Plan{
		Listeners:  []configir.Listener{{Port: 80}},
		CacheZones: []configir.CacheZone{{Name: "default", MaxSizeMB: 1024, KeysZoneMB: 16, InactiveSeconds: 3600}},
		Sites: []configir.Site{
			{ID: "crs-block", WAF: &configir.WAF{Mode: configir.WAFModeBlock, ParanoiaLevel: 2, AnomalyThreshold: 10,
				RequestBodyLimit: 131072, ExcludedRuleIDs: []uint32{920350, 942100}}},
			{ID: "crs-detect", WAF: &configir.WAF{Mode: configir.WAFModeDetect, ParanoiaLevel: 1, AnomalyThreshold: 5}},
			{ID: "crs-same-limit", WAF: &configir.WAF{Mode: configir.WAFModeBlock, ParanoiaLevel: 4, AnomalyThreshold: 5,
				RequestBodyLimit: 131072, ExcludedRuleIDs: []uint32{941100}}},
			{ID: "site-without-crs"},
		},
	}
}

func TestRenderWAFGolden(t *testing.T) {
	p, plan := wafParams(), wafPlan()
	got, err := Render(p, plan)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "waf.conf.golden", got)
	path, modsec, err := ModSecurityConf(p, plan)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "waf.modsecurity.conf.golden", modsec)
	if dir, name := filepath.Split(path); dir != "/var/lib/edgeweir-node/nginx/conf/" || !IsModSecurityConf(name) {
		t.Fatalf("ModSecurity configuration path %q", path)
	}
	conf := string(got)
	for _, want := range []string{
		"load_module /usr/lib/edgeweir-openresty/modules/ngx_http_modsecurity_module.so;",
		"modsecurity_rules_file " + path + ";",
		"waf_body_limits = {0, 131072},",
		"location @edgeweir_waf_0 {",
		"modsecurity_rules 'SecRequestBodyAccess Off';",
		"location @edgeweir_waf_131072 {",
		"modsecurity_rules 'SecRequestBodyLimit 131072';",
		`set $edgeweir_ctx_ref "";`,
		`proxy_set_header X-Edgeweir-Waf "";`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx.conf lacks %q", want)
		}
	}
	// ModSecurity is on only in the CRS locations: one per server and body
	// limit (sites with the same limit share one).
	if n := strings.Count(conf, "modsecurity on;"); n != 2*len(plan.WAFBodyLimits()) {
		t.Errorf("modsecurity on in %d locations, want %d", n, 2*len(plan.WAFBodyLimits()))
	}
	for _, site := range plan.Sites {
		if strings.Contains(conf, site.ID) {
			t.Errorf("site id %s in nginx.conf", site.ID)
		}
	}
	rules := string(modsec)
	for _, want := range []string{
		`SecRule REQUEST_HEADERS:X-Edgeweir-Waf "@beginsWith crs-block;" \` + "\n" +
			`    "id:10100,phase:1,pass,nolog,t:none,ctl:ruleRemoveById=920350,ctl:ruleRemoveById=942100"`,
		`"@beginsWith crs-same-limit;"`,
		"Include /usr/share/edgeweir-openresty/crs/crs-setup.conf",
		"Include /usr/share/edgeweir-openresty/crs/rules/*.conf",
		"SecUnicodeMapFile /usr/share/edgeweir-openresty/modsecurity/unicode.mapping 20127",
		"SecResponseBodyAccess Off",
		"ctl:ruleEngine=DetectionOnly",
	} {
		if !strings.Contains(rules, want) {
			t.Errorf("ModSecurity configuration lacks %q", want)
		}
	}
	if strings.Contains(rules, "crs-detect;") || strings.Contains(rules, "site-without-crs") {
		t.Error("sites without exclusions got exclusion rules")
	}
	// The settings come before the CRS, whose initialization keeps values
	// set earlier; exclusions too.
	if i, j := strings.Index(rules, "id:10000,"), strings.Index(rules, "rules/*.conf"); i < 0 || i > j {
		t.Error("per-request settings must precede the CRS rules")
	}
	// A changed exclusion changes the file name and so nginx.conf.
	plan.Sites[0].WAF.ExcludedRuleIDs = []uint32{920350}
	other, err := Render(p, plan)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(got, other) {
		t.Fatal("changing an exclusion did not change nginx.conf")
	}
}

func TestRenderWithoutWAF(t *testing.T) {
	p := wafParams()
	plan := wafPlan()
	plan.Sites = plan.Sites[3:]
	got, err := Render(p, plan)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(got)
	// $edgeweir_ctx_ref stays: the gRPC location takes the context over too.
	for _, unwanted := range []string{"load_module", "modsecurity", "@edgeweir_waf_", "X-Edgeweir-Waf"} {
		if strings.Contains(conf, unwanted) {
			t.Errorf("nginx.conf without CRS sites contains %q", unwanted)
		}
	}
	if path, modsec, err := ModSecurityConf(p, plan); path != "" || modsec != nil || err != nil {
		t.Fatalf("ModSecurityConf without CRS sites = %q, %q, %v", path, modsec, err)
	}
	// A node without the module renders fine as long as no site needs it.
	p.ModSecurityModule = ""
	if _, err := Render(p, plan); err != nil {
		t.Fatal(err)
	}
	if _, err := Render(p, wafPlan()); err == nil {
		t.Fatal("a CRS site rendered without a ModSecurity module")
	}
}

func TestRenderRejectsUnsafeModSecurityPaths(t *testing.T) {
	for name, mutate := range map[string]func(*Params){
		"module":      func(p *Params) { p.ModSecurityModule = "/x.so; include /etc/passwd" },
		"relative":    func(p *Params) { p.ModSecurityModule = "modules/x.so" },
		"crs dir":     func(p *Params) { p.CRSDir = "/usr/share/crs rules" },
		"unicode map": func(p *Params) { p.ModSecurityUnicodeMap = "/x\"y" },
	} {
		p := wafParams()
		mutate(&p)
		if _, err := Render(p, wafPlan()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestModSecurityProbe(t *testing.T) {
	p := wafParams()
	got, err := ModSecurityProbe(p, "/var/lib/edgeweir-node/nginx/conf/modsecurity-probe.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"load_module /usr/lib/edgeweir-openresty/modules/ngx_http_modsecurity_module.so;",
		"modsecurity_rules_file /var/lib/edgeweir-node/nginx/conf/modsecurity-probe.conf;",
		"modsecurity on;",
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("probe lacks %q", want)
		}
	}
	if _, err := ModSecurityProbe(p, "relative.conf"); err == nil {
		t.Error("relative probe configuration accepted")
	}
}

func TestIsModSecurityConf(t *testing.T) {
	for name, want := range map[string]bool{
		"modsecurity-0123456789abcdef.conf": true,
		"modsecurity-0123456789abcdeg.conf": false,
		"modsecurity-probe.conf":            false,
		"modsecurity-0123456789abcdef.txt":  false,
		"nginx.conf":                        false,
	} {
		if got := IsModSecurityConf(name); got != want {
			t.Errorf("IsModSecurityConf(%q) = %v", name, got)
		}
	}
}
