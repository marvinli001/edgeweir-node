package agent_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/render"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

// modulesHarness enrolls an agent whose engine has the static modules
// features and, with modsecurity, a ModSecurity module and a CRS directory.
func modulesHarness(t *testing.T, features []string, modsecurity bool, failProbe bool) (*harness, *fakeconsole.Console, *fakeEngine, agentStop) {
	t.Helper()
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-m", ClusterID: "cl-m", ReportInterval: 1, KeepaliveInterval: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	root := t.TempDir()
	h := &harness{t: t, console: console, url: srv.URL, stateDir: filepath.Join(root, "state"), root: root}
	dp := fakedataplane.Start(t)
	cfg := h.agentConfig(dp.Socket)
	if modsecurity {
		module := filepath.Join(root, "modules", "ngx_http_modsecurity_module.so")
		crs := filepath.Join(root, "crs")
		for _, dir := range []string{filepath.Dir(module), filepath.Join(crs, "rules")} {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for _, f := range []string{module, filepath.Join(crs, "crs-setup.conf")} {
			if err := os.WriteFile(f, nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		cfg.Render.ModSecurityModule, cfg.Render.CRSDir = module, crs
	}
	eng := newFakeEngine()
	eng.features, eng.failProbe = features, failProbe
	stop := startAgent(t, cfg, eng, dataplane.NewClient(dp.Socket))
	console.AddToken("m-token")
	if _, err := enroll.Run(context.Background(), enroll.Options{
		ServerURL: srv.URL, Token: "m-token", CASHA256: console.CA.Pin(), StateDir: h.stateDir, Logger: testLogger(t),
	}); err != nil {
		t.Fatal(err)
	}
	return h, console, eng, stop
}

type agentStop = func()

// rejectedFor waits for a rejection whose message names why.
func rejectedFor(c *fakeconsole.Console, why string) func() bool {
	return func() bool {
		s := c.LastStatus()
		return s != nil && s.GetState() == nodev1.ApplyState_APPLY_STATE_FAILED && strings.Contains(s.GetMessage(), why)
	}
}

func compressionConfig() *nodev1.NodeConfig {
	s := demoSite("site-br", "br.test")
	s.Tls = &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Brotli: true, BrotliTypes: []string{"text/css"},
		Zstd: true, ZstdLevel: 5, ZstdTypes: []string{"text/css"}}
	c := baseConfig(s)
	c.RequiredFeatures = []string{"brotli-v1", "zstd-v1"}
	return c
}

func wafConfig(excluded ...uint32) *nodev1.NodeConfig {
	s := demoSite("site-crs", "crs.test")
	s.Waf = &nodev1.SiteWaf{Mode: "block", ParanoiaLevel: 1, AnomalyThreshold: 5, RequestBodyLimit: 131072, ExcludedRuleIds: excluded}
	c := baseConfig(s)
	c.RequiredFeatures = []string{"modsecurity-v1"}
	return c
}

func TestModuleFeaturesAreDetectedAndReported(t *testing.T) {
	_, console, eng, _ := modulesHarness(t, []string{"zstd-v1", "brotli-v1"}, true, false)
	eventually(t, "module features reported", func() bool {
		st := console.LastStatus()
		return hasFeature(st, "brotli-v1") && hasFeature(st, "zstd-v1") && hasFeature(st, "modsecurity-v1")
	})
	eng.mu.Lock()
	probes := eng.probes
	eng.mu.Unlock()
	if probes != 1 {
		t.Fatalf("ModSecurity probes = %d, want 1 at startup", probes)
	}
	rev := console.Publish(compressionConfig())
	eventually(t, "Brotli and Zstandard applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	_, _, conf := eng.counts()
	for _, want := range []string{"brotli on;", "zstd_comp_level 5;", "gzip_vary on;"} {
		if !strings.Contains(conf, want) {
			t.Errorf("nginx.conf lacks %q", want)
		}
	}
}

func TestSitesNeedTheModules(t *testing.T) {
	// No ModSecurity module; the probe is never run.
	_, console, eng, _ := modulesHarness(t, []string{"brotli-v1"}, false, false)
	eventually(t, "status", func() bool { return console.LastStatus() != nil })
	console.Publish(compressionConfig())
	eventually(t, "rejected without zstd-v1", rejectedFor(console, "zstd-v1"))
	console.Publish(wafConfig())
	eventually(t, "rejected without modsecurity-v1", rejectedFor(console, "modsecurity-v1"))
	st := console.LastStatus()
	if hasFeature(st, "modsecurity-v1") || hasFeature(st, "zstd-v1") || !hasFeature(st, "brotli-v1") {
		t.Fatalf("features %v", st.GetInfo().GetSupportedFeatures())
	}
	eng.mu.Lock()
	defer eng.mu.Unlock()
	if eng.probes != 0 {
		t.Fatalf("probed ModSecurity without a module: %d", eng.probes)
	}
}

func TestModSecurityThatDoesNotLoadIsNotReported(t *testing.T) {
	_, console, _, _ := modulesHarness(t, nil, true, true)
	eventually(t, "status", func() bool { return console.LastStatus() != nil })
	console.Publish(wafConfig())
	eventually(t, "rejected", rejectedFor(console, "modsecurity-v1"))
	if hasFeature(console.LastStatus(), "modsecurity-v1") {
		t.Fatal("modsecurity-v1 reported although the module does not load")
	}
}

func TestModSecurityConfigurationFiles(t *testing.T) {
	h, console, eng, _ := modulesHarness(t, nil, true, false)
	confDir := filepath.Join(h.root, "nginx", "conf")
	modsecFiles := func() []string {
		var out []string
		entries, _ := os.ReadDir(confDir)
		for _, e := range entries {
			if render.IsModSecurityConf(e.Name()) {
				out = append(out, e.Name())
			}
		}
		return out
	}
	rev := console.Publish(wafConfig(942100))
	eventually(t, "CRS site applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	files := modsecFiles()
	if len(files) != 1 {
		t.Fatalf("ModSecurity configurations %v", files)
	}
	rules, err := os.ReadFile(filepath.Join(confDir, files[0]))
	if err != nil || !strings.Contains(string(rules), `"@beginsWith site-crs;"`) || !strings.Contains(string(rules), "ctl:ruleRemoveById=942100") {
		t.Fatalf("ModSecurity configuration: %v\n%s", err, rules)
	}
	_, reloads, conf := eng.counts()
	if !strings.Contains(conf, "modsecurity_rules_file "+filepath.Join(confDir, files[0])+";") || !strings.Contains(conf, "load_module ") {
		t.Fatalf("nginx.conf does not load the ModSecurity configuration:\n%s", conf)
	}
	for _, name := range []string{"modsecurity-probe.conf", "modsecurity-probe.nginx.conf"} {
		if _, err := os.Stat(filepath.Join(confDir, name)); !os.IsNotExist(err) {
			t.Errorf("probe file %s left behind: %v", name, err)
		}
	}

	// Another exclusion: a new file, a reload, the old file removed.
	rev = console.Publish(wafConfig(941100, 942100))
	eventually(t, "exclusion change applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if _, r, _ := eng.counts(); r != reloads+1 {
		t.Fatalf("reloads %d -> %d: an exclusion change is structural", reloads, r)
	}
	if next := modsecFiles(); len(next) != 1 || next[0] == files[0] {
		t.Fatalf("ModSecurity configurations after the change: %v (before %v)", next, files)
	}

	// CRS off: nginx.conf no longer loads the module, no file remains.
	c := wafConfig()
	c.Sites[0].Waf = nil
	c.RequiredFeatures = nil
	rev = console.Publish(c)
	eventually(t, "CRS off applied", statusWith(console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	if _, _, conf := eng.counts(); strings.Contains(conf, "modsecurity") || strings.Contains(conf, "load_module") {
		t.Fatalf("nginx.conf still loads ModSecurity:\n%s", conf)
	}
	if left := modsecFiles(); len(left) != 0 {
		t.Fatalf("ModSecurity configurations left: %v", left)
	}
}
