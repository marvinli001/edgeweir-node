package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	"github.com/marvinli001/edgeweir-node/internal/render"
)

// extraFeatures are the features that depend on this node's files rather
// than on the agent version: GeoIP databases and OpenResty modules. Sites
// may use them (configir.Options.ExtraFeatures) and ReportStatus announces
// them.
func (a *Agent) extraFeatures() []string {
	return append(slices.Clone(a.geoFeatures), a.moduleFeatures...)
}

var errNoModSecurity = errors.New("no ModSecurity module")

// detectModules finds the optional OpenResty modules this node can use:
// brotli-v1 and zstd-v1 from the configure arguments of `nginx -V`,
// modsecurity-v1 when the ModSecurity module and the OWASP CRS load in a
// configuration test.
func (a *Agent) detectModules(ctx context.Context) {
	features, err := a.engine.ModuleFeatures(ctx)
	if err != nil {
		a.log.Warn("cannot list the engine's modules (nginx -V)", "err", err)
	}
	if err := a.probeModSecurity(ctx); err == nil {
		features = append(features, configir.FeatureModSecurity)
	} else if !errors.Is(err, errNoModSecurity) {
		a.log.Warn("ModSecurity module unusable; sites cannot run the OWASP CRS on this node", "err", err)
	}
	slices.Sort(features)
	a.moduleFeatures = slices.Compact(features)
	a.log.Info("OpenResty modules detected", "features", a.moduleFeatures)
}

// probeModSecurity tests a configuration that loads the ModSecurity module
// and the CRS the way a CRS site would.
func (a *Agent) probeModSecurity(ctx context.Context) error {
	p := a.cfg.Render.WithDefaults()
	if p.ModSecurityModule == "" {
		return errNoModSecurity
	}
	for _, f := range []string{p.ModSecurityModule, filepath.Join(p.CRSDir, "crs-setup.conf"), filepath.Join(p.CRSDir, "rules")} {
		if _, err := os.Stat(f); err != nil {
			return err
		}
	}
	plan := &configir.Plan{Sites: []configir.Site{{ID: "probe", WAF: &configir.WAF{
		Mode: configir.WAFModeDetect, ParanoiaLevel: 1, AnomalyThreshold: 5, RequestBodyLimit: 131072,
		ExcludedRuleIDs: []uint32{920350},
	}}}}
	_, modsec, err := render.ModSecurityConf(p, plan)
	if err != nil {
		return err
	}
	dir := filepath.Join(p.Prefix, "conf")
	modsecPath := filepath.Join(dir, "modsecurity-probe.conf")
	confPath := filepath.Join(dir, "modsecurity-probe.nginx.conf")
	defer func() {
		_ = os.Remove(modsecPath)
		_ = os.Remove(confPath)
	}()
	conf, err := render.ModSecurityProbe(p, modsecPath)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(modsecPath, modsec, 0o644); err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(confPath, conf, 0o644); err != nil {
		return err
	}
	if err := a.engine.Test(ctx, confPath); err != nil {
		return fmt.Errorf("ModSecurity and the OWASP CRS do not load: %w", err)
	}
	return nil
}

// installModSecurityConf writes the CRS configuration plan needs next to
// nginx.conf (named after its content, so the running nginx keeps its own
// file until it reloads). It returns the path, or "" when no site runs the
// CRS.
func (a *Agent) installModSecurityConf(plan *configir.Plan) (string, error) {
	path, conf, err := render.ModSecurityConf(a.cfg.Render, plan)
	if err != nil || path == "" {
		return "", err
	}
	if err := fsutil.WriteFileAtomic(path, conf, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// removeStaleModSecurityConfs deletes the CRS configurations of earlier
// nginx.conf files; keep is the one in use ("" when none).
func (a *Agent) removeStaleModSecurityConfs(keep string) {
	dir := filepath.Join(a.cfg.Render.WithDefaults().Prefix, "conf")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		path := filepath.Join(dir, e.Name())
		if render.IsModSecurityConf(e.Name()) && path != keep {
			if err := os.Remove(path); err != nil {
				a.log.Debug("cannot remove an old ModSecurity configuration", "path", path, "err", err)
			}
		}
	}
}
