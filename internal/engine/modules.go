package engine

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Features of the optional OpenResty modules (see configir): Brotli and
// Zstandard are static modules of edgeweir-openresty; ModSecurity is a
// dynamic module the node probes separately.
const (
	FeatureBrotli      = "brotli-v1"
	FeatureZstd        = "zstd-v1"
	FeatureModSecurity = "modsecurity-v1"
)

// ModSecurityModuleFile is the file name of the ModSecurity-nginx dynamic
// module.
const ModSecurityModuleFile = "ngx_http_modsecurity_module.so"

var addModuleRE = regexp.MustCompile(`--add-module=('[^']*'|"[^"]*"|\S+)`)

// ParseModuleFeatures returns the features of the static modules named in
// the configure arguments of `nginx -V` output: ngx_brotli (brotli-v1)
// and zstd-nginx-module (zstd-v1). Only --add-module counts: a dynamic
// module is not part of the binary.
func ParseModuleFeatures(v string) []string {
	var out []string
	for _, line := range strings.Split(v, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "configure arguments:") {
			continue
		}
		for _, m := range addModuleRE.FindAllStringSubmatch(line, -1) {
			dir := strings.TrimRight(strings.Trim(m[1], `'"`), "/")
			switch name := path.Base(dir); {
			case name == "ngx_brotli" || strings.HasPrefix(name, "ngx_brotli-"):
				out = append(out, FeatureBrotli)
			case name == "zstd-nginx-module" || strings.HasPrefix(name, "zstd-nginx-module-"):
				out = append(out, FeatureZstd)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// ModuleFeatures returns the features of the static modules compiled into
// the binary (ParseModuleFeatures of `nginx -V`).
func (n *Nginx) ModuleFeatures(ctx context.Context) ([]string, error) {
	out, err := exec.CommandContext(ctx, n.cfg.Bin, "-V").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s -V: %w", n.cfg.Bin, err)
	}
	return ParseModuleFeatures(string(out)), nil
}

// DefaultModSecurityModule returns where edgeweir-openresty installs the
// ModSecurity module relative to the nginx binary bin (resolved through
// PATH and symlinks): <prefix>/modules next to <prefix>/nginx/sbin/nginx.
// It returns "" when there is no such file.
func DefaultModSecurityModule(bin string) string {
	p, err := exec.LookPath(bin)
	if err != nil {
		return ""
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		return ""
	}
	p, err = filepath.Abs(p)
	if err != nil {
		return ""
	}
	module := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(p))), "modules", ModSecurityModuleFile)
	if st, err := os.Stat(module); err != nil || !st.Mode().IsRegular() {
		return ""
	}
	return module
}
