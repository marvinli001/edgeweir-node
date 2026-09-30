package render

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

//go:embed modsecurity.conf.tmpl
var modsecTemplate string

var modsecTmpl = template.Must(template.New("modsecurity.conf").
	Option("missingkey=error").
	Parse(modsecTemplate))

// ModSecurity rule ids of the generated configuration (the range 1-99999
// is reserved for local rules; the CRS uses 900000-999999).
const (
	ruleIDSettings   = 10000
	ruleIDMode       = 10001
	ruleIDExclusions = 10100
)

// WAFHeader is the internal request header in which the edge layer hands
// ModSecurity a request's site, CRS mode, paranoia level and anomaly
// threshold ("<site>;<mode>;<paranoia>;<threshold>"). Clients cannot send
// X-Edgeweir-* headers: the edge layer removes them first.
const WAFHeader = "X-Edgeweir-Waf"

type modsecExclusion struct {
	RuleID  int
	SiteID  string
	RuleIDs []string
}

type modsecData struct {
	CRSDir      string
	UnicodeMap  string
	Header      string
	SettingsID  int
	ModeID      int
	Exclusions  []modsecExclusion
	ModeDetect  string
	HeaderRegex string
}

// ModSecurityConf returns the path (in the nginx prefix's conf directory,
// named after its content) and the contents of the ModSecurity
// configuration nginx.conf loads when a site of plan runs the OWASP CRS,
// or "" and nil when none does. The file holds the engine settings, the
// per-request settings rule reading WAFHeader, each site's excluded rules
// and the CRS itself.
func ModSecurityConf(p Params, plan *configir.Plan) (string, []byte, error) {
	p = p.WithDefaults()
	if plan == nil || !plan.UsesWAF() {
		return "", nil, nil
	}
	if p.ModSecurityModule == "" {
		return "", nil, errors.New("a site runs the OWASP CRS, but this node has no ModSecurity module")
	}
	for name, v := range map[string]string{"ModSecurity module": p.ModSecurityModule, "CRS directory": p.CRSDir} {
		if !safePath.MatchString(v) {
			return "", nil, fmt.Errorf("%s %q must be an absolute path without spaces or special characters", name, v)
		}
	}
	if p.ModSecurityUnicodeMap != "" && !safePath.MatchString(p.ModSecurityUnicodeMap) {
		return "", nil, fmt.Errorf("unicode map %q must be an absolute path without spaces or special characters", p.ModSecurityUnicodeMap)
	}
	d := modsecData{
		CRSDir:     p.CRSDir,
		UnicodeMap: p.ModSecurityUnicodeMap,
		Header:     WAFHeader,
		SettingsID: ruleIDSettings,
		ModeID:     ruleIDMode,
		ModeDetect: configir.WAFModeDetect,
		// The same bounds as configir.buildWAF; anything else leaves the
		// CRS defaults (paranoia level 1, threshold 5, blocking).
		HeaderRegex: fmt.Sprintf(`^[A-Za-z0-9_-]{1,128};(%s|%s);([%d-%d]);([0-9]{1,4})$`,
			configir.WAFModeDetect, configir.WAFModeBlock, configir.MinParanoiaLevel, configir.MaxParanoiaLevel),
	}
	for _, s := range plan.Sites {
		if s.WAF == nil || len(s.WAF.ExcludedRuleIDs) == 0 {
			continue
		}
		if !configir.ValidID(s.ID) {
			return "", nil, fmt.Errorf("invalid site id %q", s.ID)
		}
		ex := modsecExclusion{RuleID: ruleIDExclusions + len(d.Exclusions), SiteID: s.ID}
		for _, id := range s.WAF.ExcludedRuleIDs {
			ex.RuleIDs = append(ex.RuleIDs, strconv.FormatUint(uint64(id), 10))
		}
		d.Exclusions = append(d.Exclusions, ex)
	}
	var buf bytes.Buffer
	if err := modsecTmpl.Execute(&buf, d); err != nil {
		return "", nil, fmt.Errorf("render ModSecurity configuration: %w", err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return filepath.Join(p.Prefix, "conf", "modsecurity-"+hex.EncodeToString(sum[:])[:16]+".conf"), buf.Bytes(), nil
}

// IsModSecurityConf reports whether name is a file name ModSecurityConf
// generates (the agent removes the ones nginx.conf no longer uses).
func IsModSecurityConf(name string) bool {
	hash, ok := strings.CutPrefix(name, "modsecurity-")
	if !ok {
		return false
	}
	hash, ok = strings.CutSuffix(hash, ".conf")
	if !ok || len(hash) != 16 {
		return false
	}
	_, err := hex.DecodeString(hash)
	return err == nil
}

// ModSecurityProbe returns an nginx.conf that loads the ModSecurity module
// and the CRS configuration at modsecConf (see ModSecurityConf) without
// listening anywhere: `nginx -t` on it tells whether the node can run the
// CRS.
func ModSecurityProbe(p Params, modsecConf string) ([]byte, error) {
	p = p.WithDefaults()
	for name, v := range map[string]string{"ModSecurity module": p.ModSecurityModule, "ModSecurity configuration": modsecConf, "nginx prefix": p.Prefix} {
		if !safePath.MatchString(v) {
			return nil, fmt.Errorf("%s %q must be an absolute path without spaces or special characters", name, v)
		}
	}
	return []byte(fmt.Sprintf(`# edgeweir-node: can this node run the OWASP CRS?
load_module %s;
pid %s/logs/modsecurity-probe.pid;
error_log stderr notice;
events {
    worker_connections 16;
}
http {
    modsecurity_rules_file %s;
    server {
        listen unix:%s/tmp/modsecurity-probe.sock;
        location / {
            modsecurity on;
            return 204;
        }
    }
}
`, p.ModSecurityModule, p.Prefix, modsecConf, p.Prefix)), nil
}
