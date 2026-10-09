package render

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
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
	// ruleIDEntries numbers the exclusion entries (SiteWaf.exclusions): at
	// most 100 per site for 512 sites, up to 71199, after the site
	// exclusions (10100-10611) and before the CRS (900000).
	ruleIDEntries = 20000
)

// WAFHeader is the internal request header in which the edge layer hands
// ModSecurity a request's site, CRS mode, paranoia level and anomaly
// threshold ("<site>;<mode>;<paranoia>;<threshold>"). Clients cannot send
// X-Edgeweir-* headers: the edge layer removes them first.
const WAFHeader = "X-Edgeweir-Waf"

// WAFExclusionHeader is the internal request header in which the edge
// layer names the exclusion entries (SiteWaf.exclusions) that apply to a
// request's normalized path: their tokens between commas (",<token>,").
const WAFExclusionHeader = "X-Edgeweir-Waf-Ex"

type modsecExclusion struct {
	RuleID  int
	SiteID  string
	RuleIDs []string
}

// modsecEntry is the rule of an exclusion entry: its ctl actions run when
// the edge layer names its token.
type modsecEntry struct {
	RuleID  int
	Token   string
	Actions []string
}

type modsecData struct {
	CRSDir      string
	UnicodeMap  string
	Header      string
	ExHeader    string
	SettingsID  int
	ModeID      int
	Exclusions  []modsecExclusion
	Entries     []modsecEntry
	ModeDetect  string
	HeaderRegex string
}

var tokenHexRE = regexp.MustCompile(`^[0-9a-f]{16}$`)

// entryRule renders exclusion entry e of a site: ctl:ruleRemoveById for
// every rule without targets, else ctl:ruleRemoveTargetById for every rule
// and target.
func entryRule(id int, e configir.WAFExclusion) (modsecEntry, error) {
	if !tokenHexRE.MatchString(e.Token) || len(e.RuleIDs) == 0 {
		return modsecEntry{}, fmt.Errorf("invalid CRS exclusion entry %q", e.Token)
	}
	out := modsecEntry{RuleID: id, Token: e.Token}
	for _, t := range e.Targets {
		if !configir.ValidWAFTarget(t) {
			return modsecEntry{}, fmt.Errorf("invalid CRS exclusion target %q", t)
		}
	}
	for _, rule := range e.RuleIDs {
		if rule < configir.MinWAFRuleID || rule > configir.MaxWAFRuleID {
			return modsecEntry{}, fmt.Errorf("invalid CRS exclusion rule id %d", rule)
		}
		r := strconv.FormatUint(uint64(rule), 10)
		if len(e.Targets) == 0 {
			out.Actions = append(out.Actions, "ctl:ruleRemoveById="+r)
			continue
		}
		for _, t := range e.Targets {
			out.Actions = append(out.Actions, "ctl:ruleRemoveTargetById="+r+";"+t)
		}
	}
	return out, nil
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
		ExHeader:   WAFExclusionHeader,
		SettingsID: ruleIDSettings,
		ModeID:     ruleIDMode,
		ModeDetect: configir.WAFModeDetect,
		// The same bounds as configir.buildWAF; anything else leaves the
		// CRS defaults (paranoia level 1, threshold 5, blocking).
		HeaderRegex: fmt.Sprintf(`^[A-Za-z0-9_-]{1,128};(%s|%s);([%d-%d]);([0-9]{1,4})$`,
			configir.WAFModeDetect, configir.WAFModeBlock, configir.MinParanoiaLevel, configir.MaxParanoiaLevel),
	}
	for _, s := range plan.Sites {
		if s.WAF == nil {
			continue
		}
		for _, e := range s.WAF.Exclusions {
			entry, err := entryRule(ruleIDEntries+len(d.Entries), e)
			if err != nil {
				return "", nil, fmt.Errorf("site %s: %w", s.ID, err)
			}
			d.Entries = append(d.Entries, entry)
		}
		if len(s.WAF.ExcludedRuleIDs) == 0 {
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
