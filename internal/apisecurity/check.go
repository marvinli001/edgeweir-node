package apisecurity

import (
	"context"
	"encoding/json"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Scope selection is shared with access authentication in Lua. Only the
// local agent socket accepts these fields; the version binds them to the plan.
type Request struct {
	SiteID           string              `json:"site_id"`
	Version          string              `json:"version"`
	Method           string              `json:"method"`
	Path             string              `json:"path"`
	RawPath          string              `json:"raw_path"`
	Query            string              `json:"query"`
	JWTScoped        bool                `json:"jwt_scoped"`
	GraphQLScoped    bool                `json:"graphql_scoped"`
	Headers          map[string][]string `json:"headers"`
	Authorization    []string            `json:"authorization"`
	Body             []byte              `json:"body"`
	BodyTruncated    bool                `json:"body_truncated"`
	HeadersTruncated bool                `json:"headers_truncated"`
	PathAmbiguous    bool                `json:"path_ambiguous"`
}

type Issue struct {
	Check string `json:"check"`
	Code  string `json:"code"`
	Mode  string `json:"mode"`
}
type Log struct {
	Template     string   `json:"template"`
	Source       string   `json:"source"`
	Issues       []Issue  `json:"issues"`
	ExceptionIDs []string `json:"exceptionIds"`
}
type Result struct {
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
	Log    *Log   `json:"log,omitempty"`
}

func (s *Settings) Check(ctx context.Context, req Request, now time.Time) Result {
	e, params, ambiguous := s.endpoint(req.Method, req.Path)
	log := &Log{Template: Discover(req.Path), Source: "traffic", Issues: []Issue{}, ExceptionIDs: []string{}}
	if e != nil && !ambiguous {
		log.Template, log.Source = e.Path, "schema"
	}
	result := Result{Log: log}
	add := func(check, mode, code string) {
		if code == "" {
			return
		}
		if len(log.Issues) < 8 {
			log.Issues = append(log.Issues, Issue{Check: check, Mode: mode, Code: code})
		}
		if mode == "enforce" && result.Status == 0 {
			result.Status = 403
			result.Error = "api-security-" + check
		}
	}
	for _, check := range []struct {
		name, mode string
		selected   bool
	}{
		{"schema", s.Schema.Mode, true}, {"jwt", s.JWT.Mode, req.JWTScoped}, {"graphql", s.GraphQL.Mode, req.GraphQLScoped},
	} {
		if check.mode == "off" || !check.selected {
			continue
		}
		if req.PathAmbiguous || ambiguous || pathAmbiguous(req.RawPath) {
			add(check.name, check.mode, "path-ambiguous")
			continue
		}
		if s.exception(req, check.name, log) {
			continue
		}
		if check.name == "schema" && e == nil {
			if s.Schema.UnknownEndpoints == "block" {
				add(check.name, check.mode, "endpoint-unknown")
			}
			continue
		}
		if ctx.Err() != nil {
			add(check.name, check.mode, "check-deadline")
			continue
		}
		if req.HeadersTruncated {
			add(check.name, check.mode, "headers-budget")
			continue
		}
		if code := headerViolation(req.Headers); code != "" {
			add(check.name, check.mode, code)
			continue
		}
		if check.name != "jwt" && (req.BodyTruncated || len(req.Body) > MaxBodyBytes) {
			add(check.name, check.mode, "body-budget")
			continue
		}
		switch check.name {
		case "schema":
			add(check.name, check.mode, validateEndpoint(ctx, e, params, req))
		case "jwt":
			add(check.name, check.mode, s.verifyJWT(ctx, req.Authorization, now))
		case "graphql":
			add(check.name, check.mode, s.graphql(ctx, req))
		}
	}
	if !s.Discovery.Enabled && len(log.Issues) == 0 && len(log.ExceptionIDs) == 0 {
		result.Log = nil
	}
	return result
}

func (s *Settings) exception(req Request, check string, log *Log) bool {
	skipped := false
	for _, e := range s.Exceptions {
		if e.Enabled && e.Check == check && (e.Method == "*" || e.Method == req.Method) && (check != "schema" || log.Source != "schema" || e.Path == log.Template) {
			if _, ok := matchTemplate(e.Path, req.Path); ok {
				skipped = true
				if len(log.ExceptionIDs) < 8 {
					log.ExceptionIDs = append(log.ExceptionIDs, e.ID)
				}
			}
		}
	}
	return skipped
}

func headerViolation(headers map[string][]string) string {
	total := 0
	names := map[string]bool{}
	if len(headers) > 200 {
		return "headers-budget"
	}
	for name, values := range headers {
		normalized := strings.ToLower(name)
		if names[normalized] || len(values) != 1 {
			return "header-duplicate"
		}
		names[normalized] = true
		if !headerRE.MatchString(name) {
			return "header-invalid"
		}
		total += len(name)
		for _, v := range values {
			total += len(v)
			if strings.ContainsAny(v, "\r\n\x00") {
				return "header-invalid"
			}
		}
	}
	if total > 32768 {
		return "headers-budget"
	}
	return ""
}

// API scopes never honor encoded-path exemptions: differing origin path
// interpretations cannot safely select one endpoint schema or exception.
func pathAmbiguous(path string) bool {
	if path == "" || path[0] != '/' || strings.ContainsAny(path, "\\;#") || strings.Contains(path, "//") {
		return true
	}
	lower := strings.ToLower(path)
	for _, marker := range []string{"%2f", "%5c", "%2e", "%25", "%3b", "%u"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return true
		}
	}
	return false
}

// The fixed dictionary is independent of observed values: random slugs,
// credentials, IDs and unrecognized segments can never become log labels.
var discoveryWords = func() map[string]bool {
	out := map[string]bool{}
	for _, s := range strings.Fields("api v1 v2 v3 v4 graphql query users user accounts account profile profiles auth login logout token tokens oauth sessions session orders order products product items item posts post comments comment search health status metrics events event files file upload uploads download downloads admin public private internal webhooks webhook me settings billing payments payment organizations organization teams team projects project resources resource reports report notifications notification assets static content data rest rpc") {
		out[s] = true
	}
	return out
}()

func Discover(path string) string {
	parts := []string{}
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	if len(parts) > 20 {
		return "/{segment1}"
	}
	for i, p := range parts {
		if !discoveryWords[p] {
			parts[i] = "{segment" + strconv.Itoa(i+1) + "}"
		}
	}
	out := "/" + strings.Join(parts, "/")
	if path != "/" && strings.HasSuffix(path, "/") {
		out += "/"
	}
	return out
}

var issueRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)
var reflectLogType = reflect.TypeFor[Log]()

// LogJSON validates the small metadata envelope again at the data-plane
// boundary; unknown fields and request values never enter the proto log.
func LogJSON(raw json.RawMessage) string {
	if len(raw) == 0 || len(raw) > 4096 {
		return ""
	}
	v, err := decodeJSON(context.Background(), raw, 8, 128)
	if err != nil {
		return ""
	}
	if err := configShape(v, reflectLogType); err != nil {
		return ""
	}
	var log Log
	if json.Unmarshal(raw, &log) != nil || !ValidPath(log.Template) || (log.Source != "traffic" && log.Source != "schema") || len(log.Issues) > 8 || len(log.ExceptionIDs) > 8 {
		return ""
	}
	for _, i := range log.Issues {
		if !check(i.Check) || !issueRE.MatchString(i.Code) || (i.Mode != "observe" && i.Mode != "enforce") {
			return ""
		}
	}
	for _, id := range log.ExceptionIDs {
		if !uuidRE.MatchString(id) {
			return ""
		}
	}
	encoded, _ := json.Marshal(log)
	return string(encoded)
}
