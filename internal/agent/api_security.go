package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/marvinli001/edgeweir-node/internal/apisecurity"
)

func writeAPISecurity(w http.ResponseWriter, status int, result apisecurity.Result) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(result)
}

func (a *Agent) serveAPISecurity(w http.ResponseWriter, r *http.Request) {
	if a.apiSecurityChecks.Add(1) > 16 {
		a.apiSecurityChecks.Add(-1)
		writeAPISecurity(w, 503, apisecurity.Result{Error: "check-overloaded"})
		return
	}
	defer a.apiSecurityChecks.Add(-1)
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 262144))
	if err != nil || !utf8.Valid(raw) {
		writeAPISecurity(w, 400, apisecurity.Result{Error: "request-budget"})
		return
	}
	var req apisecurity.Request
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || len(req.Path) > 8192 || len(req.RawPath) > 8192 || len(req.Query) > 16384 || len(req.Method) > 32 {
		writeAPISecurity(w, 400, apisecurity.Result{Error: "request-budget"})
		return
	}
	if d.Decode(new(any)) != io.EOF {
		writeAPISecurity(w, 400, apisecurity.Result{Error: "request-budget"})
		return
	}
	a.mu.Lock()
	var settings *apisecurity.Settings
	var version string
	if a.plan != nil {
		for i := range a.plan.Sites {
			site := &a.plan.Sites[i]
			if site.ID == req.SiteID {
				settings, version = site.APISecurity, site.APISecurityVersion
				break
			}
		}
	}
	a.mu.Unlock()
	if settings == nil || version == "" || version != req.Version {
		writeAPISecurity(w, 503, apisecurity.Result{Error: "policy-unavailable"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 75*time.Millisecond)
	defer cancel()
	writeAPISecurity(w, 200, settings.Check(ctx, req, time.Now()))
}
