package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/apisecurity"
	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func apiTestAgent(t *testing.T) (*Agent, apisecurity.Request) {
	t.Helper()
	raw, err := os.ReadFile("../configir/testdata/content_hash_vector_api_security.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	var cfg nodev1.NodeConfig
	if err := protojson.Unmarshal(vector.Config, &cfg); err != nil {
		t.Fatal(err)
	}
	s, version, err := apisecurity.Parse(cfg.Sites[0].GetApiSecurityJson())
	if err != nil {
		t.Fatal(err)
	}
	s.GraphQL.Mode = "enforce"
	a := &Agent{plan: &configir.Plan{Sites: []configir.Site{{ID: "api-site", APISecurity: s, APISecurityVersion: version}}}}
	req := apisecurity.Request{SiteID: "api-site", Version: version, Method: "POST", Path: "/graphql", RawPath: "/graphql", GraphQLScoped: true, Headers: map[string][]string{"content-type": {"application/json"}}, Body: []byte(`{"query":"{ok}"}`)}
	return a, req
}

func apiPost(t *testing.T, a *Agent, req apisecurity.Request) (int, apisecurity.Result) {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.agentHandler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/api-security/check", bytes.NewReader(raw)))
	var out apisecurity.Result
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return w.Code, out
}

func TestAPISecurityAgentAppliedPlanVersionAndPolicies(t *testing.T) {
	a, req := apiTestAgent(t)
	if status, out := apiPost(t, a, req); status != 200 || out.Status != 0 {
		t.Fatalf("valid request %d %+v", status, out)
	}
	req.Body = []byte(`{"query":"{__schema{types{name}}}"}`)
	if status, out := apiPost(t, a, req); status != 200 || out.Status != 403 || out.Log.Issues[0].Code != "graphql-introspection" {
		t.Fatalf("enforced request %d %+v", status, out)
	}
	req.Version = "older"
	if status, out := apiPost(t, a, req); status != 503 || out.Error != "policy-unavailable" {
		t.Fatalf("mixed versions %d %+v", status, out)
	}
	req.Version = a.plan.Sites[0].APISecurityVersion
	a.mu.Lock()
	a.plan = &configir.Plan{Sites: []configir.Site{}}
	a.mu.Unlock()
	if status, out := apiPost(t, a, req); status != 503 || out.Error != "policy-unavailable" {
		t.Fatalf("removed policy %d %+v", status, out)
	}
}

type heldAPIBody struct {
	entered chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

func (r *heldAPIBody) Read([]byte) (int, error) {
	r.once.Do(func() { r.entered <- struct{}{} })
	<-r.release
	return 0, io.EOF
}
func (r *heldAPIBody) Close() error { return nil }

func TestAPISecurityAgentConcurrencyNeverQueues(t *testing.T) {
	a, _ := apiTestAgent(t)
	handler := a.agentHandler()
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", "/v1/api-security/check", nil)
			r.Body = &heldAPIBody{entered: entered, release: release}
			handler.ServeHTTP(httptest.NewRecorder(), r)
		}()
	}
	defer func() { close(release); wg.Wait() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for i := 0; i < 16; i++ {
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("accepted requests did not enter bounded readers")
		}
	}
	if a.apiSecurityChecks.Load() != 16 {
		t.Fatal("wrong number in flight")
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/v1/api-security/check", nil))
	if w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte("check-overloaded")) {
		t.Fatalf("17th request queued/accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestAPISecurityAgentEnvelopeBudget(t *testing.T) {
	a, _ := apiTestAgent(t)
	for _, raw := range []string{string(bytes.Repeat([]byte{'x'}, 262145)), `{"site_id":"api-site"} {}`, `{"site_id":"api-site","unknown":1}`, string([]byte{'{', '"', 'p', 'a', 't', 'h', '"', ':', '"', 255, '"', '}'})} {
		w := httptest.NewRecorder()
		a.agentHandler().ServeHTTP(w, httptest.NewRequest("POST", "/v1/api-security/check", bytes.NewBufferString(raw)))
		if w.Code != 400 {
			t.Fatalf("envelope accepted %d", w.Code)
		}
	}
}
