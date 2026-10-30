package agent

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/challengeverify"
	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// TestServeChallengeVerify: the agent verifies an answer with the provider and
// the secret of the applied plan, and answers unavailable (the data plane
// falls back) while either is missing or the secret is older than the plan.
func TestServeChallengeVerify(t *testing.T) {
	var gotSecret string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotSecret = r.PostForm.Get("secret")
		ok := r.PostForm.Get("response") == "good-token"
		_ = json.NewEncoder(w).Encode(map[string]any{"success": ok, "hostname": "shop.test"})
	}))
	defer provider.Close()

	a := &Agent{
		cfg: Config{ChallengeVerify: &challengeverify.Verifier{Endpoints: map[string]string{"turnstile": provider.URL}}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		plan: &configir.Plan{Sites: []configir.Site{
			{ID: "site-p", Protection: &configir.Protection{Interactive: &configir.ChallengeProvider{
				Kind: "turnstile", SiteKey: "site-key-fake", CredentialID: "cp-1", CredentialVersion: 2,
			}}},
			{ID: "site-b", Protection: &configir.Protection{}},
		}},
		creds: map[string]configir.Credential{"cp-1": {Version: 2, SecretKey: `{"secret":"fake-turnstile-secret"}`}},
	}
	ask := func(body string) challengeVerifyAnswer {
		t.Helper()
		rec := httptest.NewRecorder()
		a.serveChallengeVerify(rec, httptest.NewRequest(http.MethodPost, "/v1/challenge/verify", strings.NewReader(body)))
		var out challengeVerifyAnswer
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if got := ask(`{"site_id":"site-p","answer":{"token":"good-token"},"host":"shop.test"}`); got.Outcome != challengeverify.Pass {
		t.Fatalf("good token: %+v", got)
	}
	if gotSecret != "fake-turnstile-secret" {
		t.Fatalf("provider got secret %q", gotSecret)
	}
	if got := ask(`{"site_id":"site-p","answer":{"token":"bad-token"},"host":"shop.test"}`); got.Outcome != challengeverify.Fail {
		t.Fatalf("bad token: %+v", got)
	}
	if got := ask(`{"site_id":"site-b","answer":{"token":"good-token"}}`); got.Outcome != challengeverify.Unavailable || got.Reason != "no provider" {
		t.Fatalf("site without provider: %+v", got)
	}
	if got := ask(`not json`); got.Outcome != challengeverify.Fail {
		t.Fatalf("bad request: %+v", got)
	}
	if got := ask(`{"site_id":"site-p","answer":{"a":"1","b":"1","c":"1","d":"1","e":"1","f":"1","g":"1","h":"1","i":"1"}}`); got.Outcome != challengeverify.Fail {
		t.Fatalf("too many fields: %+v", got)
	}

	a.creds["cp-1"] = configir.Credential{Version: 1, SecretKey: `{"secret":"fake-turnstile-secret"}`}
	if got := ask(`{"site_id":"site-p","answer":{"token":"good-token"}}`); got.Outcome != challengeverify.Unavailable || got.Reason != "secret missing" {
		t.Fatalf("older secret: %+v", got)
	}
	delete(a.creds, "cp-1")
	if got := ask(`{"site_id":"site-p","answer":{"token":"good-token"}}`); got.Outcome != challengeverify.Unavailable {
		t.Fatalf("no secret: %+v", got)
	}
}
