package agent

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/marvinli001/edgeweir-node/internal/challengeverify"
	"github.com/marvinli001/edgeweir-node/internal/configir"
)

// challengeVerifyRequest is what the data plane sends for an answer to a
// site's interactive provider (POST /v1/challenge/verify). The provider's
// settings come from the applied plan, never from the request.
type challengeVerifyRequest struct {
	SiteID    string            `json:"site_id"`
	Answer    map[string]string `json:"answer"`
	RemoteIP  string            `json:"remote_ip"`
	UserAgent string            `json:"user_agent"`
	Host      string            `json:"host"`
}

// challengeVerifyAnswer is pass, fail or unavailable (the data plane then
// serves the built-in image captcha) with the provider's reason.
type challengeVerifyAnswer struct {
	Outcome string `json:"outcome"`
	Reason  string `json:"reason,omitempty"`
}

// maxAnswerFields bounds the widget fields of a request.
const maxAnswerFields = 8

func (a *Agent) serveChallengeVerify(w http.ResponseWriter, r *http.Request) {
	var req challengeVerifyRequest
	raw, err := io.ReadAll(io.LimitReader(r.Body, 32<<10))
	answer := challengeVerifyAnswer{Outcome: challengeverify.Fail, Reason: "bad request"}
	if err == nil && json.Unmarshal(raw, &req) == nil && len(req.Answer) <= maxAnswerFields {
		answer = a.verifyChallenge(r, req)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(answer)
}

// verifyChallenge checks an answer with the site's provider. Without a
// provider in the plan, or without its secret (not fetched yet, or older
// than the plan names), the answer is unavailable.
func (a *Agent) verifyChallenge(r *http.Request, req challengeVerifyRequest) challengeVerifyAnswer {
	a.mu.Lock()
	var provider *configir.ChallengeProvider
	if plan := a.plan; plan != nil {
		for i := range plan.Sites {
			if s := &plan.Sites[i]; s.ID == req.SiteID && s.Protection != nil {
				provider = s.Protection.Interactive
				break
			}
		}
	}
	var stored configir.Credential
	var have bool
	if provider != nil {
		stored, have = a.creds[provider.CredentialID]
	}
	a.mu.Unlock()
	if provider == nil {
		return challengeVerifyAnswer{Outcome: challengeverify.Unavailable, Reason: "no provider"}
	}
	var secret map[string]string
	if !have || stored.Version < provider.CredentialVersion || json.Unmarshal([]byte(stored.SecretKey), &secret) != nil {
		return challengeVerifyAnswer{Outcome: challengeverify.Unavailable, Reason: "secret missing"}
	}
	v := a.cfg.ChallengeVerify
	if v == nil {
		v = &challengeverify.Verifier{}
	}
	res := v.Verify(r.Context(), challengeverify.Request{
		Provider: challengeverify.Provider{Kind: provider.Kind, SiteKey: provider.SiteKey, MinScore: provider.MinScore,
			ProjectID: provider.ProjectID, Region: provider.Region, Prefix: provider.Prefix},
		Secret: secret, Answer: req.Answer, RemoteIP: req.RemoteIP, UserAgent: req.UserAgent, Host: req.Host,
	})
	if res.Outcome == challengeverify.Unavailable {
		a.log.Warn("challenge provider unavailable, the built-in captcha stands in", "site", req.SiteID, "provider", provider.Kind, "reason", res.Reason)
	}
	return challengeVerifyAnswer{Outcome: res.Outcome, Reason: res.Reason}
}
