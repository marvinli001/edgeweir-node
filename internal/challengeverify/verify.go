// Package challengeverify checks the answers of third-party CAPTCHA widgets
// (the interactive challenge's providers, feature challenge-v3) with the
// provider's server-side API. The agent calls it for the data plane (agent
// socket POST /v1/challenge/verify), so provider secrets never enter the
// data plane's shared memory.
//
// Every check ends in one of three outcomes: pass, fail (the provider
// rejected the answer) or unavailable (the provider could not be asked:
// timeout, network or server error, an answer that cannot be read, or the
// provider refused our credentials). The data plane serves the built-in
// image captcha after unavailable, so visitors are never locked out by a
// provider outage or a misconfigured key.
package challengeverify

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Outcomes of a check.
const (
	Pass        = "pass"
	Fail        = "fail"
	Unavailable = "unavailable"
)

// Action is the reCAPTCHA v3 / Enterprise and Turnstile action the
// challenge page names; answers for another action fail.
const Action = "edgeweir_challenge"

// Timeout bounds one call to a provider.
const Timeout = 3 * time.Second

// maxBody bounds a provider's answer.
const maxBody = 64 << 10

// Provider is the public part of a site's interactive provider
// (configir.ChallengeProvider).
type Provider struct {
	Kind      string
	SiteKey   string
	MinScore  uint32 // hundredths
	ProjectID string
	Region    string // aliyun: cn or sgp
	Prefix    string
}

// Request is one answer to check.
type Request struct {
	Provider Provider
	// Secret holds the kind's secret fields (contract CHALLENGE_PROVIDER_SECRETS).
	Secret map[string]string
	// Answer holds what the widget produced: token (turnstile, recaptcha*),
	// ticket and randstr (tencent), param (aliyun), lot_number,
	// captcha_output, pass_token and gen_time (geetest).
	Answer map[string]string
	// RemoteIP and UserAgent of the visitor, Host the site's host name the
	// page was served on.
	RemoteIP  string
	UserAgent string
	Host      string
}

// Result is the outcome and the provider's reason (an error code, a score).
type Result struct {
	Outcome string
	Reason  string
}

// Verifier calls the providers.
type Verifier struct {
	// Client sends the requests; nil uses a client with Timeout.
	Client *http.Client
	// Endpoints replaces a kind's verification URL (tests and the e2e mock):
	// turnstile, recaptcha (v2 and v3), recaptcha_enterprise (base URL
	// before /v1/projects), tencent, aliyun (base URL), geetest.
	Endpoints map[string]string
	// Now is the clock of signatures (nil: time.Now).
	Now func() time.Time
}

// Default endpoints.
const (
	turnstileURL  = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	recaptchaURL  = "https://www.google.com/recaptcha/api/siteverify"
	enterpriseURL = "https://recaptchaenterprise.googleapis.com"
	tencentURL    = "https://captcha.tencentcloudapi.com"
	geetestURL    = "https://gcaptcha4.geetest.com/validate"
)

func aliyunURL(region string) string {
	if region == "sgp" {
		return "https://captcha.ap-southeast-1.aliyuncs.com"
	}
	return "https://captcha.cn-shanghai.aliyuncs.com"
}

func (v *Verifier) endpoint(kind, def string) string {
	if u, ok := v.Endpoints[kind]; ok && u != "" {
		return u
	}
	return def
}

func (v *Verifier) now() time.Time {
	if v.Now != nil {
		return v.Now()
	}
	return time.Now()
}

func (v *Verifier) client() *http.Client {
	if v.Client != nil {
		return v.Client
	}
	return &http.Client{Timeout: Timeout}
}

var errUnreadable = errors.New("unreadable answer")

// unavailable reports an outcome that lets the data plane fall back.
func unavailable(reason string) Result { return Result{Outcome: Unavailable, Reason: reason} }

// Verify checks one answer. It never returns pass without the provider's
// confirmation.
func (v *Verifier) Verify(ctx context.Context, r Request) Result {
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	for _, field := range secretFields[r.Provider.Kind] {
		if r.Secret[field] == "" {
			return unavailable("secret missing")
		}
	}
	switch r.Provider.Kind {
	case "turnstile":
		return v.siteverify(ctx, r, v.endpoint("turnstile", turnstileURL), false)
	case "recaptcha_v2":
		return v.siteverify(ctx, r, v.endpoint("recaptcha", recaptchaURL), false)
	case "recaptcha_v3":
		return v.siteverify(ctx, r, v.endpoint("recaptcha", recaptchaURL), true)
	case "recaptcha_enterprise":
		return v.enterprise(ctx, r)
	case "tencent":
		return v.tencent(ctx, r)
	case "aliyun":
		return v.aliyun(ctx, r)
	case "geetest":
		return v.geetest(ctx, r)
	}
	return unavailable("unsupported provider")
}

// secretFields are the secret fields each kind needs.
var secretFields = map[string][]string{
	"turnstile":            {"secret"},
	"recaptcha_v2":         {"secret"},
	"recaptcha_v3":         {"secret"},
	"recaptcha_enterprise": {"apiKey"},
	"tencent":              {"secretId", "secretKey", "appSecretKey"},
	"aliyun":               {"accessKeyId", "accessKeySecret"},
	"geetest":              {"captchaKey"},
}

// answerField returns an answer field, or "" when it is missing or longer
// than max bytes.
func answerField(r Request, name string, max int) string {
	v := r.Answer[name]
	if len(v) > max {
		return ""
	}
	return v
}

// do sends req and decodes a JSON answer into out. A transport error, a
// status other than 2xx (or 4xx when accept4xx) or an unreadable body is
// errUnreadable or the transport error.
func (v *Verifier) do(req *http.Request, out any, accept4xx bool) (int, error) {
	resp, err := v.client().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return resp.StatusCode, err
	}
	ok := resp.StatusCode/100 == 2 || (accept4xx && resp.StatusCode/100 == 4)
	if !ok {
		return resp.StatusCode, fmt.Errorf("status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return resp.StatusCode, errUnreadable
	}
	return resp.StatusCode, nil
}

func reasonOf(err error) string {
	var ne interface{ Timeout() bool }
	if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	return err.Error()
}

// siteverify checks Turnstile and reCAPTCHA v2 / v3 tokens: the same form
// API. v3 also needs the action and the minimum score.
func (v *Verifier) siteverify(ctx context.Context, r Request, endpoint string, scored bool) Result {
	token := answerField(r, "token", 4096)
	if token == "" {
		return Result{Outcome: Fail, Reason: "missing-input-response"}
	}
	form := url.Values{"secret": {r.Secret["secret"]}, "response": {token}}
	if r.RemoteIP != "" {
		form.Set("remoteip", r.RemoteIP)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return unavailable(err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var answer struct {
		Success  bool     `json:"success"`
		Hostname string   `json:"hostname"`
		Action   string   `json:"action"`
		Score    *float64 `json:"score"`
		Errors   []string `json:"error-codes"`
	}
	if _, err := v.do(req, &answer, false); err != nil {
		return unavailable(reasonOf(err))
	}
	if !answer.Success {
		reason := strings.Join(answer.Errors, ",")
		for _, code := range answer.Errors {
			// Our key, not the visitor's answer: let the data plane fall back.
			switch code {
			case "missing-input-secret", "invalid-input-secret", "internal-error", "bad-request":
				return unavailable(reason)
			}
		}
		return Result{Outcome: Fail, Reason: reason}
	}
	if r.Host != "" && answer.Hostname != "" && !strings.EqualFold(answer.Hostname, r.Host) {
		return Result{Outcome: Fail, Reason: "hostname-mismatch"}
	}
	if scored {
		if answer.Action != Action {
			return Result{Outcome: Fail, Reason: "action-mismatch"}
		}
		if answer.Score == nil || !scorePasses(*answer.Score, r.Provider.MinScore) {
			return Result{Outcome: Fail, Reason: "low-score"}
		}
	}
	return Result{Outcome: Pass}
}

// scorePasses compares a 0.0-1.0 score with a minimum in hundredths.
func scorePasses(score float64, min uint32) bool {
	if min == 0 {
		min = 50
	}
	return math.Round(score*100) >= float64(min)
}

// enterprise checks a reCAPTCHA Enterprise token with an assessment.
func (v *Verifier) enterprise(ctx context.Context, r Request) Result {
	token := answerField(r, "token", 4096)
	if token == "" {
		return Result{Outcome: Fail, Reason: "MISSING"}
	}
	body, _ := json.Marshal(map[string]any{"event": map[string]string{
		"token": token, "siteKey": r.Provider.SiteKey, "expectedAction": Action,
		"userIpAddress": r.RemoteIP, "userAgent": r.UserAgent,
	}})
	endpoint := v.endpoint("recaptcha_enterprise", enterpriseURL) + "/v1/projects/" + url.PathEscape(r.Provider.ProjectID) +
		"/assessments?key=" + url.QueryEscape(r.Secret["apiKey"])
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return unavailable(err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	var answer struct {
		TokenProperties struct {
			Valid         bool   `json:"valid"`
			InvalidReason string `json:"invalidReason"`
			Hostname      string `json:"hostname"`
			Action        string `json:"action"`
		} `json:"tokenProperties"`
		RiskAnalysis struct {
			Score *float64 `json:"score"`
		} `json:"riskAnalysis"`
	}
	if _, err := v.do(req, &answer, false); err != nil {
		return unavailable(reasonOf(err))
	}
	tp := answer.TokenProperties
	switch {
	case !tp.Valid:
		return Result{Outcome: Fail, Reason: tp.InvalidReason}
	case tp.Action != Action:
		return Result{Outcome: Fail, Reason: "UNEXPECTED_ACTION"}
	case r.Host != "" && tp.Hostname != "" && !strings.EqualFold(tp.Hostname, r.Host):
		return Result{Outcome: Fail, Reason: "hostname-mismatch"}
	case answer.RiskAnalysis.Score == nil || !scorePasses(*answer.RiskAnalysis.Score, r.Provider.MinScore):
		return Result{Outcome: Fail, Reason: "low-score"}
	}
	return Result{Outcome: Pass}
}

// tencentFailCodes are CaptchaCode values that reject the visitor's
// ticket (randstr mismatch, expired, reused, cannot be decrypted, another
// app's, flagged as risky); other codes but 1 (OK), such as 100 (app id
// and secret do not match), are our configuration or the service.
var tencentFailCodes = map[int]bool{7: true, 8: true, 9: true, 15: true, 16: true, 21: true}

// tencent checks a ticket with DescribeCaptchaResult (TC3-HMAC-SHA256).
// A disaster-recovery ticket ("trerror_", the widget could not load) is
// unavailable without asking.
func (v *Verifier) tencent(ctx context.Context, r Request) Result {
	ticket, randstr := answerField(r, "ticket", 4096), answerField(r, "randstr", 256)
	if strings.HasPrefix(ticket, "trerror_") {
		return unavailable("widget unavailable")
	}
	if ticket == "" || randstr == "" {
		return Result{Outcome: Fail, Reason: "missing ticket"}
	}
	appID, err := strconv.ParseUint(r.Provider.SiteKey, 10, 64)
	if err != nil {
		return unavailable("CaptchaAppId is not a number")
	}
	payload, _ := json.Marshal(map[string]any{
		"CaptchaType": 9, "Ticket": ticket, "UserIp": r.RemoteIP, "Randstr": randstr,
		"CaptchaAppId": appID, "AppSecretKey": r.Secret["appSecretKey"],
	})
	endpoint := v.endpoint("tencent", tencentURL)
	u, err := url.Parse(endpoint)
	if err != nil {
		return unavailable(err.Error())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return unavailable(err.Error())
	}
	now := v.now().UTC()
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-TC-Action", "DescribeCaptchaResult")
	req.Header.Set("X-TC-Version", "2019-07-22")
	req.Header.Set("X-TC-Timestamp", strconv.FormatInt(now.Unix(), 10))
	req.Header.Set("Authorization", TC3Authorization(r.Secret["secretId"], r.Secret["secretKey"], "captcha", u.Host, payload, now))
	var answer struct {
		Response struct {
			CaptchaCode *int   `json:"CaptchaCode"`
			CaptchaMsg  string `json:"CaptchaMsg"`
			Error       *struct {
				Code string `json:"Code"`
			} `json:"Error"`
		} `json:"Response"`
	}
	if _, err := v.do(req, &answer, false); err != nil {
		return unavailable(reasonOf(err))
	}
	resp := answer.Response
	switch {
	case resp.Error != nil:
		return unavailable(resp.Error.Code)
	case resp.CaptchaCode == nil:
		return unavailable("no CaptchaCode")
	case *resp.CaptchaCode == 1:
		return Result{Outcome: Pass}
	case tencentFailCodes[*resp.CaptchaCode]:
		return Result{Outcome: Fail, Reason: strconv.Itoa(*resp.CaptchaCode)}
	}
	return unavailable("CaptchaCode " + strconv.Itoa(*resp.CaptchaCode))
}

// TC3Authorization is the Authorization header of a Tencent Cloud API 3.0
// POST with a JSON body (signed headers content-type and host).
func TC3Authorization(secretID, secretKey, service, host string, payload []byte, t time.Time) string {
	date := t.UTC().Format("2006-01-02")
	canonical := strings.Join([]string{
		"POST", "/", "",
		"content-type:application/json; charset=utf-8\nhost:" + host + "\n",
		"content-type;host",
		sha256Hex(payload),
	}, "\n")
	scope := date + "/" + service + "/tc3_request"
	toSign := strings.Join([]string{"TC3-HMAC-SHA256", strconv.FormatInt(t.Unix(), 10), scope, sha256Hex([]byte(canonical))}, "\n")
	key := hmacSHA256([]byte("TC3"+secretKey), date)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(key, toSign))
	return "TC3-HMAC-SHA256 Credential=" + secretID + "/" + scope + ", SignedHeaders=content-type;host, Signature=" + signature
}

// aliyun checks a CaptchaVerifyParam with VerifyIntelligentCaptcha (V3
// signature ACS3-HMAC-SHA256).
func (v *Verifier) aliyun(ctx context.Context, r Request) Result {
	param := answerField(r, "param", 8192)
	if param == "" {
		return Result{Outcome: Fail, Reason: "missing CaptchaVerifyParam"}
	}
	body := url.Values{"CaptchaVerifyParam": {param}, "SceneId": {r.Provider.SiteKey}}.Encode()
	endpoint := v.endpoint("aliyun", aliyunURL(r.Provider.Region))
	u, err := url.Parse(endpoint)
	if err != nil {
		return unavailable(err.Error())
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(endpoint, "/")+"/", strings.NewReader(body))
	if err != nil {
		return unavailable(err.Error())
	}
	nonce := make([]byte, 16)
	_, _ = rand.Read(nonce)
	headers := map[string]string{
		"content-type":          "application/x-www-form-urlencoded",
		"host":                  u.Host,
		"x-acs-action":          "VerifyIntelligentCaptcha",
		"x-acs-content-sha256":  sha256Hex([]byte(body)),
		"x-acs-date":            v.now().UTC().Format("2006-01-02T15:04:05Z"),
		"x-acs-signature-nonce": hex.EncodeToString(nonce),
		"x-acs-version":         "2023-03-05",
	}
	for k, val := range headers {
		if k != "host" {
			req.Header.Set(k, val)
		}
	}
	req.Header.Set("Authorization", ACS3Authorization(r.Secret["accessKeyId"], r.Secret["accessKeySecret"], "POST", "/", "", headers, []byte(body)))
	var answer struct {
		Success *bool  `json:"Success"`
		Code    string `json:"Code"`
		Result  *struct {
			VerifyResult bool   `json:"VerifyResult"`
			VerifyCode   string `json:"VerifyCode"`
		} `json:"Result"`
	}
	if _, err := v.do(req, &answer, false); err != nil {
		return unavailable(reasonOf(err))
	}
	switch {
	case answer.Success != nil && !*answer.Success, answer.Result == nil:
		return unavailable(answer.Code)
	case answer.Result.VerifyResult:
		return Result{Outcome: Pass, Reason: answer.Result.VerifyCode}
	}
	return Result{Outcome: Fail, Reason: answer.Result.VerifyCode}
}

// ACS3Authorization is the Authorization header of an Alibaba Cloud V3
// signature (ACS3-HMAC-SHA256); query is the canonical query string
// (sorted, encoded, "" for none) and every header given is signed.
func ACS3Authorization(accessKeyID, accessKeySecret, method, path, query string, headers map[string]string, body []byte) string {
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	var canonicalHeaders strings.Builder
	for _, k := range names {
		canonicalHeaders.WriteString(k + ":" + strings.TrimSpace(headers[k]) + "\n")
	}
	signed := strings.Join(names, ";")
	canonical := strings.Join([]string{method, path, query, canonicalHeaders.String(), signed, sha256Hex(body)}, "\n")
	signature := hex.EncodeToString(hmacSHA256([]byte(accessKeySecret), "ACS3-HMAC-SHA256\n"+sha256Hex([]byte(canonical))))
	return "ACS3-HMAC-SHA256 Credential=" + accessKeyID + ",SignedHeaders=" + signed + ",Signature=" + signature
}

// geetest checks a GeeTest v4 answer with /validate.
func (v *Verifier) geetest(ctx context.Context, r Request) Result {
	lot, output := answerField(r, "lot_number", 128), answerField(r, "captcha_output", 4096)
	pass, gen := answerField(r, "pass_token", 512), answerField(r, "gen_time", 32)
	if lot == "" || output == "" || pass == "" || gen == "" {
		return Result{Outcome: Fail, Reason: "missing answer"}
	}
	form := url.Values{
		"lot_number": {lot}, "captcha_output": {output}, "pass_token": {pass}, "gen_time": {gen},
		"sign_token": {hex.EncodeToString(hmacSHA256([]byte(r.Secret["captchaKey"]), lot))},
	}
	endpoint := v.endpoint("geetest", geetestURL) + "?captcha_id=" + url.QueryEscape(r.Provider.SiteKey)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return unavailable(err.Error())
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var answer struct {
		Status string `json:"status"`
		Code   string `json:"code"`
		Result string `json:"result"`
		Reason string `json:"reason"`
	}
	if _, err := v.do(req, &answer, false); err != nil {
		return unavailable(reasonOf(err))
	}
	switch {
	case answer.Status == "error":
		return unavailable(answer.Code)
	case answer.Result == "success":
		return Result{Outcome: Pass}
	case answer.Result == "fail":
		return Result{Outcome: Fail, Reason: answer.Reason}
	}
	return unavailable("unknown result")
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}
