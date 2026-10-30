package challengeverify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recorded serves a testdata answer with status and keeps the last request.
type recorded struct {
	t       *testing.T
	file    string
	status  int
	delay   time.Duration
	method  string
	path    string
	query   url.Values
	headers http.Header
	body    string
}

func (rc *recorded) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	rc.method, rc.path, rc.query, rc.headers, rc.body = r.Method, r.URL.Path, r.URL.Query(), r.Header.Clone(), string(raw)
	if rc.delay > 0 {
		select {
		case <-time.After(rc.delay):
		case <-r.Context().Done():
			return
		}
	}
	answer, err := os.ReadFile(filepath.Join("testdata", rc.file))
	if err != nil {
		rc.t.Fatal(err)
	}
	w.Header().Set("Content-Type", "application/json")
	if rc.status != 0 {
		w.WriteHeader(rc.status)
	}
	_, _ = w.Write(answer)
}

func serve(t *testing.T, file string, status int) (*recorded, string) {
	t.Helper()
	rc := &recorded{t: t, file: file, status: status}
	srv := httptest.NewServer(rc)
	t.Cleanup(srv.Close)
	return rc, srv.URL
}

var fixed = time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)

func verifier(kind, endpoint string) *Verifier {
	return &Verifier{Endpoints: map[string]string{kind: endpoint}, Now: func() time.Time { return fixed }}
}

func TestSiteverifyProviders(t *testing.T) {
	cases := []struct {
		name, kind, endpoint, file string
		status                     int
		host                       string
		minScore                   uint32
		want                       string
	}{
		{"turnstile pass", "turnstile", "turnstile", "turnstile_pass.json", 0, "www.example.com", 0, Pass},
		{"turnstile spent token", "turnstile", "turnstile", "turnstile_spent.json", 0, "www.example.com", 0, Fail},
		{"turnstile other host", "turnstile", "turnstile", "turnstile_pass.json", 0, "evil.example.net", 0, Fail},
		{"turnstile our secret is wrong", "turnstile", "turnstile", "turnstile_bad_secret.json", 0, "", 0, Unavailable},
		{"turnstile server error", "turnstile", "turnstile", "turnstile_pass.json", 502, "", 0, Unavailable},
		{"recaptcha v2 pass", "recaptcha_v2", "recaptcha", "recaptcha_v2_pass.json", 0, "www.example.com", 0, Pass},
		{"recaptcha v2 invalid", "recaptcha_v2", "recaptcha", "recaptcha_invalid.json", 0, "", 0, Fail},
		{"recaptcha v3 pass", "recaptcha_v3", "recaptcha", "recaptcha_v3_pass.json", 0, "www.example.com", 50, Pass},
		{"recaptcha v3 low score", "recaptcha_v3", "recaptcha", "recaptcha_v3_low.json", 0, "www.example.com", 50, Fail},
		{"recaptcha v3 score at the minimum", "recaptcha_v3", "recaptcha", "recaptcha_v3_low.json", 0, "www.example.com", 30, Pass},
		{"recaptcha v3 without action", "recaptcha_v3", "recaptcha", "recaptcha_v2_pass.json", 0, "", 50, Fail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rc, u := serve(t, c.file, c.status)
			got := verifier(c.endpoint, u).Verify(context.Background(), Request{
				Provider: Provider{Kind: c.kind, SiteKey: "site-key", MinScore: c.minScore},
				Secret:   map[string]string{"secret": "the-secret"},
				Answer:   map[string]string{"token": "tok"},
				RemoteIP: "203.0.113.7", Host: c.host,
			})
			if got.Outcome != c.want {
				t.Fatalf("outcome %+v, want %s", got, c.want)
			}
			form, _ := url.ParseQuery(rc.body)
			if rc.method != http.MethodPost || form.Get("secret") != "the-secret" || form.Get("response") != "tok" || form.Get("remoteip") != "203.0.113.7" {
				t.Fatalf("request %s %v", rc.method, form)
			}
		})
	}
}

func TestMissingAnswerOrSecret(t *testing.T) {
	v := verifier("turnstile", "http://127.0.0.1:1")
	if got := v.Verify(context.Background(), Request{Provider: Provider{Kind: "turnstile"}, Secret: map[string]string{"secret": "s"}}); got.Outcome != Fail {
		t.Fatalf("no token: %+v", got)
	}
	if got := v.Verify(context.Background(), Request{Provider: Provider{Kind: "turnstile"}, Answer: map[string]string{"token": "t"}}); got.Outcome != Unavailable {
		t.Fatalf("no secret: %+v", got)
	}
	if got := v.Verify(context.Background(), Request{Provider: Provider{Kind: "turnstile"}, Secret: map[string]string{"secret": "s"},
		Answer: map[string]string{"token": strings.Repeat("x", 5000)}}); got.Outcome != Fail {
		t.Fatalf("oversized token: %+v", got)
	}
	if got := v.Verify(context.Background(), Request{Provider: Provider{Kind: "nope"}}); got.Outcome != Unavailable {
		t.Fatalf("unknown kind: %+v", got)
	}
}

func TestTimeoutAndNetworkErrorsAreUnavailable(t *testing.T) {
	rc := &recorded{t: t, file: "turnstile_pass.json", delay: 2 * time.Second}
	srv := httptest.NewServer(rc)
	defer srv.Close()
	v := verifier("turnstile", srv.URL)
	v.Client = &http.Client{Timeout: 100 * time.Millisecond}
	got := v.Verify(context.Background(), Request{Provider: Provider{Kind: "turnstile"}, Secret: map[string]string{"secret": "s"}, Answer: map[string]string{"token": "t"}})
	if got.Outcome != Unavailable || got.Reason != "timeout" {
		t.Fatalf("slow provider: %+v", got)
	}
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	got = verifier("turnstile", closed.URL).Verify(context.Background(), Request{Provider: Provider{Kind: "turnstile"},
		Secret: map[string]string{"secret": "s"}, Answer: map[string]string{"token": "t"}})
	if got.Outcome != Unavailable {
		t.Fatalf("refused connection: %+v", got)
	}
	// An answer that is not JSON.
	html := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) }))
	defer html.Close()
	got = verifier("turnstile", html.URL).Verify(context.Background(), Request{Provider: Provider{Kind: "turnstile"},
		Secret: map[string]string{"secret": "s"}, Answer: map[string]string{"token": "t"}})
	if got.Outcome != Unavailable {
		t.Fatalf("unreadable answer: %+v", got)
	}
}

func TestEnterprise(t *testing.T) {
	for _, c := range []struct {
		file   string
		status int
		want   string
	}{{"enterprise_pass.json", 0, Pass}, {"enterprise_dupe.json", 0, Fail}, {"enterprise_pass.json", 403, Unavailable}} {
		rc, u := serve(t, c.file, c.status)
		got := verifier("recaptcha_enterprise", u).Verify(context.Background(), Request{
			Provider: Provider{Kind: "recaptcha_enterprise", SiteKey: "6Lc-site", ProjectID: "my-project", MinScore: 50},
			Secret:   map[string]string{"apiKey": "AIza-key"}, Answer: map[string]string{"token": "tok"},
			RemoteIP: "203.0.113.7", UserAgent: "Mozilla/5.0", Host: "www.example.com",
		})
		if got.Outcome != c.want {
			t.Fatalf("%s %d: %+v, want %s", c.file, c.status, got, c.want)
		}
		var body struct {
			Event map[string]string `json:"event"`
		}
		if err := json.Unmarshal([]byte(rc.body), &body); err != nil {
			t.Fatal(err)
		}
		if rc.path != "/v1/projects/my-project/assessments" || rc.query.Get("key") != "AIza-key" ||
			body.Event["token"] != "tok" || body.Event["siteKey"] != "6Lc-site" || body.Event["expectedAction"] != Action ||
			body.Event["userIpAddress"] != "203.0.113.7" {
			t.Fatalf("request %s %v %s", rc.path, rc.query, rc.body)
		}
	}
}

func TestTencent(t *testing.T) {
	for _, c := range []struct {
		file   string
		ticket string
		want   string
	}{
		{"tencent_pass.json", "t03abc", Pass},
		{"tencent_reused.json", "t03abc", Fail},
		{"tencent_auth_error.json", "t03abc", Unavailable},
		{"tencent_pass.json", "trerror_1001_190000000_1793347200", Unavailable},
	} {
		rc, u := serve(t, c.file, 0)
		got := verifier("tencent", u).Verify(context.Background(), Request{
			Provider: Provider{Kind: "tencent", SiteKey: "190000000"},
			Secret:   map[string]string{"secretId": "AKIDexample", "secretKey": "secret-key", "appSecretKey": "app-secret"},
			Answer:   map[string]string{"ticket": c.ticket, "randstr": "@abc"}, RemoteIP: "203.0.113.7",
		})
		if got.Outcome != c.want {
			t.Fatalf("%s %s: %+v, want %s", c.file, c.ticket, got, c.want)
		}
		if strings.HasPrefix(c.ticket, "trerror_") {
			if rc.method != "" {
				t.Fatal("a disaster-recovery ticket must not be sent to the provider")
			}
			continue
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(rc.body), &body); err != nil {
			t.Fatal(err)
		}
		host := strings.TrimPrefix(u, "http://")
		wantAuth := TC3Authorization("AKIDexample", "secret-key", "captcha", host, []byte(rc.body), fixed)
		if body["CaptchaType"] != float64(9) || body["CaptchaAppId"] != float64(190000000) || body["AppSecretKey"] != "app-secret" ||
			body["Ticket"] != c.ticket || body["Randstr"] != "@abc" || body["UserIp"] != "203.0.113.7" ||
			rc.headers.Get("X-TC-Action") != "DescribeCaptchaResult" || rc.headers.Get("X-TC-Version") != "2019-07-22" ||
			rc.headers.Get("X-TC-Timestamp") != "1793347200" || rc.headers.Get("Authorization") != wantAuth {
			t.Fatalf("request %v %v", body, rc.headers)
		}
	}
}

func TestAliyun(t *testing.T) {
	for _, c := range []struct {
		file   string
		status int
		want   string
	}{{"aliyun_pass.json", 0, Pass}, {"aliyun_fail.json", 0, Fail}, {"aliyun_forbidden.json", 404, Unavailable}} {
		rc, u := serve(t, c.file, c.status)
		got := verifier("aliyun", u).Verify(context.Background(), Request{
			Provider: Provider{Kind: "aliyun", SiteKey: "scene1", Region: "cn", Prefix: "abc123"},
			Secret:   map[string]string{"accessKeyId": "LTAIexample", "accessKeySecret": "secret"},
			Answer:   map[string]string{"param": `{"sceneId":"scene1","certifyId":"x","deviceToken":"y","data":"z"}`},
		})
		if got.Outcome != c.want {
			t.Fatalf("%s: %+v, want %s", c.file, got, c.want)
		}
		form, _ := url.ParseQuery(rc.body)
		h := rc.headers
		if rc.path != "/" || form.Get("SceneId") != "scene1" || !strings.Contains(form.Get("CaptchaVerifyParam"), "certifyId") ||
			h.Get("x-acs-action") != "VerifyIntelligentCaptcha" || h.Get("x-acs-version") != "2023-03-05" ||
			h.Get("x-acs-date") != "2026-10-30T08:00:00Z" || len(h.Get("x-acs-signature-nonce")) != 32 ||
			h.Get("x-acs-content-sha256") != sha256Hex([]byte(rc.body)) {
			t.Fatalf("request %s %v %v", rc.path, form, h)
		}
		headers := map[string]string{"host": strings.TrimPrefix(u, "http://")}
		for _, k := range []string{"content-type", "x-acs-action", "x-acs-content-sha256", "x-acs-date", "x-acs-signature-nonce", "x-acs-version"} {
			headers[k] = h.Get(k)
		}
		if want := ACS3Authorization("LTAIexample", "secret", "POST", "/", "", headers, []byte(rc.body)); h.Get("Authorization") != want {
			t.Fatalf("Authorization %q, want %q", h.Get("Authorization"), want)
		}
	}
}

func TestGeeTest(t *testing.T) {
	for _, c := range []struct {
		file string
		want string
	}{{"geetest_pass.json", Pass}, {"geetest_fail.json", Fail}, {"geetest_error.json", Unavailable}} {
		rc, u := serve(t, c.file, 0)
		got := verifier("geetest", u).Verify(context.Background(), Request{
			Provider: Provider{Kind: "geetest", SiteKey: "647f5ed2ed8acb4be36784e01556bb71"},
			Secret:   map[string]string{"captchaKey": "b09a7aafbfd83f73b35a9b530d0337bf"},
			Answer: map[string]string{"lot_number": "4dc3cfc2cdff448cad8d13107198d473", "captcha_output": "out",
				"pass_token": "pass", "gen_time": "1793347200"},
		})
		if got.Outcome != c.want {
			t.Fatalf("%s: %+v, want %s", c.file, got, c.want)
		}
		form, _ := url.ParseQuery(rc.body)
		// sign_token = HMAC-SHA256(captcha_key, lot_number), from openssl dgst -sha256 -hmac.
		if rc.query.Get("captcha_id") != "647f5ed2ed8acb4be36784e01556bb71" || form.Get("lot_number") != "4dc3cfc2cdff448cad8d13107198d473" ||
			form.Get("captcha_output") != "out" || form.Get("pass_token") != "pass" || form.Get("gen_time") != "1793347200" ||
			form.Get("sign_token") != "c99f3aa68104bdcd085f372dc6556a17a5a830a1a3d25125fb0010466977f3d8" {
			t.Fatalf("request %v %v", rc.query, form)
		}
	}
}

// TestSignatureVectors reproduces the vendors' worked examples: Tencent
// Cloud API 3.0 (tencentcloud.com/document/product/213/33224, the doc's
// masked SecretKey of 32 "*" reproduces its signature) and Alibaba Cloud V3
// (help.aliyun.com/zh/sdk/product-overview/v3-request-structure-and-signature).
func TestSignatureVectors(t *testing.T) {
	stars := strings.Repeat("*", 32)
	payload := []byte(`{"Limit": 1, "Filters": [{"Values": ["unnamed"], "Name": "instance-name"}]}`)
	got := TC3Authorization("AKID"+stars, stars, "cvm", "cvm.tencentcloudapi.com", payload, time.Unix(1551113065, 0))
	want := "TC3-HMAC-SHA256 Credential=AKID" + stars + "/2019-02-25/cvm/tc3_request, SignedHeaders=content-type;host, " +
		"Signature=a7b8551448762bd123d6f79e81815e31a92013640a6cef36a08ad4b292a4d2f2"
	if got != want {
		t.Fatalf("TC3:\n got %s\nwant %s", got, want)
	}
	got = ACS3Authorization("YourAccessKeyId", "YourAccessKeySecret", "POST", "/",
		"ImageId=win2019_1809_x64_dtc_zh-cn_40G_alibase_20230811.vhd&RegionId=cn-shanghai",
		map[string]string{
			"host":                  "ecs.cn-shanghai.aliyuncs.com",
			"x-acs-action":          "RunInstances",
			"x-acs-content-sha256":  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			"x-acs-date":            "2023-10-26T10:22:32Z",
			"x-acs-signature-nonce": "3156853299f313e23d1673dc12e1703d",
			"x-acs-version":         "2014-05-26",
		}, nil)
	want = "ACS3-HMAC-SHA256 Credential=YourAccessKeyId,SignedHeaders=host;x-acs-action;x-acs-content-sha256;x-acs-date;x-acs-signature-nonce;x-acs-version," +
		"Signature=06563a9e1b43f5dfe96b81484da74bceab24a1d853912eee15083a6f0f3283c0"
	if got != want {
		t.Fatalf("ACS3:\n got %s\nwant %s", got, want)
	}
}
