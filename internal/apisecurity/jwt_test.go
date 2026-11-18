package apisecurity

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testKey(t *testing.T, alg, kid string) (JWK, any, jwt.SigningMethod) {
	t.Helper()
	encode := base64.RawURLEncoding.EncodeToString
	switch alg {
	case "RS256":
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		return JWK{Kid: kid, Alg: alg, Kty: "RSA", N: encode(key.N.Bytes()), E: encode(big.NewInt(int64(key.E)).Bytes())}, key, jwt.SigningMethodRS256
	case "ES256":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return JWK{Kid: kid, Alg: alg, Kty: "EC", Crv: "P-256", X: encode(key.X.FillBytes(make([]byte, 32))), Y: encode(key.Y.FillBytes(make([]byte, 32)))}, key, jwt.SigningMethodES256
	default:
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return JWK{Kid: kid, Alg: "EdDSA", Kty: "OKP", Crv: "Ed25519", X: encode(pub)}, key, jwt.SigningMethodEdDSA
	}
}
func jwtSettings(t *testing.T, key JWK) *Settings {
	return settings(t, func(s *Settings) {
		s.JWT.Mode = "enforce"
		s.JWT.Issuer = "https://issuer.test"
		s.JWT.Audiences = []string{"api", "alternate"}
		s.JWT.Algorithms = []string{key.Alg}
		s.JWT.Keys = []JWK{key}
		s.JWT.ClockToleranceSeconds = 0
	})
}
func signedToken(t *testing.T, key any, method jwt.SigningMethod, kid string, now time.Time, edit func(jwt.MapClaims, map[string]any)) string {
	t.Helper()
	claims := jwt.MapClaims{"iss": "https://issuer.test", "aud": "api", "exp": now.Add(time.Hour).Unix(), "nbf": now.Add(-time.Minute).Unix(), "iat": now.Add(-time.Minute).Unix(), "sub": "private-user"}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = kid
	if edit != nil {
		edit(claims, token.Header)
	}
	out, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func jwtRequest(token string) Request {
	return Request{Method: "GET", Path: "/private/data", RawPath: "/private/data", JWTScoped: true, Headers: map[string][]string{}, Authorization: []string{"Bearer " + token}}
}

func TestJWTAlgorithmsClaimsAndStaticKeys(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, alg := range []string{"RS256", "ES256", "EdDSA"} {
		t.Run(alg, func(t *testing.T) {
			jwk, key, method := testKey(t, alg, "current")
			s := jwtSettings(t, jwk)
			for _, tc := range []struct {
				name  string
				edit  func(jwt.MapClaims, map[string]any)
				valid bool
			}{
				{"valid", nil, true},
				{"audience rotation", func(c jwt.MapClaims, h map[string]any) { c["aud"] = []string{"other", "alternate"} }, true},
				{"missing expiration", func(c jwt.MapClaims, h map[string]any) { delete(c, "exp") }, false},
				{"expired", func(c jwt.MapClaims, h map[string]any) { c["exp"] = now.Add(-time.Second).Unix() }, false},
				{"missing issuer", func(c jwt.MapClaims, h map[string]any) { delete(c, "iss") }, false},
				{"wrong issuer", func(c jwt.MapClaims, h map[string]any) { c["iss"] = "https://attacker.test" }, false},
				{"missing audience", func(c jwt.MapClaims, h map[string]any) { delete(c, "aud") }, false},
				{"wrong audience", func(c jwt.MapClaims, h map[string]any) { c["aud"] = "other" }, false},
				{"future nbf", func(c jwt.MapClaims, h map[string]any) { c["nbf"] = now.Add(time.Hour).Unix() }, false},
				{"future iat", func(c jwt.MapClaims, h map[string]any) { c["iat"] = now.Add(time.Hour).Unix() }, false},
				{"malformed nbf", func(c jwt.MapClaims, h map[string]any) { c["nbf"] = "tomorrow" }, false},
				{"unknown kid", func(c jwt.MapClaims, h map[string]any) { h["kid"] = "removed" }, false},
				{"missing kid", func(c jwt.MapClaims, h map[string]any) { delete(h, "kid") }, false},
				{"embedded key", func(c jwt.MapClaims, h map[string]any) { h["jwk"] = jwk }, false},
				{"remote jwks", func(c jwt.MapClaims, h map[string]any) { h["jku"] = "https://attacker.test/jwks" }, false},
				{"remote certificate", func(c jwt.MapClaims, h map[string]any) { h["x5u"] = "https://attacker.test/cert" }, false},
				{"unknown crit", func(c jwt.MapClaims, h map[string]any) { h["crit"] = []string{"unexpected"} }, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					token := signedToken(t, key, method, "current", now, tc.edit)
					r := s.Check(context.Background(), jwtRequest(token), now)
					if (r.Status == 0) != tc.valid {
						t.Fatalf("status %d log %+v", r.Status, r.Log)
					}
				})
			}
			_, other, _ := testKey(t, alg, "other")
			wrong := signedToken(t, other, method, "current", now, nil)
			if r := s.Check(context.Background(), jwtRequest(wrong), now); r.Status != 403 {
				t.Fatal("wrong signature accepted")
			}
		})
	}
}

func TestJWTNoneConfusionDuplicatesAndRotation(t *testing.T) {
	now := time.Unix(1800000000, 0)
	jwk, key, method := testKey(t, "EdDSA", "old")
	s := jwtSettings(t, jwk)
	valid := signedToken(t, key, method, "old", now, nil)
	next, nextKey, nextMethod := testKey(t, "EdDSA", "new")
	rotated := settings(t, func(s *Settings) { s.JWT = jwtSettings(t, jwk).JWT; s.JWT.Keys = []JWK{jwk, next} })
	if r := rotated.Check(context.Background(), jwtRequest(valid), now); r.Status != 0 {
		t.Fatal("rotation did not preserve old key")
	}
	nextToken := signedToken(t, nextKey, nextMethod, "new", now, nil)
	if r := rotated.Check(context.Background(), jwtRequest(nextToken), now); r.Status != 0 {
		t.Fatal("rotation did not install new key")
	}
	rotated = jwtSettings(t, next)
	if r := rotated.Check(context.Background(), jwtRequest(valid), now); resultCode(r) != "jwt-unknown-kid" {
		t.Fatal("removed key/token cached")
	}
	encode := base64.RawURLEncoding.EncodeToString
	for _, tc := range []struct{ name, header, claims string }{
		{"header duplicate", `{"alg":"EdDSA","kid":"old","kid":"new"}`, `{"exp":1800000100}`},
		{"claim duplicate", `{"alg":"EdDSA","kid":"old"}`, `{"iss":"https://issuer.test","aud":"api","exp":1800000100,"exp":1}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := encode([]byte(tc.header)) + "." + encode([]byte(tc.claims))
			sig, err := method.Sign(text, key)
			if err != nil {
				t.Fatal(err)
			}
			r := s.Check(context.Background(), jwtRequest(text+"."+encode(sig)), now)
			if resultCode(r) != "json-duplicate-key" {
				t.Fatalf("%+v", r.Log)
			}
		})
	}
	none := encode([]byte(`{"alg":"none","kid":"old"}`)) + "." + strings.Split(valid, ".")[1] + "."
	confused := signedToken(t, []byte(jwk.X), jwt.SigningMethodHS256, "old", now, nil)
	for _, token := range []string{none, confused, strings.Repeat("x", 32768)} {
		if r := s.Check(context.Background(), jwtRequest(token), now); r.Status != 403 {
			t.Fatal("none/confusion/budget bypass")
		}
	}
	req := jwtRequest(valid)
	req.Authorization = append(req.Authorization, "Bearer other")
	if r := s.Check(context.Background(), req, now); resultCode(r) != "jwt-authorization" {
		t.Fatal("duplicate Authorization accepted")
	}
	s.JWT.Mode = "observe"
	req = jwtRequest("bad")
	if r := s.Check(context.Background(), req, now); r.Status != 0 || r.Log.Issues[0].Check != "jwt" {
		t.Fatal("JWT observation blocked or not logged")
	}
}

func TestConfigurationShapeBudgetsAndKeyBinding(t *testing.T) {
	ed, _, _ := testKey(t, "EdDSA", "ed")
	ec, _, _ := testKey(t, "ES256", "ec")
	rsaKey, _, _ := testKey(t, "RS256", "rsa")
	for _, tc := range []struct {
		name string
		edit func(*Settings)
	}{
		{"version", func(s *Settings) { s.Version = 2 }},
		{"mode", func(s *Settings) { s.Schema.Mode = "allow" }},
		{"nullable parameter", func(s *Settings) {
			s.Schema.Endpoints = []Endpoint{{Method: "GET", Path: "/api/{id}", Parameters: []Parameter{
				{In: "path", Name: "id", Required: true, Schema: &Schema{Type: "string", Nullable: true}},
			}}}
		}},
		{"missing path parameter", func(s *Settings) {
			s.Schema.Endpoints = []Endpoint{{Method: "GET", Path: "/api/{id}", Parameters: []Parameter{}}}
		}},
		{"active JWT empty", func(s *Settings) { s.JWT.Mode = "enforce" }},
		{"algorithm confusion", func(s *Settings) { s.JWT.Keys = []JWK{ed}; s.JWT.Algorithms = []string{"RS256"} }},
		{"duplicate kid", func(s *Settings) { s.JWT.Keys = []JWK{ed, ed}; s.JWT.Algorithms = []string{"EdDSA"} }},
		{"wrong curve", func(s *Settings) {
			k := ed
			k.Crv = "P-256"
			s.JWT.Keys = []JWK{k}
			s.JWT.Algorithms = []string{"EdDSA"}
		}},
		{"mixed key parts", func(s *Settings) { k := ed; k.N = "AQAB"; s.JWT.Keys = []JWK{k}; s.JWT.Algorithms = []string{"EdDSA"} }},
		{"off curve", func(s *Settings) {
			k := ec
			k.Y = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
			s.JWT.Keys = []JWK{k}
			s.JWT.Algorithms = []string{"ES256"}
		}},
		{"small RSA", func(s *Settings) {
			k := rsaKey
			k.N = base64.RawURLEncoding.EncodeToString([]byte{255, 255})
			s.JWT.Keys = []JWK{k}
		}},
		{"even RSA exponent", func(s *Settings) { k := rsaKey; k.E = "Ag"; s.JWT.Keys = []JWK{k} }},
		{"graph fields", func(s *Settings) { s.GraphQL.MaxFields = 1001 }},
		{"schema enforce import issue", func(s *Settings) {
			s.Schema.Mode = "enforce"
			s.Schema.Issues = []ImportIssue{{Location: "x", Code: "unsupported"}}
		}},
		{"schema depth", func(s *Settings) {
			schema := &Schema{Type: "string"}
			for i := 0; i < 8; i++ {
				schema = &Schema{Type: "array", Items: schema}
			}
			s.Schema.Endpoints = []Endpoint{{Method: "POST", Path: "/api", Parameters: []Parameter{}, Body: &Body{Schema: schema}}}
		}},
		{"reversed bounds", func(s *Settings) {
			s.Schema.Endpoints = []Endpoint{{Method: "POST", Path: "/api", Parameters: []Parameter{}, Body: &Body{Schema: &Schema{Type: "integer", Minimum: number(10), Maximum: number(1)}}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := Parse(defaultsJSON)
			tc.edit(s)
			raw, _ := json.Marshal(s)
			if _, _, err := Parse(string(raw)); err == nil {
				t.Fatal("invalid setting accepted")
			}
		})
	}
	for name, raw := range map[string]string{
		"unknown field":          strings.Replace(defaultsJSON, `"version":1`, `"version":1,"secret":"not-allowed"`, 1),
		"duplicate config field": strings.Replace(defaultsJSON, `"version":1`, `"version":1,"version":1`, 1),
		"case alias":             strings.Replace(defaultsJSON, `"version":1`, `"Version":1`, 1),
		"missing required":       strings.Replace(defaultsJSON, `"version":1,`, "", 1),
		"null array":             strings.Replace(defaultsJSON, `"exceptions":[]`, `"exceptions":null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := Parse(raw); err == nil {
				t.Fatal("invalid config shape accepted")
			}
		})
	}
	s := jwtSettings(t, ed)
	raw, _ := json.Marshal(s)
	private := strings.Replace(string(raw), `"kty":"OKP"`, `"kty":"OKP","d":"private"`, 1)
	if _, _, err := Parse(private); err == nil {
		t.Fatal("private JWK material accepted")
	}
	_, a, err := Parse(defaultsJSON)
	if err != nil {
		t.Fatal(err)
	}
	_, b, err := Parse(" " + defaultsJSON)
	if err != nil || a == b {
		t.Fatal("version identity discarded raw bytes")
	}
}
