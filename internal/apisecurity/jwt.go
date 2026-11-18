package apisecurity

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func publicKey(k JWK) (crypto.PublicKey, error) {
	bad := func() (crypto.PublicKey, error) { return nil, fmt.Errorf("invalid public JWK %q", k.Kid) }
	decode := func(s string, max int) ([]byte, error) {
		if s == "" || len(s) > max {
			return nil, fmt.Errorf("invalid JWK component")
		}
		return base64.RawURLEncoding.Strict().DecodeString(s)
	}
	switch {
	case k.Alg == "RS256" && k.Kty == "RSA":
		if k.Crv != "" || k.X != "" || k.Y != "" {
			return bad()
		}
		n, err := decode(k.N, 1400)
		if err != nil || len(n) == 0 || n[0] == 0 {
			return bad()
		}
		e, err := decode(k.E, 16)
		if err != nil || len(e) == 0 || len(e) > 4 || e[0] == 0 {
			return bad()
		}
		num := new(big.Int).SetBytes(n)
		exp := new(big.Int).SetBytes(e).Int64()
		if num.BitLen() < 2048 || num.BitLen() > 8192 || num.Bit(0) != 1 || exp < 3 || exp > 2147483647 || exp%2 == 0 {
			return bad()
		}
		return &rsa.PublicKey{N: num, E: int(exp)}, nil
	case k.Alg == "ES256" && k.Kty == "EC" && k.Crv == "P-256":
		if k.N != "" || k.E != "" {
			return bad()
		}
		x, err := decode(k.X, 128)
		if err != nil || len(x) != 32 {
			return bad()
		}
		y, err := decode(k.Y, 128)
		if err != nil || len(y) != 32 {
			return bad()
		}
		key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !key.Curve.IsOnCurve(key.X, key.Y) {
			return bad()
		}
		return key, nil
	case k.Alg == "EdDSA" && k.Kty == "OKP" && k.Crv == "Ed25519":
		if k.N != "" || k.E != "" || k.Y != "" {
			return bad()
		}
		x, err := decode(k.X, 128)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return bad()
		}
		return ed25519.PublicKey(x), nil
	}
	return bad()
}

func (s *Settings) verifyJWT(ctx context.Context, authorization []string, now time.Time) string {
	if len(authorization) != 1 {
		return "jwt-authorization"
	}
	header := authorization[0]
	if len(header) > 32768 {
		return "jwt-budget"
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "jwt-authorization"
	}
	segments := strings.Split(parts[1], ".")
	if len(segments) != 3 {
		return "jwt-invalid"
	}
	for _, p := range segments[:2] {
		raw, err := base64.RawURLEncoding.Strict().DecodeString(p)
		if err != nil || len(raw) > 16384 {
			return "jwt-invalid"
		}
		v, err := decodeJSON(ctx, raw, 16, 2048)
		if err != nil {
			return issueCode(err)
		}
		if _, ok := v.(map[string]any); !ok {
			return "jwt-invalid"
		}
	}
	j := s.JWT
	parser := jwt.NewParser(jwt.WithValidMethods(j.Algorithms), jwt.WithIssuer(j.Issuer), jwt.WithAudience(j.Audiences...),
		jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(time.Duration(j.ClockToleranceSeconds)*time.Second),
		jwt.WithJSONNumber(), jwt.WithStrictDecoding(), jwt.WithTimeFunc(func() time.Time { return now }))
	code := "jwt-invalid"
	_, err := parser.Parse(parts[1], func(token *jwt.Token) (any, error) {
		for _, name := range []string{"jwk", "jku", "x5u", "x5c", "crit", "b64"} {
			if _, ok := token.Header[name]; ok {
				code = "jwt-header"
				return nil, violation(code)
			}
		}
		kid, ok := token.Header["kid"].(string)
		key, found := s.keys[kid]
		if !ok || !found {
			code = "jwt-unknown-kid"
			return nil, violation(code)
		}
		if token.Method.Alg() != key.alg {
			code = "jwt-algorithm"
			return nil, violation(code)
		}
		if ctx.Err() != nil {
			code = "check-deadline"
			return nil, violation(code)
		}
		return key.public, nil
	})
	if ctx.Err() != nil {
		return "check-deadline"
	}
	if err != nil {
		return code
	}
	return ""
}
