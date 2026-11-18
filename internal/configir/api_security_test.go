package configir

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

func TestAPISecurityContentHashVectorAndRawBytes(t *testing.T) {
	raw, err := os.ReadFile("testdata/content_hash_vector_api_security.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector hashVector
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	c := &nodev1.NodeConfig{}
	if err := protojson.Unmarshal(vector.Config, c); err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalBytes(c)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(b) != vector.CanonicalHex {
		t.Fatalf("canonical bytes differ from TS\ngot %x\nwant %s", b, vector.CanonicalHex)
	}
	h, err := ContentHash(c)
	if err != nil || h != vector.ContentHash {
		t.Fatalf("hash %s want %s: %v", h, vector.ContentHash, err)
	}
	if err := VerifyHash(c); err != nil {
		t.Fatal(err)
	}
	original := c.Sites[0].GetApiSecurityJson()
	Canonicalize(c)
	if c.Sites[0].GetApiSecurityJson() != original {
		t.Fatal("canonicalizer rewrote API JSON")
	}
	p, err := Build(c, Options{ClusterID: c.GetClusterId()})
	if err != nil {
		t.Fatal(err)
	}
	wantVersion := sha256.Sum256([]byte(original))
	if len(p.Sites) != 1 || p.Sites[0].APISecurity == nil || p.Sites[0].APISecurityVersion != hex.EncodeToString(wantVersion[:]) {
		t.Fatalf("API policy missing from plan: %+v", p.Sites)
	}
	for _, edit := range []func(*nodev1.Site){
		func(s *nodev1.Site) { s.ApiSecurityJson = " " + s.ApiSecurityJson },
		func(s *nodev1.Site) {
			s.ApiSecurityJson = strings.Replace(s.ApiSecurityJson, `"sampleRate":1000`, `"sampleRate":1001`, 1)
		},
		func(s *nodev1.Site) { s.ApiSecurityJson = "" },
	} {
		changed := proto.Clone(c).(*nodev1.NodeConfig)
		edit(changed.Sites[0])
		if hash, err := ContentHash(changed); err != nil || hash == h {
			t.Fatalf("API raw byte change absent from hash: %s %v", hash, err)
		}
	}
	encoded, err := json.Marshal(p.Sites[0])
	if err != nil || !strings.Contains(string(encoded), `"api_security":{`) {
		t.Fatalf("site table API object: %s %v", encoded, err)
	}
}

func TestAPISecurityInvalidScopeRejectsDisabledSites(t *testing.T) {
	raw, err := os.ReadFile("testdata/content_hash_vector_api_security.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector hashVector
	_ = json.Unmarshal(raw, &vector)
	for name, scope := range map[string]any{
		"bad domain":    map[string]any{"domains": []string{"bad domain"}},
		"bad prefix":    map[string]any{"pathPrefixes": []string{"relative"}},
		"bad extension": map[string]any{"extensions": []string{"PHP"}},
	} {
		t.Run(name, func(t *testing.T) {
			c := &nodev1.NodeConfig{}
			if err := protojson.Unmarshal(vector.Config, c); err != nil {
				t.Fatal(err)
			}
			s := c.Sites[0]
			s.Enabled = false
			var cfg map[string]any
			if err := json.Unmarshal([]byte(s.ApiSecurityJson), &cfg); err != nil {
				t.Fatal(err)
			}
			cfg["jwt"].(map[string]any)["scope"] = scope
			b, _ := json.Marshal(cfg)
			s.ApiSecurityJson = string(b)
			if _, err := Build(c, Options{ClusterID: c.ClusterId}); err == nil {
				t.Fatal("disabled site invalid JWT scope accepted")
			}
		})
	}
}
