package configir

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

func encodedPathVector(t *testing.T) (*nodev1.NodeConfig, hashVector) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "content_hash_vector_encoded_paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v hashVector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	cfg := &nodev1.NodeConfig{}
	if err := protojson.Unmarshal(v.Config, cfg); err != nil {
		t.Fatal(err)
	}
	return cfg, v
}

// TestContentHashVectorEncodedPaths matches the console's vector:
// Site.encoded_path_exemptions sorted by prefix in the canonical form.
func TestContentHashVectorEncodedPaths(t *testing.T) {
	cfg, v := encodedPathVector(t)
	if cfg.GetSites()[0].GetId() != "b" {
		t.Fatal("vector is already canonical")
	}
	b, err := CanonicalBytes(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.CanonicalHex != hex.EncodeToString(b) {
		t.Fatalf("canonical bytes differ from the console\n got %x\nwant %s", b, v.CanonicalHex)
	}
	h, err := ContentHash(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if v.ContentHash != h {
		t.Fatalf("vector hash %s, Go computes %s", v.ContentHash, h)
	}
	c, _ := encodedPathVector(t)
	vectorSite(c, "a").EncodedPathExemptions[0].Semicolon = true
	if h2, _ := ContentHash(c); h2 == h {
		t.Fatal("a flag does not change the hash")
	}
}

// TestEncodedPathExemptions checks the site table and what is refused.
func TestEncodedPathExemptions(t *testing.T) {
	if !slices.Contains(SupportedFeatures, FeatureEncodedPaths) {
		t.Fatalf("SupportedFeatures lacks %s", FeatureEncodedPaths)
	}
	cfg, _ := encodedPathVector(t)
	Canonicalize(cfg)
	plan, err := Build(cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range plan.Sites {
		raw, _ := json.Marshal(site)
		switch site.ID {
		case "a":
			want := `"encoded_path_exemptions":[{"prefix":"/api/","semicolon":true},{"prefix":"/data/","encoded_slash":true,"semicolon":true},{"prefix":"/files/","encoded_slash":true}]`
			if !strings.Contains(string(raw), want) {
				t.Fatalf("site a json %s", raw)
			}
		case "b":
			if strings.Contains(string(raw), "encoded_path_exemptions") {
				t.Fatalf("site b json %s", raw)
			}
		}
	}
	s := vectorSite(cfg, "a")
	for _, prefix := range []string{"", "files/", "/a%2Fb/", "/a;b/", `/a\b/`, "/a#b", "/a?b", "/a b/", "/a//b/",
		"/a/../b/", "/a/./", "/a/..", "/a/.", "/café/", "/" + strings.Repeat("a", maxEncodedPathPrefix)} {
		s.EncodedPathExemptions = []*nodev1.EncodedPathExemption{{Prefix: prefix, EncodedSlash: true}}
		if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("%q: err %v", prefix, err)
		}
	}
	for _, prefix := range []string{"/", "/files/", "/api/v1", "/a/.well-known/", "/a..b/", "/" + strings.Repeat("a", maxEncodedPathPrefix-1)} {
		s.EncodedPathExemptions = []*nodev1.EncodedPathExemption{{Prefix: prefix, Semicolon: true}}
		if _, err := Build(cfg, Options{}); err != nil {
			t.Errorf("%q: err %v", prefix, err)
		}
	}
	s.EncodedPathExemptions = []*nodev1.EncodedPathExemption{{Prefix: "/files/"}}
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) {
		t.Errorf("nothing allowed: err %v", err)
	}
	s.EncodedPathExemptions = []*nodev1.EncodedPathExemption{{Prefix: "/f/", EncodedSlash: true}, {Prefix: "/f/", Semicolon: true}}
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) {
		t.Errorf("duplicate: err %v", err)
	}
	s.EncodedPathExemptions = nil
	for i := range maxEncodedPathExemptions + 1 {
		s.EncodedPathExemptions = append(s.EncodedPathExemptions, &nodev1.EncodedPathExemption{Prefix: "/p" + strconv.Itoa(i) + "/", EncodedSlash: true})
	}
	if _, err := Build(cfg, Options{}); !errors.Is(err, ErrRejected) {
		t.Errorf("too many: err %v", err)
	}
}

// TestEncodedPathPrefixVectors checks the prefixes against the console's
// vectors (test/lua/encoded_path_vectors.json, rule-engine encoded-path.ts).
func TestEncodedPathPrefixVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "test", "lua", "encoded_path_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Prefixes []struct {
			Prefix string `json:"prefix"`
			Valid  bool   `json:"valid"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Prefixes) == 0 {
		t.Fatal("no prefix vectors")
	}
	for _, p := range v.Prefixes {
		if got := validEncodedPathPrefix(p.Prefix); got != p.Valid {
			t.Errorf("%q: valid %v, want %v", p.Prefix, got, p.Valid)
		}
	}
}
