package mdconv

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

var update = flag.Bool("update", false, "rewrite the golden Markdown files")

// TestConvertGolden converts the saved pages (testdata/README.md) and
// compares with the reviewed Markdown.
func TestConvertGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/pages.json")
	if err != nil {
		t.Fatal(err)
	}
	var pages map[string]struct {
		URL         string `json:"url"`
		ContentType string `json:"content_type"`
	}
	if err := json.Unmarshal(raw, &pages); err != nil {
		t.Fatal(err)
	}
	inputs, _ := filepath.Glob("testdata/pages/*.html")
	if len(inputs) != len(pages) {
		t.Fatalf("%d pages, %d entries in pages.json", len(inputs), len(pages))
	}
	for name, page := range pages {
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(filepath.Join("testdata/pages", name+".html"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := Convert(src, page.ContentType, page.URL)
			if err != nil {
				t.Fatal(err)
			}
			if !utf8.Valid(got) {
				t.Fatal("output is not UTF-8")
			}
			golden := filepath.Join("testdata/pages", name+".md")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Errorf("%s differs from the golden file (go test ./internal/mdconv -update, then review the diff)", name)
			}
		})
	}
}

func TestConvertEdgeCases(t *testing.T) {
	src, err := os.ReadFile("testdata/pages/edge-cases.html")
	if err != nil {
		t.Fatal(err)
	}
	out, err := Convert(src, "text/html", "https://example.com/docs/page")
	if err != nil {
		t.Fatal(err)
	}
	md := string(out)
	frontmatter := "---\ntitle: \"Edge cases: the standard title wins\"\ndescription: Open Graph description\nimage: https://example.com/images/card.png\n---\n\n"
	if !strings.HasPrefix(md, frontmatter) {
		t.Errorf("frontmatter:\n%s", md[:min(len(md), 300)])
	}
	jsonLD := "```json\n{\"@context\":\"https://schema.org\",\"@type\":\"Article\",\"headline\":\"Edge cases\"}\n{\"@type\":\"BreadcrumbList\",\"itemListElement\":[]}\n```\n"
	if !strings.HasSuffix(md, jsonLD) {
		t.Errorf("JSON-LD block:\n%s", md[max(0, len(md)-300):])
	}
	for _, want := range []string{
		"# Article title",
		"By someone",
		"[link](https://example.com/docs/guide/intro.html)", // <base href> resolved against the page
		"[link](https://example.com/about)",
		"[link](https://example.org/x?a=1&b=2)",
		"![Diagram](https://example.com/docs/guide/diagram.png)",
		"## Setup\n",
		"~~gone~~",
		"```go\npackage main",
		"| Name   | Value |",
		"| b \\| c | 2     |",
		"- two\n  \n  - nested",
		"1. first",
		"> Quoted text.",
		"Article footer stays.",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, unwanted := range []string{
		"Logo", "Menu A", "Menu B", "Sidebar ads", "Hidden paragraph", "Decorative text", "Invisible text",
		"Search", "Go]", "icon", "a comment", "Deutsch", "Français", "Site footer", "Template content",
		"Enable JavaScript", "window.tracking", "color: red", "not json", "Document title",
		"](#setup)",
	} {
		if strings.Contains(md, unwanted) {
			t.Errorf("kept %q", unwanted)
		}
	}
}

func TestConvertCharset(t *testing.T) {
	src, err := os.ReadFile("testdata/pages/gbk.html")
	if err != nil {
		t.Fatal(err)
	}
	// The document's own declaration (GBK), then the header's charset.
	for _, ct := range []string{"text/html", "text/html; charset=gbk"} {
		out, err := Convert(src, ct, "http://example.cn/guide/index.html")
		if err != nil {
			t.Fatal(err)
		}
		md := string(out)
		for _, want := range []string{"title: 边缘节点使用说明", "# 边缘节点使用说明", "本页使用 **GBK** 编码", "1. 安装节点", "| 缓存 | 按路径缓存 |", "[帮助](http://example.cn/guide/help.html)"} {
			if !strings.Contains(md, want) {
				t.Errorf("%s: missing %q in\n%s", ct, want, md)
			}
		}
		if strings.Contains(md, "首页") || strings.Contains(md, "版权所有") {
			t.Errorf("%s: content outside <main> kept", ct)
		}
	}
}

func TestConvertMainAndBody(t *testing.T) {
	// Two <main> elements (one hidden): the visible one.
	out, err := Convert([]byte(`<body><p>chrome</p><main hidden>old</main><main><p>content</p></main></body>`), "text/html", "https://e.test/")
	if err != nil || string(out) != "content\n" {
		t.Errorf("got %q, %v", out, err)
	}
	// Two visible: the body.
	out, err = Convert([]byte(`<body><main>a</main><p>b</p><div role="main">c</div></body>`), "text/html", "https://e.test/")
	if err != nil || string(out) != "a\n\nb\n\nc\n" {
		t.Errorf("got %q, %v", out, err)
	}
	// The document title is the last fallback.
	out, err = Convert([]byte(`<title> Plain
	title </title><p>x</p>`), "text/html", "https://e.test/")
	if err != nil || string(out) != "---\ntitle: Plain title\n---\n\nx\n" {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestConvertEmpty(t *testing.T) {
	for _, src := range []string{"", `<div id="app"></div><script src="/app.js"></script>`, `<nav><a href="/">x</a></nav>`} {
		if _, err := Convert([]byte(src), "text/html", "https://e.test/"); !errors.Is(err, ErrEmpty) {
			t.Errorf("%q: %v", src, err)
		}
	}
	// JSON-LD alone is a document.
	out, err := Convert([]byte(`<script type="application/ld+json">{"a": 1}</script>`), "text/html", "https://e.test/")
	if err != nil || string(out) != "```json\n{\"a\":1}\n```\n" {
		t.Errorf("got %q, %v", out, err)
	}
}

func TestYAMLScalar(t *testing.T) {
	for in, want := range map[string]string{
		"Plain title":          "Plain title",
		"Title: subtitle":      `"Title: subtitle"`,
		"- dash":               `"- dash"`,
		"#hash":                `"#hash"`,
		"a #comment":           `"a #comment"`,
		"yes":                  `"yes"`,
		"42":                   `"42"`,
		"ends with colon:":     `"ends with colon:"`,
		`He said "hi"`:         `He said "hi"`,
		`"quoted"`:             `"\"quoted\""`,
		"中文标题：副标题":             "中文标题：副标题",
		"tab\there":            `"tab\there"`,
		"https://e.test/a.png": "https://e.test/a.png",
	} {
		if got := yamlScalar(in); got != want {
			t.Errorf("yamlScalar(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestEstimateTokens(t *testing.T) {
	for in, want := range map[string]int{"": 0, "abcd": 1, "abcde": 2, "中文": 2, "ab中文": 3} {
		if got := EstimateTokens([]byte(in)); got != want {
			t.Errorf("EstimateTokens(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestResolveBase(t *testing.T) {
	for _, c := range [][3]string{
		{"https://e.test/a/b", "", "https://e.test/a/b"},
		{"https://e.test/a/b", "/x/", "https://e.test/x/"},
		{"https://e.test/a/b", "https://cdn.test/y/", "https://cdn.test/y/"},
		{"https://e.test/a/b", "javascript:alert(1)", "https://e.test/a/b"},
	} {
		if got := resolveBase(c[0], c[1]); got != c[2] {
			t.Errorf("resolveBase(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func TestParseHeader(t *testing.T) {
	if up, err := ParseHeader("up=edgeweir_origin_verify"); err != nil || up != "edgeweir_origin_verify" {
		t.Errorf("got %q, %v", up, err)
	}
	for _, v := range []string{"", "up=", "edgeweir_origin_verify", "up=a;b", "up=a b"} {
		if _, err := ParseHeader(v); err == nil {
			t.Errorf("%q accepted", v)
		}
	}
}
