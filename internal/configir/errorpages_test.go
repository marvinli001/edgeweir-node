package configir

import (
	"errors"
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

func page(status uint32, template string) *nodev1.ErrorPage {
	return &nodev1.ErrorPage{Status: status, Template: template}
}

func TestBuildErrorPages(t *testing.T) {
	s := site("site-a", "a.test")
	s.KeepCacheTag = true
	s.ErrorPages = &nodev1.SiteErrorPages{
		Pages:                 []*nodev1.ErrorPage{page(403, "<p>{{status}}</p>"), page(503, strings.Repeat("x", MaxErrorPageBytes))},
		InterceptOriginErrors: true,
	}
	plain := site("site-b", "b.test")
	// Intercepting needs a page: without one the setting is dropped.
	plain.ErrorPages = &nodev1.SiteErrorPages{InterceptOriginErrors: true}
	p, err := Build(&nodev1.NodeConfig{Sites: []*nodev1.Site{s, plain}}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := p.Sites[0]
	if !got.KeepCacheTag || got.ErrorPages == nil || !got.ErrorPages.Intercept || len(got.ErrorPages.Pages) != 2 ||
		got.ErrorPages.Pages[403] != "<p>{{status}}</p>" || len(got.ErrorPages.Pages[503]) != MaxErrorPageBytes {
		t.Fatalf("site = %+v, pages %+v", got, got.ErrorPages)
	}
	if p.Sites[1].ErrorPages != nil || p.Sites[1].KeepCacheTag {
		t.Fatalf("plain site = %+v", p.Sites[1])
	}

	for name, pages := range map[string][]*nodev1.ErrorPage{
		"status 404":       {page(404, "x")},
		"status 500":       {page(500, "x")},
		"duplicate":        {page(502, "a"), page(502, "b")},
		"empty template":   {page(403, "")},
		"oversized":        {page(504, strings.Repeat("y", MaxErrorPageBytes+1))},
		"status 0 (unset)": {page(0, "x")},
	} {
		c := &nodev1.NodeConfig{Sites: []*nodev1.Site{site("site-a", "a.test")}}
		c.Sites[0].ErrorPages = &nodev1.SiteErrorPages{Pages: pages}
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want rejection", name, err)
		}
		// Disabled sites are checked too.
		c.Sites[0].Enabled = false
		if _, err := Build(c, Options{}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s on a disabled site: err = %v, want rejection", name, err)
		}
	}
}

func TestBuildPlatformErrorPagesAndOfflineHosts(t *testing.T) {
	c := &nodev1.NodeConfig{
		Sites: []*nodev1.Site{site("site-a", "a.test")},
		PlatformErrorPages: &nodev1.PlatformErrorPages{
			UnknownHost: "<p>{{host}}</p>", SiteSuspended: strings.Repeat("s", MaxErrorPageBytes),
		},
		OfflineHosts: []*nodev1.OfflineHost{
			{Name: "old.test", Reason: "disabled"},
			{Name: "example.org", Wildcard: true, Reason: "suspended"},
			{Name: "Upper.test", Reason: "disabled"},
			{Name: "bad_name.test", Reason: "disabled"},
			{Name: "com", Wildcard: true, Reason: "disabled"},
			{Name: "old.test", Reason: "suspended"},
			{Name: "old.test", Wildcard: true, Reason: "suspended"},
		},
	}
	p, err := Build(c, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if *p.PlatformErrorPages != (PlatformErrorPages{UnknownHost: "<p>{{host}}</p>", SiteSuspended: strings.Repeat("s", MaxErrorPageBytes)}) {
		t.Fatalf("platform pages = %+v", p.PlatformErrorPages)
	}
	want := []OfflineHost{
		{Name: "old.test", Reason: "disabled"},
		{Name: "example.org", Wildcard: true, Reason: "suspended"},
		{Name: "old.test", Wildcard: true, Reason: "suspended"},
	}
	if !slices.Equal(p.OfflineHosts, want) {
		t.Fatalf("offline hosts = %+v, want %+v", p.OfflineHosts, want)
	}
	warnings := strings.Join(p.Warnings, "\n")
	for _, w := range []string{`invalid offline host "Upper.test"`, `invalid offline host "bad_name.test"`,
		`top-level label "*.com"`, `duplicate offline host "old.test"`} {
		if !strings.Contains(warnings, w) {
			t.Errorf("warnings %q lack %q", warnings, w)
		}
	}

	// Empty templates: built-in pages, no platform pages at all.
	c.PlatformErrorPages = &nodev1.PlatformErrorPages{}
	if p, err = Build(c, Options{}); err != nil || p.PlatformErrorPages != nil {
		t.Fatalf("empty platform pages: %+v, %v", p.PlatformErrorPages, err)
	}
	c.PlatformErrorPages = &nodev1.PlatformErrorPages{SiteDisabled: strings.Repeat("d", MaxErrorPageBytes+1)}
	if _, err = Build(c, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("oversized platform page: %v", err)
	}
	c.PlatformErrorPages = nil
	c.OfflineHosts = []*nodev1.OfflineHost{{Name: "old.test", Reason: "deleted"}}
	if _, err = Build(c, Options{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("unknown offline reason: %v", err)
	}
}
