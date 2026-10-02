package configir

import (
	"slices"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// tlsPendingConfig has a site with a certificate whose domain new.a.test
// waits for it, and a site without a certificate that carries the flag too.
func tlsPendingConfig() *nodev1.NodeConfig {
	origin := &nodev1.OriginPool{Id: "p", Origins: []*nodev1.Origin{{Id: "o1", Address: "origin.test", Port: 80, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1}}}
	tls := &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", ForceHttps: true, HstsMaxAge: 60}
	return &nodev1.NodeConfig{
		Listeners:        []*nodev1.Listener{{Port: 80}, {Port: 443, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS}},
		Certificates:     []*nodev1.CertificateRef{{Id: "cert-a", Names: []string{"a.test"}, Sha256Fingerprint: strings.Repeat("a", 64)}},
		RequiredFeatures: []string{"tls-v1", FeatureTLSPendingDomains},
		Sites: []*nodev1.Site{
			{
				Id: "a", Enabled: true, CertificateId: "cert-a", Tls: tls, OriginPool: origin,
				Domains: []*nodev1.Domain{{Name: "a.test"}, {Name: "new.a.test", TlsPending: true}},
			},
			{
				Id: "b", Enabled: true, OriginPool: origin,
				Domains: []*nodev1.Domain{{Name: "b.test", TlsPending: true}},
			},
		},
	}
}

func TestBuildTLSPendingDomains(t *testing.T) {
	if !slices.Contains(SupportedFeatures, FeatureTLSPendingDomains) || FeatureTLSPendingDomains != "tls-pending-domains-v1" {
		t.Fatalf("SupportedFeatures lacks tls-pending-domains-v1: %v", SupportedFeatures)
	}
	p, err := Build(tlsPendingConfig(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Sites) != 2 {
		t.Fatalf("sites = %+v", p.Sites)
	}
	want := []Domain{{Name: "a.test"}, {Name: "new.a.test", TLSPending: true}}
	if !slices.Equal(p.Sites[0].Domains, want) {
		t.Fatalf("domains of a = %+v, want %+v", p.Sites[0].Domains, want)
	}
	// Without a certificate there is no HTTPS to wait for.
	if p.Sites[1].Domains[0].TLSPending {
		t.Fatalf("domains of b = %+v", p.Sites[1].Domains)
	}
}
