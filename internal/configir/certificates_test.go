package configir

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// testCertPEM returns a self-signed ECDSA P-256 certificate, a CA when ca.
func testCertPEM(t *testing.T, ca bool) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: ca, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// multiCertConfig has site a with three certificates and optional client
// certificates, site b with one certificate, and session ticket keys.
func multiCertConfig(t *testing.T) *nodev1.NodeConfig {
	origin := &nodev1.OriginPool{Id: "p", Origins: []*nodev1.Origin{{Id: "o1", Address: "origin.test", Port: 80, Scheme: nodev1.OriginScheme_ORIGIN_SCHEME_HTTP, Weight: 1}}}
	tls := &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern"}
	ref := func(id, c string) *nodev1.CertificateRef {
		return &nodev1.CertificateRef{Id: id, Sha256Fingerprint: strings.Repeat(c, 64)}
	}
	return &nodev1.NodeConfig{
		ClusterId:        "c1",
		Listeners:        []*nodev1.Listener{{Port: 80}, {Port: 443, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS}},
		Certificates:     []*nodev1.CertificateRef{ref("c-ec", "a"), ref("c-rsa", "b"), ref("c-x", "c"), ref("c-y", "d"), ref("c-z", "e")},
		RequiredFeatures: []string{"tls-v1", FeatureMultiCertificate, FeatureClientCert},
		SessionTicketKeys: []*nodev1.SessionTicketKeyRef{
			{Id: "k1", Role: "previous"}, {Id: "k2", Role: "current"}, {Id: "k3", Role: "next"},
		},
		Sites: []*nodev1.Site{
			{
				Id: "a", Enabled: true, CertificateId: "c-ec", AdditionalCertificateIds: []string{"c-rsa", "c-x"}, Tls: tls, OriginPool: origin,
				Domains: []*nodev1.Domain{{Name: "a.test"}},
				ClientCertificate: &nodev1.ClientCertificate{
					Mode: nodev1.ClientCertificateMode_CLIENT_CERTIFICATE_MODE_OPTIONAL, CaPem: testCertPEM(t, true), Depth: 2,
				},
			},
			{Id: "b", Enabled: true, CertificateId: "c-y", Tls: tls, OriginPool: origin, Domains: []*nodev1.Domain{{Name: "b.test"}}},
		},
	}
}

func TestBuildMultipleCertificates(t *testing.T) {
	for _, f := range []string{"multi-certificate-v1", "client-cert-v1"} {
		if !slices.Contains(SupportedFeatures, f) {
			t.Fatalf("SupportedFeatures lacks %s", f)
		}
	}
	p, err := Build(multiCertConfig(t), Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Sites[0].CertificateIDs(); !slices.Equal(got, []string{"c-ec", "c-rsa", "c-x"}) {
		t.Fatalf("certificates of a %v", got)
	}
	if got := p.Sites[1].CertificateIDs(); !slices.Equal(got, []string{"c-y"}) {
		t.Fatalf("certificates of b %v", got)
	}
	if cc := p.Sites[0].ClientCertificate; cc == nil || cc.Mode != ClientCertOptional || cc.Depth != 2 || cc.ForwardHeaders {
		t.Fatalf("client certificate %+v", cc)
	}
	if got := p.SessionTicketKeyIDs(); !slices.Equal(got, []string{"k2", "k1", "k3"}) {
		t.Fatalf("ticket keys %v", got)
	}

	// Rejected wholesale; disabled sites are checked too.
	for name, change := range map[string]func(*nodev1.NodeConfig){
		"without certificate": func(c *nodev1.NodeConfig) {
			c.Sites[0].CertificateId, c.Sites[0].ClientCertificate = "", nil
		},
		"four additional": func(c *nodev1.NodeConfig) {
			c.Sites[0].AdditionalCertificateIds = []string{"c-rsa", "c-x", "c-y", "c-z"}
		},
		"twice":           func(c *nodev1.NodeConfig) { c.Sites[0].AdditionalCertificateIds = []string{"c-rsa", "c-rsa"} },
		"the first again": func(c *nodev1.NodeConfig) { c.Sites[0].AdditionalCertificateIds = []string{"c-ec"} },
		"unknown":         func(c *nodev1.NodeConfig) { c.Sites[0].AdditionalCertificateIds = []string{"c-missing"} },
		"disabled site": func(c *nodev1.NodeConfig) {
			c.Sites[1].Enabled, c.Sites[1].AdditionalCertificateIds = false, []string{"c-missing"}
		},
		"client no cert": func(c *nodev1.NodeConfig) { c.Sites[0].CertificateId, c.Sites[0].AdditionalCertificateIds = "", nil },
		"client http3":   func(c *nodev1.NodeConfig) { c.Sites[0].Tls.Http3 = true },
		"depth 0":        func(c *nodev1.NodeConfig) { c.Sites[0].ClientCertificate.Depth = 0 },
		"depth 6":        func(c *nodev1.NodeConfig) { c.Sites[0].ClientCertificate.Depth = 6 },
		"no CA":          func(c *nodev1.NodeConfig) { c.Sites[0].ClientCertificate.CaPem = "" },
		"garbage":        func(c *nodev1.NodeConfig) { c.Sites[0].ClientCertificate.CaPem += "junk" },
		"leaf":           func(c *nodev1.NodeConfig) { c.Sites[0].ClientCertificate.CaPem = testCertPEM(t, false) },
		"key block": func(c *nodev1.NodeConfig) {
			c.Sites[0].ClientCertificate.CaPem += "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n"
		},
		"eleven CAs": func(c *nodev1.NodeConfig) {
			c.Sites[0].ClientCertificate.CaPem = strings.Repeat(c.Sites[0].ClientCertificate.CaPem, 11)
		},
		"too large": func(c *nodev1.NodeConfig) {
			c.Sites[0].ClientCertificate.CaPem += strings.Repeat(" ", MaxClientCABytes)
		},
		"disabled client": func(c *nodev1.NodeConfig) {
			c.Sites[1].Enabled = false
			c.Sites[1].ClientCertificate = &nodev1.ClientCertificate{Mode: nodev1.ClientCertificateMode_CLIENT_CERTIFICATE_MODE_REQUIRED, CaPem: c.Sites[0].ClientCertificate.CaPem, Depth: 9}
		},
		"unknown mode":        func(c *nodev1.NodeConfig) { c.Sites[0].ClientCertificate.Mode = 7 },
		"ticket id":           func(c *nodev1.NodeConfig) { c.SessionTicketKeys[0].Id = "k 1" },
		"ticket id twice":     func(c *nodev1.NodeConfig) { c.SessionTicketKeys[0].Id = "k2" },
		"ticket role":         func(c *nodev1.NodeConfig) { c.SessionTicketKeys[0].Role = "old" },
		"ticket role twice":   func(c *nodev1.NodeConfig) { c.SessionTicketKeys[0].Role = "current" },
		"ticket without id":   func(c *nodev1.NodeConfig) { c.SessionTicketKeys[0].Id = "" },
		"unsupported feature": func(c *nodev1.NodeConfig) { c.RequiredFeatures = append(c.RequiredFeatures, "client-cert-v2") },
	} {
		c := multiCertConfig(t)
		change(c)
		if _, err := Build(c, Options{ClusterID: "c1"}); !errors.Is(err, ErrRejected) {
			t.Errorf("%s: err = %v, want a rejection", name, err)
		}
	}

	// Ten CAs and the required mode with header forwarding are fine;
	// UNSPECIFIED is off.
	c := multiCertConfig(t)
	c.Sites[0].ClientCertificate.CaPem = strings.Repeat(c.Sites[0].ClientCertificate.CaPem, 10)
	c.Sites[0].ClientCertificate.Mode = nodev1.ClientCertificateMode_CLIENT_CERTIFICATE_MODE_REQUIRED
	c.Sites[0].ClientCertificate.ForwardHeaders = true
	c.Sites[1].ClientCertificate = &nodev1.ClientCertificate{CaPem: "ignored", Depth: 9}
	c.SessionTicketKeys = c.SessionTicketKeys[1:2]
	p, err = Build(c, Options{ClusterID: "c1"})
	if err != nil {
		t.Fatal(err)
	}
	if cc := p.Sites[0].ClientCertificate; cc.Mode != ClientCertRequired || !cc.ForwardHeaders {
		t.Fatalf("client certificate %+v", cc)
	}
	if p.Sites[1].ClientCertificate != nil {
		t.Fatalf("UNSPECIFIED mode is not off: %+v", p.Sites[1].ClientCertificate)
	}
	if got := p.SessionTicketKeyIDs(); !slices.Equal(got, []string{"k2"}) {
		t.Fatalf("ticket keys %v", got)
	}
}

// TestDiffSessionTicketKeys: a diff replaces the ticket keys wholesale.
func TestDiffSessionTicketKeys(t *testing.T) {
	base := multiCertConfig(t)
	base.Revision = 1
	Canonicalize(base)
	base.ContentHash, _ = ContentHash(base)
	target := multiCertConfig(t)
	target.Revision = 2
	target.SessionTicketKeys = []*nodev1.SessionTicketKeyRef{{Id: "k4", Role: "next"}, {Id: "k3", Role: "current"}, {Id: "k2", Role: "previous"}}
	Canonicalize(target)
	target.ContentHash, _ = ContentHash(target)
	got, err := ApplyDiff(base, Diff(base, target))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.GetSessionTicketKeys()) != 3 || got.GetSessionTicketKeys()[2].GetId() != "k4" {
		t.Fatalf("ticket keys %v", got.GetSessionTicketKeys())
	}
}
