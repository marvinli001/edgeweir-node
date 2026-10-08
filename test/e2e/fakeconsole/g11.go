package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

// G11 (multi-certificate-v1, client-cert-v1, session resumption): the
// sites, generated at start (ECDSA P-256 and RSA 2048, self-signed):
//
//	site-g11a  a.g11.test with an ECDSA and an RSA certificate, b.g11.test
//	           with a third (ECDSA) certificate
//	site-g11c  c.g11.test and c2.g11.test, one certificate for both
//	site-g11m  m.g11.test, client certificates required (the e2e client
//	           CA, depth 2) and forwarded to the origin
//
// No cache rules: every request reaches whoami, which echoes the request
// headers. The session ticket keys g11-k1..k4 (80 bytes); rotate=1
// publishes k2 previous, k3 current, k4 next instead of k1, k2, k3.
//
// The client certificates are written next to the origin CA (the node
// mounts that volume at /etc/edgeweir-e2e): g11-client.crt / .key, issued
// by the client CA (CN=e2e-client, OU=Ops), and g11-rogue.crt / .key,
// self-signed with the same subject.

type g11Cert struct {
	material *nodev1.CertificateMaterial
	names    []string
}

var (
	g11Certs     = map[string]*g11Cert{}
	g11TicketIDs = []string{"g11-k1", "g11-k2", "g11-k3", "g11-k4"}
)

func g11Key(rsaKey bool) crypto.Signer {
	if rsaKey {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal(err)
		}
		return k
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	return k
}

func pemOf(kind string, der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

func keyPEM(key crypto.Signer) string {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	return pemOf("PRIVATE KEY", der)
}

var g11Serial int64 = 0x6110

// g11Issue signs template for key with parent (self-signed without one)
// and returns the certificate's DER.
func g11Issue(template *x509.Certificate, key crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer) []byte {
	g11Serial++
	template.SerialNumber = big.NewInt(g11Serial)
	template.NotBefore, template.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour)
	if parent == nil {
		parent, parentKey = template, key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, key.Public(), parentKey)
	if err != nil {
		log.Fatal(err)
	}
	return der
}

// g11SiteCert creates a site certificate for names and hands it out.
func g11SiteCert(c *fakeconsole.Console, id string, rsaKey bool, names ...string) {
	key := g11Key(rsaKey)
	der := g11Issue(&x509.Certificate{Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, key, nil, nil)
	sum := sha256.Sum256(der)
	m := &nodev1.CertificateMaterial{Id: id, ChainPem: pemOf("CERTIFICATE", der), PrivateKeyPem: keyPEM(key), Sha256Fingerprint: hex.EncodeToString(sum[:])}
	g11Certs[id] = &g11Cert{material: m, names: names}
	c.SetCertificate(m)
}

// g11Setup creates the site certificates, the client CA with its client
// certificates (written to dir) and the session ticket keys; it returns
// the client CA's PEM.
func g11Setup(c *fakeconsole.Console, dir string) string {
	g11SiteCert(c, "g11-ec", false, "a.g11.test")
	g11SiteCert(c, "g11-rsa", true, "a.g11.test")
	g11SiteCert(c, "g11-b", false, "b.g11.test")
	g11SiteCert(c, "g11-c", false, "c.g11.test", "c2.g11.test")
	g11SiteCert(c, "g11-m", false, "m.g11.test")

	caKey := g11Key(false)
	caTemplate := &x509.Certificate{Subject: pkix.Name{CommonName: "Edgeweir e2e client CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER := g11Issue(caTemplate, caKey, nil, nil)
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		log.Fatal(err)
	}
	client := &x509.Certificate{Subject: pkix.Name{CommonName: "e2e-client", OrganizationalUnit: []string{"Ops"}},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	for name, parent := range map[string]*x509.Certificate{"g11-client": ca, "g11-rogue": nil} {
		key := g11Key(false)
		template := *client
		var der []byte
		if parent != nil {
			der = g11Issue(&template, key, parent, caKey)
		} else {
			der = g11Issue(&template, key, nil, nil)
		}
		// World-readable: the node's user reads them for openssl s_client.
		for file, content := range map[string]string{name + ".crt": pemOf("CERTIFICATE", der), name + ".key": keyPEM(key)} {
			path := filepath.Join(dir, file)
			if err := os.WriteFile(path+".tmp", []byte(content), 0o644); err != nil {
				log.Fatal(err)
			}
			if err := os.Rename(path+".tmp", path); err != nil {
				log.Fatal(err)
			}
		}
	}
	for _, id := range g11TicketIDs {
		secret := make([]byte, 80)
		if _, err := rand.Read(secret); err != nil {
			log.Fatal(err)
		}
		c.SetSessionTicketKey(id, secret)
	}
	return pemOf("CERTIFICATE", caDER)
}

// g11Config is the base configuration with the G11 sites and session
// ticket keys (rotated: one rotation later).
func g11Config(origin, clientCA string, rotated bool) *nodev1.NodeConfig {
	tls := func() *nodev1.TlsOptions { return &nodev1.TlsOptions{MinimumVersion: "1.2", CipherProfile: "modern", Http2: true} }
	a := site("site-g11a", "a.g11.test", origin, 80)
	a.Domains = append(a.Domains, &nodev1.Domain{Name: "b.g11.test"})
	a.CertificateId, a.AdditionalCertificateIds, a.Tls = "g11-ec", []string{"g11-rsa", "g11-b"}, tls()
	cs := site("site-g11c", "c.g11.test", origin, 80)
	cs.Domains = append(cs.Domains, &nodev1.Domain{Name: "c2.g11.test"})
	cs.CertificateId, cs.Tls = "g11-c", tls()
	m := site("site-g11m", "m.g11.test", origin, 80)
	m.CertificateId, m.Tls = "g11-m", tls()
	m.ClientCertificate = &nodev1.ClientCertificate{Mode: nodev1.ClientCertificateMode_CLIENT_CERTIFICATE_MODE_REQUIRED, CaPem: clientCA, Depth: 2, ForwardHeaders: true}
	sites := []*nodev1.Site{a, cs, m}
	for _, s := range sites {
		s.CacheRules = nil
	}
	cfg := config(append(baseSites(origin), sites...)...)
	for id, cert := range g11Certs {
		cfg.Certificates = append(cfg.Certificates, &nodev1.CertificateRef{Id: id, Names: cert.names, Sha256Fingerprint: cert.material.GetSha256Fingerprint()})
	}
	keys := g11TicketIDs[:3]
	if rotated {
		keys = g11TicketIDs[1:]
	}
	cfg.SessionTicketKeys = []*nodev1.SessionTicketKeyRef{{Id: keys[0], Role: "previous"}, {Id: keys[1], Role: "current"}, {Id: keys[2], Role: "next"}}
	cfg.RequiredFeatures = append(cfg.RequiredFeatures, "tls-v1", configir.FeatureMultiCertificate, configir.FeatureClientCert)
	return cfg
}

// g11Handlers: POST /g11 publishes g11Config (?rotate=1: the rotated
// ticket keys; ?enabled=false: the base configuration again).
func g11Handlers(mux *http.ServeMux, c *fakeconsole.Console, origin, clientCA string) {
	mux.HandleFunc("POST /g11", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		cfg := g11Config(origin, clientCA, q.Get("rotate") == "1")
		if q.Get("enabled") == "false" {
			cfg = config(baseSites(origin)...)
		}
		fmt.Fprint(w, c.Publish(cfg))
	})
}
