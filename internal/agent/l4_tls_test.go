package agent_test

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func TestL4TLSBootstrapWithoutHTTPSSites(t *testing.T) {
	for _, cold := range []bool{true, false} {
		name := "reload"
		if cold {
			name = "cold"
		}
		t.Run(name, func(t *testing.T) {
			cert := material(t, "cert-tls", "stream.test")
			config := func(port uint32, secure bool) *nodev1.NodeConfig {
				c := baseConfig()
				app := l4App("app-tls", port, nodev1.L4Protocol_L4_PROTOCOL_TCP)
				if secure {
					app.CertificateId, app.TlsMinimumVersion = cert.Id, "1.3"
					c.Certificates = []*nodev1.CertificateRef{{Id: cert.Id, Names: []string{"stream.test"}, Sha256Fingerprint: cert.Sha256Fingerprint}}
				}
				c.L4Apps = []*nodev1.L4App{app}
				return c
			}
			e := startEnrolledPrepared(t, "l4-tls-"+name, nil, func(c *fakeconsole.Console, _ *fakedataplane.Server) { c.SetCertificate(cert) }, config(9200, cold))
			if !cold {
				rev := e.console.Publish(config(9200, true))
				eventually(t, "TLS listener applied", statusWith(e.console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
			}
			certPath := filepath.Join(e.cfg.Render.Prefix, "conf", "bootstrap.crt")
			keyPath := filepath.Join(e.cfg.Render.Prefix, "conf", "bootstrap.key")
			pair, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil {
				t.Fatalf("stream TLS bootstrap: %v", err)
			}
			for _, path := range []string{certPath, keyPath} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("private bootstrap material %s: %v, %v", path, info, err)
				}
			}
			rev := e.console.Publish(config(9201, true))
			eventually(t, "new TLS port applied", statusWith(e.console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
			after, err := tls.LoadX509KeyPair(certPath, keyPath)
			if err != nil || string(pair.Certificate[0]) != string(after.Certificate[0]) {
				t.Fatalf("bootstrap replaced on reload: %v", err)
			}
			_, _, conf := e.eng.counts()
			if !strings.Contains(conf, "listen 9201 reuseport ssl;") || strings.Contains(conf, "listen 443") {
				t.Fatalf("expected only stream TLS: %s", conf)
			}
			if e.dp.L4().Apps[0].Certificate == nil || e.dp.L4().Apps[0].Certificate.Fingerprint != cert.Sha256Fingerprint {
				t.Fatal("bootstrap must not replace the application's certificate")
			}
		})
	}
}
