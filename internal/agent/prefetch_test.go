package agent_test

import (
	"crypto/tls"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

var (
	desktopUA = "edgeweir-node-prefetch/" + version.Version
	mobileUA  = "Mozilla/5.0 (Linux; Android 14; Mobile) edgeweir-node-prefetch/" + version.Version
)

// recordingEdge imitates the node's edge listener and records every
// request: "<sni> <host> <uri> <user agent>" (sni "-" over plain HTTP).
type recordingEdge struct {
	mu   sync.Mutex
	seen []string
}

func (e *recordingEdge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sni := "-"
	if r.TLS != nil {
		sni = r.TLS.ServerName
	}
	e.mu.Lock()
	e.seen = append(e.seen, sni+" "+r.Host+" "+r.URL.RequestURI()+" "+r.UserAgent())
	e.mu.Unlock()
	_, _ = w.Write([]byte("ok"))
}

func (e *recordingEdge) requests() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := slices.Clone(e.seen)
	slices.Sort(out)
	return out
}

// listenEdge serves h on a loopback port (with TLS when tlsConfig is set)
// and returns the port.
func listenEdge(t *testing.T, h http.Handler, tlsConfig *tls.Config) uint32 {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	if tlsConfig != nil {
		srv.TLS = tlsConfig
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return uint32(srv.Listener.Addr().(*net.TCPAddr).Port)
}

func variantTask(id string, targets ...*nodev1.PrefetchTarget) *nodev1.NodeTask {
	return &nodev1.NodeTask{Id: id, CreatedAt: timestamppb.Now(), Kind: &nodev1.NodeTask_Prefetch{Prefetch: &nodev1.PrefetchTask{Targets: targets}}}
}

// TestAgentPrefetchDeviceVariants: a mobile target is requested with a
// mobile User-Agent (the data plane caches the mobile object), desktop and
// unspecified ones with the agent's own; an unknown variant fails.
func TestAgentPrefetchDeviceVariants(t *testing.T) {
	edge := &recordingEdge{}
	e := startEnrolledConfig(t, "variants", nil, edgeConfig(listenEdge(t, edge, nil)))
	target := func(path string, v nodev1.DeviceVariant) *nodev1.PrefetchTarget {
		return &nodev1.PrefetchTarget{SiteId: "site-a", Url: "http://site-a.test" + path, Variant: v}
	}
	e.console.AddTask(variantTask("p-variants",
		target("/d", nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP),
		target("/m", nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE),
		target("/u", nodev1.DeviceVariant_DEVICE_VARIANT_UNSPECIFIED),
		target("/x", nodev1.DeviceVariant(7)),
	), false)
	res := waitResults(t, e.console, 1)[0]
	want := map[string]string{"failed": "1", "total": "4", "url": "http://site-a.test/x", "reason": "other"}
	if res.GetSucceeded() != 3 || res.GetFailed() != 1 || res.GetErrorCode() != "prefetch_failed" ||
		!maps.Equal(res.GetErrorParams(), want) || !strings.Contains(res.GetMessage(), "http://site-a.test/x (variant 7): unsupported device variant") {
		t.Fatalf("result = %v", res)
	}
	got := edge.requests()
	wantSeen := []string{
		"- site-a.test /d " + desktopUA,
		"- site-a.test /m " + mobileUA,
		"- site-a.test /u " + desktopUA,
	}
	if !slices.Equal(got, wantSeen) {
		t.Fatalf("edge saw %q\nwant %q", got, wantSeen)
	}
}

// TestAgentPrefetchHTTPS: https URLs go over TLS to the first HTTPS
// listener without the PROXY protocol, with SNI and Host set to the URL's
// host; a failed handshake (no certificate for the host) fails that URL
// only.
func TestAgentPrefetchHTTPS(t *testing.T) {
	ca, err := pkitest.NewCA("prefetch test CA")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueServer([]string{"site-a.test"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	edge := &recordingEdge{}
	tlsPort := listenEdge(t, edge, &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "site-a.test" {
			return nil, errors.New("no certificate for this name") // like the node's listeners
		}
		return &cert, nil
	}})
	plain := &recordingEdge{}
	cfg := edgeConfig(listenEdge(t, plain, nil))
	cfg.Listeners = append(cfg.Listeners,
		// Lower port, but the PROXY protocol would reject the agent.
		&nodev1.Listener{Port: 1, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS, ProxyProtocol: true},
		&nodev1.Listener{Port: tlsPort, Protocol: nodev1.ListenerProtocol_LISTENER_PROTOCOL_HTTPS})
	e := startEnrolledConfig(t, "https", nil, cfg)
	e.console.AddTask(variantTask("p-https",
		&nodev1.PrefetchTarget{SiteId: "site-a", Url: "https://site-a.test/secure?x=1"},
		&nodev1.PrefetchTarget{SiteId: "site-a", Url: "https://site-a.test:8443/m", Variant: nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE},
		&nodev1.PrefetchTarget{SiteId: "site-a", Url: "http://site-a.test/plain"},
		&nodev1.PrefetchTarget{SiteId: "site-a", Url: "https://unknown.test/x"},
	), false)
	res := waitResults(t, e.console, 1)[0]
	if res.GetSucceeded() != 3 || res.GetFailed() != 1 || res.GetErrorCode() != "prefetch_failed" ||
		res.GetErrorParams()["url"] != "https://unknown.test/x" || res.GetErrorParams()["reason"] != "other" ||
		!strings.Contains(res.GetMessage(), "TLS handshake with the node's HTTPS listener") {
		t.Fatalf("result = %v", res)
	}
	wantTLS := []string{
		"site-a.test site-a.test /m " + mobileUA,
		"site-a.test site-a.test /secure?x=1 " + desktopUA,
	}
	if got := edge.requests(); !slices.Equal(got, wantTLS) {
		t.Fatalf("HTTPS listener saw %q\nwant %q", got, wantTLS)
	}
	if got := plain.requests(); !slices.Equal(got, []string{"- site-a.test /plain " + desktopUA}) {
		t.Fatalf("plain listener saw %q", got)
	}
}
