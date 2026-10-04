package controlplane_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/coder/websocket"

	"github.com/marvinli001/edgeweir-node/internal/controlplane"
	"github.com/marvinli001/edgeweir-node/internal/enroll"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/identity"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

func TestParseServerURL(t *testing.T) {
	for _, ok := range []string{
		"https://console.example.com:8443", "https://10.0.0.1:8443", "https://[::1]:8443/", "https://c.test",
		"wss://console.example.com", "wss://[::1]:8080/", "ws://10.0.0.1:3000",
	} {
		if _, err := controlplane.ParseServerURL(ok); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for bad, why := range map[string]string{
		"http://console:8443":           "scheme must be https",
		"console:8443":                  "scheme must be https",
		"https://":                      "missing host",
		"https://user:pw@console:8443":  "credentials",
		"https://console:8443/?token=x": "query",
		"https://console:8443/#frag":    "fragment",
		"https://con sole:8443":         "invalid server URL",
		"ftp://console":                 "scheme must be https, wss or ws",
		"wss://console/node-channel":    "has no path",
		"ws://console:3000/x":           "has no path",
		"wss://user:pw@console":         "credentials",
	} {
		if _, err := controlplane.ParseServerURL(bad); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%q: err = %v, want %q", bad, err, why)
		}
	}
}

func TestIsAuthError(t *testing.T) {
	cases := map[error]bool{
		connect.NewError(connect.CodeUnauthenticated, errors.New("x")):  true,
		connect.NewError(connect.CodePermissionDenied, errors.New("x")): true,
		connect.NewError(connect.CodeUnavailable, errors.New("x")):      false,
		errors.New("plain"): false,
		errors.Join(connect.NewError(connect.CodeUnauthenticated, nil)): true,
	}
	for err, want := range cases {
		if got := controlplane.IsAuthError(err); got != want {
			t.Errorf("IsAuthError(%v) = %v, want %v", err, got, want)
		}
	}
}

func TestNewPinnedClientValidatesURL(t *testing.T) {
	if _, _, err := controlplane.NewPinnedClient("http://console", "", "00"); err == nil {
		t.Fatal("plain http accepted")
	}
}

// TestChannelMTLSAndReload: the channel authenticates with the node
// certificate, and Reload swaps in the renewed credentials and signals
// watchers through Changed.
func TestChannelMTLSAndReload(t *testing.T) {
	if _, err := controlplane.NewChannel(identity.Store{Dir: t.TempDir()}); !errors.Is(err, identity.ErrNotEnrolled) {
		t.Fatalf("channel without identity: %v", err)
	}
	console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-cp", ClusterID: "cl-cp"})
	if err != nil {
		t.Fatal(err)
	}
	srv := console.StartTLS(t)
	dir := filepath.Join(t.TempDir(), "state")
	console.AddToken("cp-token")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := enroll.Run(ctx, enroll.Options{ServerURL: srv.URL, Token: "cp-token", CASHA256: console.CA.Pin(), StateDir: dir}); err != nil {
		t.Fatal(err)
	}
	ch, err := controlplane.NewChannel(identity.Store{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	if ch.Identity().NodeID != "node-cp" {
		t.Fatalf("identity = %+v", ch.Identity().Identity)
	}
	if _, err := ch.Client().ReportStatus(ctx, connect.NewRequest(&nodev1.ReportStatusRequest{})); err != nil {
		t.Fatalf("mTLS call: %v", err)
	}
	_, _, _, mtls := console.Counters()
	if mtls["/edgeweir.node.v1.NodeService/ReportStatus"] != 1 {
		t.Fatalf("mTLS calls = %v", mtls)
	}
	changed := ch.Changed()
	if err := ch.Reload(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changed:
	default:
		t.Fatal("Reload did not signal Changed")
	}
	if ch.Changed() == changed {
		t.Fatal("Changed not re-armed after Reload")
	}
	if _, err := ch.Client().ReportStatus(ctx, connect.NewRequest(&nodev1.ReportStatusRequest{})); err != nil {
		t.Fatalf("call after reload: %v", err)
	}

	// A pinned client refuses a console whose CA does not match the pin.
	client, closeFn, err := controlplane.NewPinnedClient(srv.URL, "", strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	if _, err := client.Enroll(ctx, connect.NewRequest(&nodev1.EnrollRequest{Token: "never-sent"})); err == nil {
		t.Fatal("pinned client accepted a console with another CA")
	}
}

// TestWebSocketEntry: through a wss:// or ws:// URL the node enrolls and
// calls with mTLS inside a WebSocket to the console's entry, with the same
// CA pin and client certificate as on the node channel port.
func TestWebSocketEntry(t *testing.T) {
	for _, secure := range []bool{false, true} {
		console, err := fakeconsole.New(fakeconsole.Options{NodeID: "node-ws", ClusterID: "cl-ws"})
		if err != nil {
			t.Fatal(err)
		}
		srv := console.StartTLS(t)
		entry := console.StartWebSocketEntry(t, srv, secure)
		server := "ws://" + entry.Listener.Addr().String()
		if secure {
			server = "wss://" + entry.Listener.Addr().String()
			roots := x509.NewCertPool()
			roots.AddCert(entry.Certificate())
			defer controlplane.SetWebSocketRoots(roots)()
		}
		dir := filepath.Join(t.TempDir(), "state")
		console.AddToken("ws-token")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// A wrong pin fails inside the WebSocket before the token is sent.
		client, closeFn, err := controlplane.NewPinnedClient(server, "", strings.Repeat("0", 64))
		if err != nil {
			t.Fatal(err)
		}
		_, err = client.Enroll(ctx, connect.NewRequest(&nodev1.EnrollRequest{Token: "ws-token"}))
		closeFn()
		if err == nil || !strings.Contains(err.Error(), "CA pin mismatch") {
			t.Fatalf("%s: enroll with a wrong pin: %v", server, err)
		}
		if _, err := enroll.Run(ctx, enroll.Options{ServerURL: server, Token: "ws-token", CASHA256: console.CA.Pin(), StateDir: dir}); err != nil {
			t.Fatalf("%s: enroll: %v", server, err)
		}
		ch, err := controlplane.NewChannel(identity.Store{Dir: dir})
		if err != nil {
			t.Fatal(err)
		}
		if got := ch.Identity().ServerURL; got != server {
			t.Fatalf("identity server URL = %q, want %q", got, server)
		}
		if _, err := ch.Client().ReportStatus(ctx, connect.NewRequest(&nodev1.ReportStatusRequest{})); err != nil {
			t.Fatalf("%s: mTLS call: %v", server, err)
		}
		_, _, _, mtls := console.Counters()
		if mtls["/edgeweir.node.v1.NodeService/ReportStatus"] != 1 {
			t.Fatalf("%s: mTLS calls = %v", server, mtls)
		}
		ch.Close()
	}
}

// TestWebSocketEntryRefusesOtherServers: a WebSocket server that does not
// answer the node channel's subprotocol is not the console's entry.
func TestWebSocketEntryRefusesOtherServers(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err == nil {
			_ = ws.Close(websocket.StatusNormalClosure, "")
		}
	}))
	defer other.Close()
	client, closeFn, err := controlplane.NewPinnedClient("ws://"+other.Listener.Addr().String(), "", strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = client.Enroll(ctx, connect.NewRequest(&nodev1.EnrollRequest{Token: "never-sent"}))
	if err == nil || !strings.Contains(err.Error(), "not the console's node channel entry") {
		t.Fatalf("enroll through another WebSocket server: %v", err)
	}
}
