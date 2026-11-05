package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	"github.com/marvinli001/edgeweir-node/internal/render"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func TestPreflightExtensionListeners(t *testing.T) {
	socket, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	port := uint32(socket.Addr().(*net.TCPAddr).Port)
	plan := &configir.Plan{Extensions: []configir.Extension{{
		ID: "node-status", Scope: "node", State: "loaded", Dir: "/extensions/status", Enabled: true,
		Listeners: []configir.ExtensionListener{{Name: "http", Bind: "127.0.0.1", Port: port}},
	}}}
	ctx := context.Background()
	if err := preflightExtensionListeners(ctx, plan, nil); err == nil || !strings.Contains(err.Error(), `listener "http"`) {
		t.Fatalf("external TCP owner accepted: %v", err)
	}
	if err := preflightExtensionListeners(ctx, plan, plan); err != nil {
		t.Fatalf("current controlled listener probed as an external owner: %v", err)
	}
	plan.ExtensionsDisabled = true
	if err := preflightExtensionListeners(ctx, plan, nil); err != nil {
		t.Fatalf("disabled listener probed: %v", err)
	}
	plan.ExtensionsDisabled = false
	if err := socket.Close(); err != nil {
		t.Fatal(err)
	}
	if err := preflightExtensionListeners(ctx, plan, nil); err != nil {
		t.Fatalf("free endpoint rejected: %v", err)
	}
	rebound, err := net.Listen("tcp4", socket.Addr().String())
	if err != nil {
		t.Fatalf("preflight leaked a listening socket: %v", err)
	}
	rebound.Close()
}

// These tests isolate activation decisions; test/e2e/run.sh exercises nginx.
type listenerEngine struct {
	Engine
	conf                   string
	dp                     *fakedataplane.Server
	failTest, ignoreReload bool
	reloads                int
}

func (e *listenerEngine) Running() bool { return true }
func (e *listenerEngine) Test(context.Context, string) error {
	if e.failTest {
		return errors.New("injected nginx precheck failure")
	}
	return nil
}
func (e *listenerEngine) Reload(context.Context) error {
	e.reloads++
	if !e.ignoreReload {
		conf, err := os.ReadFile(e.conf)
		if err != nil {
			return err
		}
		e.dp.LoadConf(render.ConfID(conf))
	}
	return nil
}

func listenerAgent(t *testing.T) (*Agent, *listenerEngine, *fakedataplane.Server) {
	t.Helper()
	root := t.TempDir()
	dp := fakedataplane.Start(t)
	eng := &listenerEngine{conf: filepath.Join(root, "nginx.conf"), dp: dp}
	a := New(Config{
		StateDir: filepath.Join(root, "state"), ConfPath: eng.conf, ReloadTimeout: 200 * time.Millisecond,
		Render: render.Params{Prefix: filepath.Join(root, "nginx"), LuaDir: "/lua", CacheDir: filepath.Join(root, "cache"), ControlSocket: dp.Socket, OriginSocket: filepath.Join(root, "origin.sock"), Resolvers: []string{"127.0.0.1"}},
	}, eng, dataplane.NewClient(dp.Socket), slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(a.health.Close)
	return a, eng, dp
}

func activationPlan(port uint32) *configir.Plan {
	plan := configir.Bootstrap(80)
	plan.Extensions = []configir.Extension{{
		ID: "node-status", Scope: "node", SHA256: strings.Repeat("a", 64), Dir: "/extensions/status", State: "loaded", Enabled: true,
		Listeners: []configir.ExtensionListener{{Name: "http", Port: port, Bind: "127.0.0.1", Allow: []string{"127.0.0.1/32"}, Methods: []string{"GET"}, MaxBody: 4096}},
	}}
	return plan
}

func TestListenerStartupConfID(t *testing.T) {
	for _, match := range []bool{true, false} {
		a, eng, dp := listenerAgent(t)
		socket, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer socket.Close()
		plan := activationPlan(uint32(socket.Addr().(*net.TCPAddr).Port))
		conf, err := render.Render(a.cfg.Render, plan)
		if err != nil {
			t.Fatal(err)
		}
		id := "different configuration"
		if match {
			id = render.ConfID(conf)
		}
		dp.LoadConf(id)
		err = a.applyPlan(context.Background(), plan)
		if match && (err != nil || dp.Table() == nil) {
			t.Fatalf("matching live ConfID did not recognize the controlled listener: %v", err)
		}
		if match && dp.Table().Extensions.ConfID != render.ConfID(conf) {
			t.Fatal("node runtime did not receive its worker configuration identity")
		}
		if !match && (err == nil || eng.reloads != 0 || dp.Table() != nil) {
			t.Fatalf("mismatched ConfID bypassed the real occupied socket: %v", err)
		}
	}
}

func TestListenerActivationFailureKeepsPrevious(t *testing.T) {
	for _, failure := range []string{"occupied", "precheck", "unconfirmed reload"} {
		t.Run(failure, func(t *testing.T) {
			a, eng, dp := listenerAgent(t)
			previous := configir.Bootstrap(80)
			previous.Revision = 7
			if err := a.applyPlan(context.Background(), previous); err != nil {
				t.Fatal(err)
			}
			old := bytes.Clone(a.conf)
			socket, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			plan := activationPlan(uint32(socket.Addr().(*net.TCPAddr).Port))
			if failure != "occupied" {
				socket.Close()
			}
			eng.failTest = failure == "precheck"
			eng.ignoreReload = failure == "unconfirmed reload"
			if err := a.applyPlan(context.Background(), plan); err == nil {
				t.Fatal("failed listener activation accepted")
			}
			live, err := os.ReadFile(a.cfg.ConfPath)
			if err != nil || !bytes.Equal(live, old) || !bytes.Equal(a.conf, old) || a.plan != previous || dp.Table().Revision != 7 {
				t.Fatalf("failure replaced previous file, plan or site table: %v", err)
			}
		})
	}
}
