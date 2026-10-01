package agent_test

import (
	"strings"
	"testing"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakedataplane"
)

func l4App(id string, port uint32, protocol nodev1.L4Protocol) *nodev1.L4App {
	return &nodev1.L4App{
		Id: id, Protocol: protocol, Port: port,
		Origins:  []*nodev1.L4Origin{{Id: "o1", Address: "origin.test", Port: 7000, Weight: 1}},
		MaxFails: 3, FailTimeoutSeconds: 30, ConnectTimeoutMs: 5000, IdleTimeoutSeconds: 600,
	}
}

func l4Config(apps ...*nodev1.L4App) *nodev1.NodeConfig {
	c := baseConfig(demoSite("site-a", "site-a.test"))
	c.IpLists = []*nodev1.IpList{{Id: "list-a", Kind: "block", Entries: []string{"198.51.100.0/24"}}, {Id: "list-b", Kind: "allow", Entries: []string{"203.0.113.0/24"}}}
	c.L4Apps = apps
	return c
}

// TestL4HotUpdateWithoutReload: origins, passive health, timeouts, IP
// lists and limits of a layer-4 application reach the stream subsystem
// through the control socket without a reload (nginx.conf unchanged);
// adding a port, changing the PROXY protocol settings or removing the last
// application reloads.
func TestL4HotUpdateWithoutReload(t *testing.T) {
	e := startEnrolledConfig(t, "l4-hot", nil, l4Config(l4App("app-a", 9000, nodev1.L4Protocol_L4_PROTOCOL_TCP)))
	_, reloads, conf := e.eng.counts()
	if !strings.Contains(conf, "stream {") || !strings.Contains(conf, "listen 9000 reuseport;") {
		t.Fatalf("no stream server for TCP 9000:\n%s", conf)
	}
	table := e.dp.L4()
	if table == nil || table.Revision != e.rev || len(table.Apps) != 1 || table.Apps[0].ID != "app-a" || len(table.IPLists) != 0 {
		t.Fatalf("layer-4 table = %+v", table)
	}

	hot := l4App("app-a", 9000, nodev1.L4Protocol_L4_PROTOCOL_TCP)
	hot.Origins = []*nodev1.L4Origin{{Id: "o2", Address: "10.9.9.9", Port: 7100, Weight: 5}, {Id: "o3", Address: "b.test", Port: 1, Weight: 1, Backup: true}}
	hot.MaxFails, hot.FailTimeoutSeconds, hot.ConnectTimeoutMs, hot.IdleTimeoutSeconds = 9, 99, 999, 9999
	hot.AllowListIds, hot.BlockListIds = []string{"list-b"}, []string{"list-a"}
	hot.MaxConnections, hot.NewConnectionsPerSecond = 10, 5
	rev := e.console.Publish(l4Config(hot))
	eventually(t, "hot update applied", statusWith(e.console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
	_, after, confAfter := e.eng.counts()
	if after != reloads || confAfter != conf {
		t.Fatalf("hot layer-4 change reloaded nginx (%d -> %d) or changed nginx.conf", reloads, after)
	}
	table = e.dp.L4()
	a := table.Apps[0]
	if table.Revision != rev || len(a.Origins) != 2 || a.Origins[0].ID != "o2" || a.Origins[1].Address != "b.test" || !a.Origins[1].Backup ||
		a.MaxFails != 9 || a.FailTimeout != 99 || a.ConnectTimeoutMS != 999 || a.IdleTimeout != 9999 ||
		a.MaxConnections != 10 || a.NewConnectionsPerSecond != 5 || len(table.IPLists) != 2 || table.IPLists[0].ID != "list-a" ||
		table.IPLists[1].Entries[0] != "203.0.113.0/24" {
		t.Fatalf("hot layer-4 table = %+v", table)
	}

	// Structural: a new port, the PROXY protocol, the last application.
	pp := l4App("app-a", 9000, nodev1.L4Protocol_L4_PROTOCOL_TCP)
	pp.ProxyProtocolVersion = 2
	for i, next := range []*nodev1.NodeConfig{
		l4Config(l4App("app-a", 9000, nodev1.L4Protocol_L4_PROTOCOL_TCP), l4App("app-b", 9001, nodev1.L4Protocol_L4_PROTOCOL_UDP)),
		l4Config(pp),
		l4Config(),
	} {
		_, before, _ := e.eng.counts()
		rev := e.console.Publish(next)
		eventually(t, "structural change applied", statusWith(e.console, rev, nodev1.ApplyState_APPLY_STATE_APPLIED))
		_, after, conf := e.eng.counts()
		if after != before+1 {
			t.Fatalf("change %d: reloads %d -> %d, want one", i, before, after)
		}
		switch i {
		case 0:
			if !strings.Contains(conf, "listen 9001 udp reuseport;") || e.dp.L4().Revision != rev || len(e.dp.L4().Apps) != 2 {
				t.Fatalf("new UDP port: %+v", e.dp.L4())
			}
		case 1:
			if !strings.Contains(conf, "proxy_protocol v2;") {
				t.Fatal("no proxy_protocol v2")
			}
		case 2:
			if strings.Contains(conf, "stream {") {
				t.Fatal("stream block without applications")
			}
		}
	}
	// Without applications nothing more goes to the stream subsystem.
	pushes := len(e.dp.L4Pushes())
	time.Sleep(300 * time.Millisecond)
	if len(e.dp.L4Pushes()) != pushes {
		t.Fatal("layer-4 table pushed without applications")
	}
}

// TestL4TableRestoredAfterRestart: an nginx restart empties the stream
// subsystem's dicts; the data plane check pushes the table again.
func TestL4TableRestoredAfterRestart(t *testing.T) {
	e := startEnrolledConfig(t, "l4-restart", nil, l4Config(l4App("app-a", 9000, nodev1.L4Protocol_L4_PROTOCOL_UDP)))
	pushes := len(e.dp.L4Pushes())
	e.dp.Restart()
	eventually(t, "layer-4 table pushed again", func() bool {
		return len(e.dp.L4Pushes()) > pushes && e.dp.L4() != nil && e.dp.L4().Revision == e.rev
	})
	if table := e.dp.Table(); table == nil || table.Revision != e.rev {
		t.Fatalf("site table after restart: %+v", table)
	}
}

// TestL4StatsShareTheStatisticsBatches: the stream subsystem's minutes go
// out with ReportStatsV2 in the sites' batches (invalid application ids
// left out).
func TestL4StatsShareTheStatisticsBatches(t *testing.T) {
	minute := time.Now().Add(-time.Minute).Truncate(time.Minute)
	e := startEnrolledPrepared(t, "l4-stats", nil, func(c *fakeconsole.Console, dp *fakedataplane.Server) {
		dp.AddStats(dataplane.MinuteStats{Minute: minute.Unix(), SiteID: "site-a", Requests: 2})
		dp.AddL4Stats(dataplane.L4MinuteStats{Minute: minute.Unix(), AppID: "app-a", Connections: 3, Refused: 1, PeakConcurrent: 2, BytesReceived: 100, BytesSent: 200},
			dataplane.L4MinuteStats{Minute: minute.Unix(), AppID: "bad|id", Connections: 9})
	}, l4Config(l4App("app-a", 9000, nodev1.L4Protocol_L4_PROTOCOL_TCP)))
	eventually(t, "layer-4 statistics", func() bool { return len(e.console.L4Stats()) == 1 })
	got := e.console.L4Stats()[0]
	if got.GetAppId() != "app-a" || !got.GetMinute().AsTime().Equal(minute) || got.GetConnections() != 3 || got.GetRefused() != 1 ||
		got.GetPeakConcurrent() != 2 || got.GetBytesReceived() != 100 || got.GetBytesSent() != 200 {
		t.Fatalf("layer-4 bucket = %v", got)
	}
	eventually(t, "site statistics", func() bool { return len(e.console.Stats()) == 1 })
	// The batch sequence is shared: no sequence was used twice.
	seq := e.console.StatsSequences()
	for i := 1; i < len(seq); i++ {
		if seq[i] <= seq[i-1] {
			t.Fatalf("batch sequences %v", seq)
		}
	}
}
