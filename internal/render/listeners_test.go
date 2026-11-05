package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

func listenerPlan() *configir.Plan {
	plan := configir.Bootstrap(80)
	plan.Extensions = []configir.Extension{{
		ID: "node-status", Scope: "node", SHA256: strings.Repeat("a", 64), Dir: "/extensions/status", State: "loaded", Enabled: true,
		Listeners: []configir.ExtensionListener{{Name: "http", Port: 19145, Bind: "127.0.0.1", Allow: []string{"127.0.0.1"}, Methods: []string{"HEAD", "GET"}, MaxBody: 0}},
	}}
	return plan
}

func TestRenderExtensionListener(t *testing.T) {
	plan := listenerPlan()
	conf, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`id = "node-status", dir = "/extensions/status"`,
		"geo $realip_remote_addr $ewx_6e6f64652d737461747573_http_peer",
		"127.0.0.1/32 1;", "listen 127.0.0.1:19145;", "client_max_body_size 1;",
		`add_header Allow "GET, HEAD" always;`,
		`listen("node-status", "http", ngx.var.uri)`,
	} {
		if !bytes.Contains(conf, []byte(want)) {
			t.Errorf("listener lacks %q", want)
		}
	}
	start := bytes.Index(conf, []byte("listen 127.0.0.1:19145;"))
	if start < 0 {
		t.Fatal("listener server missing")
	}
	end := bytes.Index(conf[start:], []byte("content_by_lua_block")) + start
	if !bytes.Contains(conf[start:end], []byte("_peer = 0) { return 403; }")) || !bytes.Contains(conf[start:end], []byte("return 405;")) {
		t.Fatal("peer and method checks must precede content Lua")
	}
	for _, change := range []func(*configir.Plan){
		func(p *configir.Plan) { p.Extensions[0].Listeners[0].Allow = []string{"10.0.0.0/8"} },
		func(p *configir.Plan) { p.Extensions[0].Listeners[0].Port++ },
		func(p *configir.Plan) { p.Extensions[0].Listeners[0].Bind = "::1" },
		func(p *configir.Plan) { p.Extensions[0].Enabled = false },
		func(p *configir.Plan) { p.ExtensionsDisabled = true },
	} {
		next := listenerPlan()
		change(next)
		got, err := Render(params(), next)
		if err != nil || bytes.Equal(got, conf) {
			t.Fatalf("binding change did not change configuration: %v", err)
		}
	}
	plan.Extensions[0].Listeners[0].Bind = "::"
	got, err := Render(params(), plan)
	if err != nil || !bytes.Contains(got, []byte("listen [::]:19145 ipv6only=on;")) {
		t.Fatalf("IPv6 listener: %v", err)
	}
	plan = listenerPlan()
	plan.Extensions[0].Config = []byte(`{"token":"new"}`)
	got, err = Render(params(), plan)
	if err != nil || !bytes.Equal(got, conf) {
		t.Fatalf("global config must remain hot: %v", err)
	}
}

func TestExtensionListenerClosedAndValidated(t *testing.T) {
	for _, change := range []func(*configir.Plan){
		func(p *configir.Plan) { p.Extensions[0].Listeners = nil },
		func(p *configir.Plan) { p.Extensions[0].Enabled = false },
		func(p *configir.Plan) {
			p.Extensions[0].State = "failed"
			p.Extensions[0].Dir = ""
		},
		func(p *configir.Plan) { p.ExtensionsDisabled = true },
	} {
		plan := listenerPlan()
		change(plan)
		got, err := Render(params(), plan)
		if err != nil || bytes.Contains(got, []byte("listen 127.0.0.1:19145;")) {
			t.Fatalf("inactive binding rendered: %v", err)
		}
	}
	for _, change := range []func(*configir.Plan){
		func(p *configir.Plan) { p.Extensions[0].Listeners[0].Bind = "127.0.0.1;" },
		func(p *configir.Plan) { p.Extensions[0].Listeners[0].Allow = []string{"all;"} },
		func(p *configir.Plan) { p.Extensions[0].Listeners[0].Name = "bad;" },
		func(p *configir.Plan) { p.Extensions[0].Listeners[0].Methods = []string{"GET;"} },
		func(p *configir.Plan) { p.Listeners[0].Port = 19145 },
		func(p *configir.Plan) { p.Tier = &configir.Tier{Port: 19145} },
	} {
		plan := listenerPlan()
		change(plan)
		if _, err := Render(params(), plan); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
}
