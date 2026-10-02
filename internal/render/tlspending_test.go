package render

import (
	"strings"
	"testing"

	"github.com/marvinli001/edgeweir-node/internal/configir"
)

func TestRenderLeavesDomainsWaitingForTheCertificateOffTLS(t *testing.T) {
	plan := compressionPlan()
	plan.Sites[0].Domains = []configir.Domain{{Name: "all.test"}, {Name: "new.all.test", TLSPending: true}}
	// Every domain of this site waits: no HTTPS server block for it at all.
	plan.Sites[2].Domains = []configir.Domain{{Name: "none.test", TLSPending: true}}
	got, err := Render(params(), plan)
	if err != nil {
		t.Fatal(err)
	}
	conf := string(got)
	for name, want := range map[string]int{
		"server_name all.test new.all.test;": 1, // HTTP
		"server_name all.test;":              1, // HTTPS
		"server_name none.test;":             1, // HTTP only
	} {
		if n := strings.Count(conf, name); n != want {
			t.Errorf("%q appears %d times, want %d", name, n, want)
		}
	}
}
