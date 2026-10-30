package configir

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"slices"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// FeatureTieredCache: the node fetches cacheable requests of sites with a
// tiered cache plan from upper tier nodes and serves lower tiers on the
// tier listener (NodeConfig.tiered_cache, ADR-0073).
const FeatureTieredCache = "tiered-cache-v1"

// FeatureTierUpper is announced when the node's certificate may serve TLS
// (it carries the serverAuth extended key usage): only such nodes can be
// upper tiers, lower tiers verify them against the node CA.
const FeatureTierUpper = "tier-upper-v1"

const (
	// MaxTierUppers is the most upper tiers a node tries for one site.
	MaxTierUppers = 3
	// MaxTierDepth is the longest chain of a plan: lower tier, regional
	// tier, upper tier.
	MaxTierDepth          = 2
	maxTierPlans          = 4096
	maxTierLatencyTargets = 1024
)

var tierPlanIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Tier is this node's part in the tiered cache (nil: no site uses one).
type Tier struct {
	// Port of the tier listener.
	Port uint32
	// Listen: this node is an upper tier in some plan, so it runs the TLS
	// tier listener for the lower tiers in Clients.
	Listen bool
	// Clients are the node ids allowed on the tier listener (the nodes whose
	// hops name this node), sorted.
	Clients []string
	// Lower: some site of this node fetches through upper tiers, so nginx
	// has the tier layer (unix socket) towards them.
	Lower bool
	// LatencyTargets are what the agent measures for the console.
	LatencyTargets []TierLatencyTarget
	// CertPath, KeyPath and CAPath are the copies of the node certificate,
	// its key and the node CA nginx reads (the agent writes them before
	// rendering, render.TierCertPath).
	CertPath, KeyPath, CAPath string
}

// TierPeer is an upper tier of a site on this node, in the order the node
// tries them.
type TierPeer struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Port    uint32 `json:"port"`
	// CDNID is the peer's CDN-Loop identifier: a peer the request already
	// passed is skipped.
	CDNID string `json:"cdn_id"`
}

// TierLatencyTarget is an origin address the agent measures the round trip
// time to.
type TierLatencyTarget struct {
	ID   string
	Host string
	Port uint32
}

// CDNID returns the CDN-Loop identifier of a node (RFC 8586 pseudonym):
// "edgeweir-" and the first 16 hex characters of sha256(node id).
func CDNID(nodeID string) string {
	if nodeID == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(nodeID))
	return "edgeweir-" + hex.EncodeToString(sum[:])[:16]
}

// buildTier checks the tiered cache of c and returns this node's part
// (nil when no plan names it or nothing is configured) and each plan's
// upper tiers for this node by plan id. listenerPorts are the edge
// listeners' ports, which the tier listener may not take.
func buildTier(c *nodev1.NodeConfig, nodeID string, listenerPorts map[uint32]bool) (*Tier, map[string][]TierPeer, error) {
	tc := c.GetTieredCache()
	used := map[string]bool{}
	for _, s := range c.GetSites() {
		if id := s.GetTierPlanId(); id != "" {
			used[id] = true
		}
	}
	if tc == nil {
		if len(used) > 0 {
			return nil, nil, fmt.Errorf("%w: sites name tiered cache plans but there is no tiered cache", ErrRejected)
		}
		return nil, nil, nil
	}
	reject := func(format string, args ...any) error {
		return fmt.Errorf("%w: tiered cache: "+format, append([]any{ErrRejected}, args...)...)
	}
	port := tc.GetPort()
	if port == 0 || port > 65535 {
		return nil, nil, reject("invalid port %d", port)
	}
	if listenerPorts[port] {
		return nil, nil, reject("port %d is a listener's", port)
	}
	addresses := map[string]string{}
	prev := ""
	for _, n := range tc.GetNodes() {
		id := n.GetId()
		if !idRE.MatchString(id) || id <= prev {
			return nil, nil, reject("node ids must be valid, sorted and unique (%q)", id)
		}
		prev = id
		if a := n.GetAddress(); a != "" {
			addr, err := netip.ParseAddr(a)
			if err != nil || addr.Zone() != "" || addr.IsUnspecified() {
				return nil, nil, reject("node %s: invalid address %q", id, a)
			}
			addresses[id] = addr.Unmap().String()
		} else {
			addresses[id] = ""
		}
	}
	if len(tc.GetPlans()) > maxTierPlans {
		return nil, nil, reject("more than %d plans", maxTierPlans)
	}
	t := &Tier{Port: port}
	clients := map[string]bool{}
	peers := map[string][]TierPeer{}
	prev = ""
	for _, plan := range tc.GetPlans() {
		pid := plan.GetId()
		if !tierPlanIDRE.MatchString(pid) || pid <= prev {
			return nil, nil, reject("plan ids must be valid, sorted and unique (%q)", pid)
		}
		prev = pid
		hops := map[string][]string{}
		prevNode := ""
		for _, h := range plan.GetHops() {
			nid := h.GetNodeId()
			if _, ok := addresses[nid]; !ok || nid <= prevNode {
				return nil, nil, reject("plan %s: hops must name known nodes, sorted and unique (%q)", pid, nid)
			}
			prevNode = nid
			ups := h.GetUpperNodeIds()
			if len(ups) == 0 || len(ups) > MaxTierUppers {
				return nil, nil, reject("plan %s: node %s has %d upper tiers (1-%d)", pid, nid, len(ups), MaxTierUppers)
			}
			for i, u := range ups {
				if u == nid || slices.Contains(ups[:i], u) || addresses[u] == "" {
					return nil, nil, reject("plan %s: node %s: invalid upper tier %q", pid, nid, u)
				}
			}
			hops[nid] = ups
		}
		if d := tierDepth(hops); d < 0 || d > MaxTierDepth {
			return nil, nil, reject("plan %s: a cycle or a chain longer than %d hops", pid, MaxTierDepth)
		}
		if !used[pid] {
			continue
		}
		for lower, ups := range hops {
			if slices.Contains(ups, nodeID) {
				t.Listen = true
				clients[lower] = true
			}
		}
		if ups := hops[nodeID]; nodeID != "" && len(ups) > 0 {
			list := make([]TierPeer, 0, len(ups))
			for _, u := range ups {
				list = append(list, TierPeer{ID: u, Address: addresses[u], Port: port, CDNID: CDNID(u)})
			}
			peers[pid] = list
			t.Lower = true
		}
	}
	for id := range used {
		if !slices.ContainsFunc(tc.GetPlans(), func(p *nodev1.TierPlan) bool { return p.GetId() == id }) {
			return nil, nil, reject("unknown plan %q", id)
		}
	}
	if len(tc.GetLatencyTargets()) > maxTierLatencyTargets {
		return nil, nil, reject("more than %d latency targets", maxTierLatencyTargets)
	}
	prev = ""
	for _, lt := range tc.GetLatencyTargets() {
		id, host := lt.GetId(), lt.GetHost()
		if !tierPlanIDRE.MatchString(id) || id <= prev {
			return nil, nil, reject("latency target ids must be valid, sorted and unique (%q)", id)
		}
		prev = id
		if _, err := netip.ParseAddr(host); err != nil && !ValidHostname(host) {
			return nil, nil, reject("latency target %s: invalid host %q", id, host)
		}
		if lt.GetPort() == 0 || lt.GetPort() > 65535 {
			return nil, nil, reject("latency target %s: invalid port", id)
		}
		t.LatencyTargets = append(t.LatencyTargets, TierLatencyTarget{ID: id, Host: host, Port: lt.GetPort()})
	}
	for id := range clients {
		t.Clients = append(t.Clients, id)
	}
	slices.Sort(t.Clients)
	if !t.Listen && !t.Lower && len(t.LatencyTargets) == 0 {
		return nil, peers, nil
	}
	return t, peers, nil
}

// tierDepth returns the longest chain of upper tiers in hops (a node's
// upper tiers, each possibly with its own), -1 when they form a cycle.
func tierDepth(hops map[string][]string) int {
	done := map[string]int{}
	onPath := map[string]bool{}
	var walk func(string) int
	walk = func(n string) int {
		if d, ok := done[n]; ok {
			return d
		}
		if onPath[n] {
			return -1
		}
		onPath[n] = true
		longest := 0
		for _, u := range hops[n] {
			d := walk(u)
			if d < 0 {
				return -1
			}
			longest = max(longest, d+1)
		}
		onPath[n] = false
		done[n] = longest
		return longest
	}
	worst := 0
	for n := range hops {
		d := walk(n)
		if d < 0 {
			return -1
		}
		worst = max(worst, d)
	}
	return worst
}
