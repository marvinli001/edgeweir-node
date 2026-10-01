package configir

import (
	"fmt"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Defaults and bounds of ActiveHealthCheck and SessionAffinity. A zero
// value takes the default; any other value outside its range rejects the
// configuration.
const (
	DefaultHealthPath         = "/"
	DefaultHealthMethod       = "GET"
	DefaultHealthStatusMin    = 200
	DefaultHealthStatusMax    = 399
	DefaultHealthInterval     = 30
	MinHealthInterval         = 5
	MaxHealthInterval         = 300
	DefaultHealthTimeout      = 5
	MaxHealthTimeout          = 60
	DefaultHealthyThreshold   = 2
	DefaultUnhealthyThreshold = 3
	MaxHealthThreshold        = 10
	DefaultAffinityTTL        = 3600
	MinAffinityTTL            = 60
	MaxAffinityTTL            = 604800
)

// validHealthPath reports whether p is a valid ActiveHealthCheck.path: "/"
// and up to 1023 more printable ASCII bytes without spaces.
func validHealthPath(p string) bool {
	if p == "" || len(p) > 1024 || p[0] != '/' {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x21 || p[i] > 0x7e {
			return false
		}
	}
	return true
}

// ActiveHealthCheck is a pool's active health check with the defaults
// applied (OriginPool.active_health_check). The agent probes every origin
// of the site except S3 origins and forbidden ones; the site table only
// carries Site.ActiveHealth, the data plane honors the agent's marks for
// such sites.
type ActiveHealthCheck struct {
	// Path is the absolute path (with an optional query) of the probes.
	Path string
	// Method is GET or HEAD.
	Method string
	// ExpectedStatusMin and ExpectedStatusMax bound a healthy answer
	// (inclusive).
	ExpectedStatusMin uint32
	ExpectedStatusMax uint32
	// Host is the probes' Host header; empty means the origin's
	// host_header, else its address.
	Host string
	// Interval separates the probes of an origin; Timeout bounds one
	// probe (never longer than Interval).
	Interval time.Duration
	Timeout  time.Duration
	// HealthyThreshold consecutive successes mark an unhealthy origin
	// healthy, UnhealthyThreshold consecutive failures a healthy one
	// unhealthy.
	HealthyThreshold   uint32
	UnhealthyThreshold uint32
}

// Affinity is a pool's session affinity (site table field "affinity"):
// TTL is the lifetime of the __ew_affinity cookie in seconds.
type Affinity struct {
	TTL uint32 `json:"ttl"`
}

// buildActiveHealthCheck validates a pool's active health check; nil
// stays nil.
func buildActiveHealthCheck(a *nodev1.ActiveHealthCheck) (*ActiveHealthCheck, error) {
	if a == nil {
		return nil, nil
	}
	out := &ActiveHealthCheck{Path: a.GetPath(), Method: a.GetMethod(), Host: a.GetHost()}
	if out.Path == "" {
		out.Path = DefaultHealthPath
	}
	if !validHealthPath(out.Path) {
		return nil, fmt.Errorf("%w: invalid active health check path %q", ErrRejected, out.Path)
	}
	switch out.Method {
	case "":
		out.Method = DefaultHealthMethod
	case "GET", "HEAD":
	default:
		return nil, fmt.Errorf("%w: unsupported active health check method %q", ErrRejected, out.Method)
	}
	var err error
	if out.ExpectedStatusMin, err = ranged(a.GetExpectedStatusMin(), DefaultHealthStatusMin, 100, 599, "expected status minimum"); err != nil {
		return nil, err
	}
	if out.ExpectedStatusMax, err = ranged(a.GetExpectedStatusMax(), DefaultHealthStatusMax, 100, 599, "expected status maximum"); err != nil {
		return nil, err
	}
	if out.ExpectedStatusMin > out.ExpectedStatusMax {
		return nil, fmt.Errorf("%w: expected status range %d-%d is empty", ErrRejected, out.ExpectedStatusMin, out.ExpectedStatusMax)
	}
	if out.Host != "" && !validHostHeader(out.Host) {
		return nil, fmt.Errorf("%w: invalid active health check host %q", ErrRejected, out.Host)
	}
	interval, err := ranged(a.GetIntervalSeconds(), DefaultHealthInterval, MinHealthInterval, MaxHealthInterval, "active health check interval")
	if err != nil {
		return nil, err
	}
	timeout, err := ranged(a.GetTimeoutSeconds(), min(DefaultHealthTimeout, interval), 1, MaxHealthTimeout, "active health check timeout")
	if err != nil {
		return nil, err
	}
	if timeout > interval {
		return nil, fmt.Errorf("%w: active health check timeout %ds exceeds the interval %ds", ErrRejected, timeout, interval)
	}
	out.Interval, out.Timeout = time.Duration(interval)*time.Second, time.Duration(timeout)*time.Second
	if out.HealthyThreshold, err = ranged(a.GetHealthyThreshold(), DefaultHealthyThreshold, 1, MaxHealthThreshold, "healthy threshold"); err != nil {
		return nil, err
	}
	if out.UnhealthyThreshold, err = ranged(a.GetUnhealthyThreshold(), DefaultUnhealthyThreshold, 1, MaxHealthThreshold, "unhealthy threshold"); err != nil {
		return nil, err
	}
	return out, nil
}

// buildAffinity validates a pool's session affinity; nil stays nil.
func buildAffinity(a *nodev1.SessionAffinity) (*Affinity, error) {
	if a == nil {
		return nil, nil
	}
	ttl, err := ranged(a.GetTtlSeconds(), DefaultAffinityTTL, MinAffinityTTL, MaxAffinityTTL, "session affinity lifetime")
	if err != nil {
		return nil, err
	}
	return &Affinity{TTL: ttl}, nil
}
