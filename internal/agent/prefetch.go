package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/version"
)

// Prefetches request URLs through the node's own edge listeners, so that
// the responses land in the cache exactly as for a client. A device
// variant is a User-Agent: sites whose cache key separates devices
// (CacheKeyPolicy.device_type) cache one object per class, and
// edgeweir.cachekey classifies a request as mobile when its User-Agent
// matches MOBILE_RE. The mobile User-Agent still names the agent.

// prefetchUserAgent returns the User-Agent of a device variant (false for
// a variant this node does not know).
func prefetchUserAgent(v nodev1.DeviceVariant) (string, bool) {
	switch v {
	case nodev1.DeviceVariant_DEVICE_VARIANT_UNSPECIFIED, nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP:
		return "edgeweir-node-prefetch/" + version.Version, true
	case nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE:
		return "Mozilla/5.0 (Linux; Android 14; Mobile) edgeweir-node-prefetch/" + version.Version, true
	}
	return "", false
}

// variantName labels a variant in result messages ("" for desktop).
func variantName(v nodev1.DeviceVariant) string {
	switch v {
	case nodev1.DeviceVariant_DEVICE_VARIANT_UNSPECIFIED, nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP:
		return ""
	case nodev1.DeviceVariant_DEVICE_VARIANT_MOBILE:
		return "mobile"
	}
	return "variant " + strconv.Itoa(int(v))
}

// prefetchTargets returns where prefetch requests go. Plain http URLs: the
// first listener that speaks HTTP without the PROXY protocol (at
// PrefetchHost), else the local edge socket (a PROXY protocol listener
// would reject the agent's requests). https URLs: the first HTTPS listener
// without the PROXY protocol, "" when there is none.
func (a *Agent) prefetchTargets() (network, addr, tlsAddr string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	port, tlsPort := a.cfg.DefaultPort, uint32(0)
	if a.plan != nil && len(a.plan.Listeners) > 0 {
		port = 0
		for _, l := range a.plan.Listeners {
			switch {
			case l.ProxyProtocol:
			case l.TLS:
				if tlsPort == 0 {
					tlsPort = l.Port
				}
			case port == 0:
				port = l.Port
			}
		}
	}
	if tlsPort != 0 {
		tlsAddr = net.JoinHostPort(a.cfg.PrefetchHost, strconv.Itoa(int(tlsPort)))
	}
	if port == 0 {
		return "unix", a.cfg.Render.WithDefaults().EdgeSocket, tlsAddr
	}
	return "tcp", net.JoinHostPort(a.cfg.PrefetchHost, strconv.Itoa(int(port))), tlsAddr
}

// prefetchClient requests URLs through the node's edge listeners.
type prefetchClient struct {
	*http.Client
	// https is set when https URLs have a listener to go to.
	https bool
}

// listenerTLSError is a failed TLS handshake with the node's own HTTPS
// listener (e.g. no certificate for the URL's host).
type listenerTLSError struct{ err error }

func (e *listenerTLSError) Error() string {
	return "TLS handshake with the node's HTTPS listener: " + e.err.Error()
}
func (e *listenerTLSError) Unwrap() error { return e.err }

// newPrefetchClient returns a client for the current listeners: plain
// requests go to the plain listener or the edge socket, https requests
// over TLS to the HTTPS listener (SNI and Host are the URL's host).
// Redirects are cached as they are, never followed.
func (a *Agent) newPrefetchClient() *prefetchClient {
	network, addr, tlsAddr := a.prefetchTargets()
	var d net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
		DisableCompression:  true,
		MaxIdleConnsPerHost: a.cfg.PrefetchConcurrency,
	}
	if tlsAddr != "" {
		tr.DialTLSContext = func(ctx context.Context, _, hostport string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(hostport)
			if err != nil {
				return nil, err
			}
			raw, err := d.DialContext(ctx, "tcp", tlsAddr)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, &tls.Config{
				ServerName: host,
				// The node's own listener: it presents the certificate of
				// the site that serves the host; nothing to verify.
				InsecureSkipVerify: true, //nolint:gosec // the node's own listener
				NextProtos:         []string{"http/1.1"},
			})
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, &listenerTLSError{err}
			}
			return conn, nil
		}
	}
	return &prefetchClient{
		Client: &http.Client{
			Timeout:       a.cfg.PrefetchTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			Transport:     tr,
		},
		https: tlsAddr != "",
	}
}

// get requests u through the edge with the given User-Agent; the Host
// header is the URL's host without the port.
func (c *prefetchClient) get(ctx context.Context, u *url.URL, userAgent string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Scheme+"://"+u.Host+u.RequestURI(), nil)
	if err != nil {
		return nil, err
	}
	req.Host = u.Hostname()
	req.Header.Set("User-Agent", userAgent)
	return c.Do(req)
}

// prefetchItem is one prefetch request: a URL and a device variant.
type prefetchItem struct {
	url     string
	variant nodev1.DeviceVariant
}

// label names an item in result messages.
func (it prefetchItem) label() string {
	if v := variantName(it.variant); v != "" {
		return it.url + " (" + v + ")"
	}
	return it.url
}

// prefetchOutcome is the result of one prefetch request.
type prefetchOutcome struct {
	done   bool   // false: not attempted or cut off by the time budget
	err    string // empty on success
	reason string // status, connect_failed, timeout, https_unsupported, other
	status int    // HTTP status when reason is "status"
}

// executePrefetch requests every target (URL and device variant).
func (a *Agent) executePrefetch(ctx context.Context, task *nodev1.NodeTask, p *nodev1.PrefetchTask, deadline time.Time) *nodev1.ReportTaskResultRequest {
	items := make([]prefetchItem, 0, len(p.GetTargets()))
	for _, t := range p.GetTargets() {
		items = append(items, prefetchItem{url: t.GetUrl(), variant: t.GetVariant()})
	}
	client := a.newPrefetchClient()
	defer client.CloseIdleConnections()
	return a.prefetchAll(ctx, task, client, items, deadline)
}

// prefetchAll requests every item through the node's own edge listeners
// with bounded concurrency until deadline. 2xx and 3xx count as success.
func (a *Agent) prefetchAll(ctx context.Context, task *nodev1.NodeTask, client *prefetchClient, items []prefetchItem, deadline time.Time) *nodev1.ReportTaskResultRequest {
	bctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	outcomes := make([]prefetchOutcome, len(items))
	sem := make(chan struct{}, a.cfg.PrefetchConcurrency)
	var wg sync.WaitGroup
	for i, it := range items {
		select {
		case sem <- struct{}{}:
		case <-bctx.Done():
		}
		if bctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			outcomes[i] = prefetchOne(bctx, client, it)
		}()
	}
	wg.Wait()
	timedOut := ctx.Err() == nil && bctx.Err() != nil

	var ok, failed, done uint32
	var msgs []string
	first := -1
	for i, o := range outcomes {
		switch {
		case !o.done:
			failed++
		case o.err == "":
			ok++
			done++
		default:
			failed++
			done++
			if first < 0 {
				first = i
			}
			if len(msgs) < 5 {
				msgs = append(msgs, items[i].label()+": "+o.err)
			}
		}
	}
	total := strconv.Itoa(len(items))
	if timedOut && done < uint32(len(items)) {
		msgs = append([]string{fmt.Sprintf("prefetch time budget exhausted: %d of %d URLs done", done, len(items))}, msgs...)
		return withCode(result(task, ok, failed, nodev1.TaskState_TASK_STATE_FAILED, strings.Join(msgs, "; ")),
			codePrefetchTimeout, map[string]string{"done": strconv.Itoa(int(done)), "total": total})
	}
	if failed == 0 {
		return result(task, ok, 0, nodev1.TaskState_TASK_STATE_SUCCEEDED, "")
	}
	o := outcomes[first]
	params := map[string]string{"failed": strconv.Itoa(int(failed)), "total": total, "url": items[first].url, "reason": o.reason}
	if o.reason == "status" {
		params["status"] = strconv.Itoa(o.status)
	}
	return withCode(result(task, ok, failed, nodev1.TaskState_TASK_STATE_FAILED, strings.Join(msgs, "; ")), codePrefetchFailed, params)
}

func prefetchOne(ctx context.Context, client *prefetchClient, it prefetchItem) prefetchOutcome {
	u, err := url.Parse(it.url)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return prefetchOutcome{done: true, err: "invalid URL", reason: "other"}
	}
	userAgent, ok := prefetchUserAgent(it.variant)
	if !ok {
		return prefetchOutcome{done: true, err: "unsupported device variant", reason: "other"}
	}
	if u.Scheme == "https" && !client.https {
		return prefetchOutcome{done: true, err: "HTTPS prefetch needs an HTTPS listener on the node", reason: "https_unsupported"}
	}
	resp, err := client.get(ctx, u, userAgent)
	if err != nil {
		return failedOutcome(ctx, err)
	}
	defer resp.Body.Close()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		o := failedOutcome(ctx, err)
		o.err = "read body: " + o.err
		return o
	}
	if resp.StatusCode >= 400 {
		return prefetchOutcome{done: true, err: "HTTP " + strconv.Itoa(resp.StatusCode), reason: "status", status: resp.StatusCode}
	}
	return prefetchOutcome{done: true}
}

// failedOutcome classifies a transport error; a request cut off by the
// task's time budget is not done.
func failedOutcome(ctx context.Context, err error) prefetchOutcome {
	if ctx.Err() != nil {
		return prefetchOutcome{err: err.Error()}
	}
	var netErr net.Error
	var opErr *net.OpError
	switch {
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return prefetchOutcome{done: true, err: err.Error(), reason: "connect_failed"}
	case errors.As(err, &netErr) && netErr.Timeout():
		return prefetchOutcome{done: true, err: err.Error(), reason: "timeout"}
	default:
		return prefetchOutcome{done: true, err: err.Error(), reason: "other"}
	}
}
