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

// Prefetches request URLs through the node's local edge listeners (unix
// sockets, plain and TLS), so that the responses land in the cache exactly
// as for a client. Those listeners serve the agent only: its requests are
// never banned, counted by CC, challenged, denied by rules or counted in
// the statistics (edgeweir.router), and origins see them from 127.0.0.1.
//
// A device variant is a User-Agent: sites whose cache key separates
// devices (CacheKeyPolicy.device_type) cache one object per class, and
// edgeweir.cachekey classifies a request as mobile when its User-Agent
// matches MOBILE_RE. The mobile User-Agent still names the agent. Requests
// accept the encodings browsers do, so that sites whose origin compresses
// cache the variant browsers ask for.
//
// The cache key holds the scheme: an http URL of a site that has a
// certificate is prefetched over https as well, and a redirect the edge
// itself answers to the https form of the URL (HTTPS only) is followed.
// Any other redirect the edge itself makes fails (nothing was cached);
// redirects of the origin are cached as they are.

// prefetchAcceptEncoding is the Accept-Encoding of prefetch requests:
// what current browsers send.
const prefetchAcceptEncoding = "gzip, deflate, br, zstd"

// edgeResponseHeader marks responses of the local listeners that the edge
// made itself, without the cache or the origin (edgeweir.router).
const edgeResponseHeader = "X-Edgeweir-Edge-Response"

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

// prefetchTargets returns the local edge sockets prefetch requests go to:
// plain, and TLS ("" while no listener speaks HTTPS: nginx.conf has no
// local TLS listener then), and the sites that have a certificate.
func (a *Agent) prefetchTargets() (plain, tlsSocket string, httpsSites map[string]bool) {
	params := a.cfg.Render.WithDefaults()
	a.mu.Lock()
	defer a.mu.Unlock()
	httpsSites = map[string]bool{}
	if a.plan == nil {
		return params.EdgeSocket, "", httpsSites
	}
	for _, l := range a.plan.Listeners {
		if l.TLS {
			tlsSocket = params.EdgeTLSSocket
		}
	}
	for _, s := range a.plan.Sites {
		if s.TLS != nil && s.CertificateID != "" {
			httpsSites[s.ID] = true
		}
	}
	return params.EdgeSocket, tlsSocket, httpsSites
}

// prefetchClient requests URLs through the node's local edge listeners.
type prefetchClient struct {
	*http.Client
	// https is set when https URLs have a listener to go to.
	https bool
	// httpsSites are the sites whose http URLs are prefetched over https
	// as well.
	httpsSites map[string]bool
}

// listenerTLSError is a failed TLS handshake with the node's own HTTPS
// listener (e.g. no certificate for the URL's host).
type listenerTLSError struct{ err error }

func (e *listenerTLSError) Error() string {
	return "TLS handshake with the node's HTTPS listener: " + e.err.Error()
}
func (e *listenerTLSError) Unwrap() error { return e.err }

// newPrefetchClient returns a client for the current listeners: plain
// requests go to the local edge socket, https requests over TLS to the
// local TLS socket (SNI and Host are the URL's host). Redirects are never
// followed by the client (see prefetchOne).
func (a *Agent) newPrefetchClient() *prefetchClient {
	plain, tlsSocket, httpsSites := a.prefetchTargets()
	var d net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return d.DialContext(ctx, "unix", plain)
		},
		DisableCompression:  true,
		MaxIdleConnsPerHost: a.cfg.PrefetchConcurrency,
	}
	if tlsSocket != "" {
		tr.DialTLSContext = func(ctx context.Context, _, hostport string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(hostport)
			if err != nil {
				return nil, err
			}
			raw, err := d.DialContext(ctx, "unix", tlsSocket)
			if err != nil {
				return nil, err
			}
			conn := tls.Client(raw, &tls.Config{
				ServerName: host,
				// The node's own listener: it presents the certificate of
				// the site that serves the host; nothing to verify.
				InsecureSkipVerify: true, //nolint:gosec // the node's own local listener
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
		https:      tlsSocket != "",
		httpsSites: httpsSites,
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
	req.Header.Set("Accept-Encoding", prefetchAcceptEncoding)
	// The address origins see (X-Real-IP, X-Forwarded-For): the local
	// listeners take it as the client address (real_ip_header).
	req.Header.Set("X-Edgeweir-Prefetch-Addr", "127.0.0.1")
	return c.Do(req)
}

// prefetchItem is one prefetch request: a URL of a site and a device
// variant.
type prefetchItem struct {
	site    string
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
	// redirect is the Location of a redirect the edge made itself.
	redirect string
}

// executePrefetch requests every target (URL and device variant).
func (a *Agent) executePrefetch(ctx context.Context, task *nodev1.NodeTask, p *nodev1.PrefetchTask, deadline time.Time) *nodev1.ReportTaskResultRequest {
	items := make([]prefetchItem, 0, len(p.GetTargets()))
	for _, t := range p.GetTargets() {
		items = append(items, prefetchItem{site: t.GetSiteId(), url: t.GetUrl(), variant: t.GetVariant()})
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
	if u.Scheme == "https" {
		return fetchOne(ctx, client, u, userAgent)
	}
	secure := *u
	secure.Scheme = "https"
	o := fetchOne(ctx, client, u, userAgent)
	if o.redirect != "" {
		// The edge answered the http URL itself: only its HTTPS redirect
		// leads to what visitors get.
		if !sameURL(o.redirect, &secure) {
			return prefetchOutcome{done: true, err: fmt.Sprintf("HTTP %d: the edge redirects to %s", o.status, o.redirect),
				reason: "status", status: o.status}
		}
		return fetchOne(ctx, client, &secure, userAgent)
	}
	if o.err != "" || !client.https || !client.httpsSites[it.site] {
		return o
	}
	// Visitors over https use another cache key.
	o = fetchOne(ctx, client, &secure, userAgent)
	if o.err != "" && o.done {
		o.err = secure.String() + ": " + o.err
	}
	return o
}

// fetchOne requests u once. A redirect the edge made itself is a failure
// with its Location in redirect.
func fetchOne(ctx context.Context, client *prefetchClient, u *url.URL, userAgent string) prefetchOutcome {
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
	if resp.StatusCode >= 300 && resp.Header.Get(edgeResponseHeader) != "" {
		return prefetchOutcome{done: true, err: "HTTP " + strconv.Itoa(resp.StatusCode) + " from the edge", reason: "status",
			status: resp.StatusCode, redirect: resp.Header.Get("Location")}
	}
	return prefetchOutcome{done: true}
}

// sameURL reports whether location names u: the same scheme, host (any
// case, default port omitted) and request URI.
func sameURL(location string, u *url.URL) bool {
	l, err := url.Parse(location)
	if err != nil || l.Scheme != u.Scheme || l.RequestURI() != u.RequestURI() {
		return false
	}
	port := func(x *url.URL) string {
		if p := x.Port(); p != "" {
			return p
		}
		if x.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return strings.EqualFold(l.Hostname(), u.Hostname()) && port(l) == port(u)
}

// failedOutcome classifies a transport error; a request cut off by the
// task's time budget is not done.
func failedOutcome(ctx context.Context, err error) prefetchOutcome {
	if ctx.Err() != nil {
		return prefetchOutcome{err: err.Error()}
	}
	return prefetchOutcome{done: true, err: err.Error(), reason: transportReason(err)}
}

// transportReason classifies a transport error: connect_failed, timeout
// or other.
func transportReason(err error) string {
	var netErr net.Error
	var opErr *net.OpError
	switch {
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return "connect_failed"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	}
	return "other"
}
