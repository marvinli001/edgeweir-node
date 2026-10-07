package agent

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// Sitemap prefetch tasks (SitemapPrefetchTask). The node fetches the
// sitemap through its own edge layer, like a prefetch (desktop User-Agent,
// redirects not followed), so the origin address policy applies and the
// console makes no outbound request; then it prefetches the URLs listed.
//
//   - Every document gets at most 30 s and 50 MiB, after gunzip: a body
//     that starts with the gzip magic bytes 1f 8b is gunzipped.
//   - A urlset lists url/loc, a sitemapindex sitemap/loc; an index is
//     followed one level (a child that is itself an index is skipped).
//     Element names are compared without their namespace.
//   - Only absolute http(s) URLs whose host the edge routes to the site
//     (its exact domains, or one label below its wildcard domains, in the
//     applied plan) are kept, in document order and without repetitions,
//     up to max_urls (0: 1000, at most 10000). Child sitemaps must be on
//     the site's hosts too.
//   - Then every URL is prefetched in every variant with the prefetch
//     concurrency and the batch's time budget; succeeded and failed count
//     these requests.
//
// A document that cannot be fetched or parsed fails the task with
// sitemap_failed {url, reason, status}; for a child of an index the other
// children and the prefetches still run. A sitemap without a URL of the
// site fails with sitemap_empty {url}. Otherwise the result is that of the
// prefetches.

const (
	defaultSitemapURLs = 1000
	maxSitemapURLs     = 10000
	// maxSitemapLoc is the sitemap protocol's URL length limit (also the
	// console's for prefetch URLs).
	maxSitemapLoc = 2048
)

// sitemapLimits bound the fetch of one sitemap document: its time and its
// size (unpacked).
type sitemapLimits struct {
	timeout time.Duration
	bytes   int64
}

var documentLimits = sitemapLimits{timeout: 30 * time.Second, bytes: 50 << 20}

// sitemapLimit is the number of URLs a task prefetches at most.
func sitemapLimit(maxURLs uint32) int {
	switch {
	case maxURLs == 0:
		return defaultSitemapURLs
	case maxURLs > maxSitemapURLs:
		return maxSitemapURLs
	}
	return int(maxURLs)
}

// sitemapVariants returns the task's device variants without repetitions;
// none means desktop.
func sitemapVariants(list []nodev1.DeviceVariant) []nodev1.DeviceVariant {
	var out []nodev1.DeviceVariant
	for _, v := range list {
		if v == nodev1.DeviceVariant_DEVICE_VARIANT_UNSPECIFIED {
			v = nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		out = []nodev1.DeviceVariant{nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP}
	}
	return out
}

// siteHosts tells whether the edge routes a host to one site, by the
// precedence of edgeweir.store.lookup_host (configir.HostMatcher).
type siteHosts struct {
	site    string
	matcher *configir.HostMatcher
}

// siteHosts returns the hosts of a site the applied plan serves.
func (a *Agent) siteHosts(siteID string) (*siteHosts, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.plan == nil {
		return nil, false
	}
	served := false
	for _, s := range a.plan.Sites {
		served = served || s.ID == siteID
	}
	return &siteHosts{site: siteID, matcher: configir.NewHostMatcher(a.plan.Sites)}, served
}

func (h *siteHosts) serves(host string) bool {
	return h.matcher.Match(host) == h.site
}

// url returns loc as an absolute http(s) URL without fragment when the
// edge routes its host to the site.
func (h *siteHosts) url(loc string) (string, bool) {
	if loc == "" || len(loc) > maxSitemapLoc {
		return "", false
	}
	u, err := url.Parse(loc)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", false
	}
	if !h.serves(strings.ToLower(u.Hostname())) {
		return "", false
	}
	u.Host = strings.ToLower(u.Host)
	u.Fragment, u.RawFragment = "", ""
	return u.String(), true
}

// sitemapError is why a sitemap document could not be used.
type sitemapError struct {
	url string
	// reason: status, connect_failed, timeout, https_unsupported,
	// invalid, too_large or other.
	reason string
	status int // with reason "status"
	err    string
}

func (e *sitemapError) params() map[string]string {
	p := map[string]string{"url": e.url, "reason": e.reason}
	if e.reason == "status" {
		p["status"] = strconv.Itoa(e.status)
	}
	return p
}

func (e *sitemapError) message() string { return "sitemap " + e.url + ": " + e.err }

var errTooLarge = errors.New("sitemap too large")

// cappedReader fails with errTooLarge once more than left bytes are read.
type cappedReader struct {
	r    io.Reader
	left int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, errTooLarge
	}
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.r.Read(p)
	if c.left -= int64(n); c.left < 0 {
		return 0, errTooLarge
	}
	return n, err
}

// bodyError is a failure to read a response body, as opposed to a body
// that is not a sitemap.
type bodyError struct{ err error }

func (e *bodyError) Error() string { return "read body: " + e.err.Error() }
func (e *bodyError) Unwrap() error { return e.err }

type bodyReader struct{ r io.Reader }

func (b bodyReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	if err != nil && err != io.EOF {
		err = &bodyError{err}
	}
	return n, err
}

// fetchSitemap fetches the sitemap at raw through the edge within lim and
// calls visit with the loc of every entry (index: the document is a
// sitemapindex) until visit returns false.
func fetchSitemap(ctx context.Context, c *prefetchClient, raw string, lim sitemapLimits, visit func(index bool, loc string) bool) *sitemapError {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return &sitemapError{url: raw, reason: "other", err: "invalid URL"}
	}
	if u.Scheme == "https" && !c.https {
		return &sitemapError{url: raw, reason: "https_unsupported", err: "HTTPS needs an HTTPS listener on the node"}
	}
	dctx, cancel := context.WithTimeout(ctx, lim.timeout)
	defer cancel()
	userAgent, _ := prefetchUserAgent(nodev1.DeviceVariant_DEVICE_VARIANT_DESKTOP)
	resp, err := c.get(dctx, u, userAgent)
	if err != nil {
		return &sitemapError{url: raw, reason: transportReason(err), err: err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return &sitemapError{url: raw, reason: "status", status: resp.StatusCode, err: "HTTP " + strconv.Itoa(resp.StatusCode)}
	}
	// The packed size is bounded too: gzip members that unpack to nothing
	// would otherwise be read until the timeout.
	br := bufio.NewReader(&cappedReader{r: bodyReader{resp.Body}, left: lim.bytes})
	var r io.Reader = br
	if magic, _ := br.Peek(2); len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return documentError(raw, lim, err)
		}
		defer zr.Close()
		r = &cappedReader{r: zr, left: lim.bytes}
	}
	if err := parseSitemap(r, visit); err != nil {
		return documentError(raw, lim, err)
	}
	return nil
}

// documentError classifies a failure to read or parse a sitemap body.
func documentError(raw string, lim sitemapLimits, err error) *sitemapError {
	var be *bodyError
	switch {
	case errors.Is(err, errTooLarge):
		size := strconv.FormatInt(lim.bytes, 10) + " bytes"
		if lim.bytes%(1<<20) == 0 {
			size = strconv.FormatInt(lim.bytes>>20, 10) + " MiB"
		}
		return &sitemapError{url: raw, reason: "too_large", err: "larger than " + size + " unpacked"}
	case errors.As(err, &be):
		return &sitemapError{url: raw, reason: transportReason(be.err), err: err.Error()}
	}
	return &sitemapError{url: raw, reason: "invalid", err: "not a sitemap: " + err.Error()}
}

// parseSitemap reads a urlset or sitemapindex document and calls visit
// with the loc of every url (sitemap) entry in document order until visit
// returns false. Element names are compared without their namespace;
// surrounding white space of a loc is ignored, locs longer than
// maxSitemapLoc are skipped.
func parseSitemap(r io.Reader, visit func(index bool, loc string) bool) error {
	d := xml.NewDecoder(r)
	index, entry := false, ""
	depth := 0
	inEntry, inLoc := false, false
	var loc strings.Builder
	for {
		tok, err := d.Token()
		if err == io.EOF {
			return errors.New("no root element")
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			depth++
			switch {
			case depth == 1:
				switch t.Name.Local {
				case "urlset":
					entry = "url"
				case "sitemapindex":
					index, entry = true, "sitemap"
				default:
					return fmt.Errorf("root element %q is neither urlset nor sitemapindex", t.Name.Local)
				}
			case depth == 2:
				inEntry = t.Name.Local == entry
			case depth == 3 && inEntry && t.Name.Local == "loc":
				inLoc = true
				loc.Reset()
			}
		case xml.CharData:
			// Bounded: a longer loc is skipped anyway (white space aside).
			if inLoc && depth == 3 && loc.Len() <= 2*maxSitemapLoc {
				loc.Write(t)
			}
		case xml.EndElement:
			if depth == 3 && inLoc {
				inLoc = false
				if s := strings.TrimSpace(loc.String()); s != "" && len(s) <= maxSitemapLoc && !visit(index, s) {
					return nil
				}
			}
			if depth == 2 {
				inEntry = false
			}
			if depth--; depth == 0 {
				return nil // anything after the root element is ignored
			}
		}
	}
}

// sitemapURLs fetches the sitemap at root (an index one level deep) and
// returns the site's URLs it lists, up to limit, and the first document
// that could not be used. When that is root itself nothing else was
// fetched; skipped counts child sitemaps that were not followed (other
// hosts, nested indexes).
func sitemapURLs(ctx context.Context, c *prefetchClient, hosts *siteHosts, root string, limit int, lim sitemapLimits) (urls []string, fail *sitemapError, skipped int) {
	if _, ok := hosts.url(root); !ok {
		return nil, &sitemapError{url: root, reason: "other", err: "not a URL on a host of the site"}, 0
	}
	seen := map[string]bool{}
	add := func(loc string) bool {
		if u, ok := hosts.url(loc); ok && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
		return len(urls) < limit
	}
	var children []string
	listed := map[string]bool{}
	fail = fetchSitemap(ctx, c, root, lim, func(index bool, loc string) bool {
		if !index {
			return add(loc)
		}
		if u, ok := hosts.url(loc); !ok {
			skipped++
		} else if !listed[u] {
			listed[u] = true
			children = append(children, u)
		}
		return true
	})
	if fail != nil {
		return nil, fail, 0
	}
	for _, child := range children {
		if len(urls) >= limit {
			break
		}
		nested := false
		err := fetchSitemap(ctx, c, child, lim, func(index bool, loc string) bool {
			if index {
				nested = true // followed one level only
				return false
			}
			return add(loc)
		})
		if nested {
			skipped++
		}
		if err != nil && fail == nil {
			fail = err
		}
		if ctx.Err() != nil {
			break // the time budget is spent
		}
	}
	return urls, fail, skipped
}

// executeSitemap prefetches the URLs of a sitemap (see above).
func (a *Agent) executeSitemap(ctx context.Context, task *nodev1.NodeTask, s *nodev1.SitemapPrefetchTask, deadline time.Time) *nodev1.ReportTaskResultRequest {
	failed := func(e *sitemapError, ok, failedN uint32, more string) *nodev1.ReportTaskResultRequest {
		msg := e.message()
		if more != "" {
			msg += "; " + more
		}
		return withCode(result(task, ok, failedN, nodev1.TaskState_TASK_STATE_FAILED, msg), codeSitemapFailed, e.params())
	}
	hosts, served := a.siteHosts(s.GetSiteId())
	if !served {
		return failed(&sitemapError{url: s.GetUrl(), reason: "other", err: "site " + strconv.Quote(s.GetSiteId()) + " is not served by this node"}, 0, 0, "")
	}
	client := a.newPrefetchClient()
	defer client.CloseIdleConnections()
	bctx, cancel := context.WithDeadline(ctx, deadline)
	urls, fail, skipped := sitemapURLs(bctx, client, hosts, s.GetUrl(), sitemapLimit(s.GetMaxUrls()), documentLimits)
	cancel()
	if skipped > 0 {
		a.log.Info("sitemap: child sitemaps skipped (other hosts or nested indexes)", "task_id", task.GetId(), "skipped", skipped)
	}
	if len(urls) == 0 {
		if fail != nil {
			return failed(fail, 0, 0, "")
		}
		return withCode(result(task, 0, 0, nodev1.TaskState_TASK_STATE_FAILED, "sitemap "+s.GetUrl()+" lists no URL of the site"),
			codeSitemapEmpty, map[string]string{"url": s.GetUrl()})
	}
	variants := sitemapVariants(s.GetVariants())
	items := make([]prefetchItem, 0, len(urls)*len(variants))
	for _, u := range urls {
		for _, v := range variants {
			items = append(items, prefetchItem{site: s.GetSiteId(), url: u, variant: v})
		}
	}
	res := a.prefetchAll(ctx, task, client, items, deadline)
	if fail != nil {
		// A sitemap of the index could not be used; the URLs of the
		// others were prefetched.
		return failed(fail, res.GetSucceeded(), res.GetFailed(), res.GetMessage())
	}
	return res
}
