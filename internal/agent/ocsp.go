package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/configir"
	"github.com/marvinli001/edgeweir-node/internal/fsutil"
	"golang.org/x/crypto/ocsp"
)

// Uploaded AIA URLs are untrusted: pin validated public DNS answers at dial
// time, reject redirects, and never inherit a proxy that bypasses this gate.
func ocspClient() *http.Client {
	policy, _, _ := configir.NewAddressPolicy(nil)
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("OCSP hostname has no addresses")
		}
		for _, ip := range ips {
			if policy.Forbidden(ip.Unmap()) {
				return nil, fmt.Errorf("OCSP address is not public")
			}
		}
		var last error
		for _, ip := range ips {
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return conn, nil
			}
			last = err
		}
		return nil, last
	}}
	return &http.Client{Timeout: 8 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func fetchOCSP(ctx context.Context, material configir.Certificate) (string, int64, error) {
	block, rest := pem.Decode([]byte(material.ChainPEM))
	if block == nil {
		return "", 0, fmt.Errorf("missing leaf")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", 0, err
	}
	if len(leaf.OCSPServer) == 0 {
		return "", 0, nil
	}
	block, _ = pem.Decode(rest)
	if block == nil {
		return "", 0, fmt.Errorf("OCSP needs the issuer certificate")
	}
	issuer, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", 0, err
	}
	endpoint, err := url.Parse(leaf.OCSPServer[0])
	if err != nil || endpoint.User != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") {
		return "", 0, fmt.Errorf("invalid OCSP endpoint")
	}
	if ip, err := netip.ParseAddr(endpoint.Hostname()); err == nil {
		policy, _, _ := configir.NewAddressPolicy(nil)
		if policy.Forbidden(ip) {
			return "", 0, fmt.Errorf("OCSP address is not public")
		}
	}
	request, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return "", 0, err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(request))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")
	client := ocspClient()
	defer client.CloseIdleConnections()
	res, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", 0, fmt.Errorf("OCSP HTTP %d", res.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return "", 0, fmt.Errorf("invalid OCSP response size")
	}
	parsed, err := ocsp.ParseResponseForCert(data, leaf, issuer)
	if err != nil {
		return "", 0, err
	}
	now := time.Now()
	until := parsed.NextUpdate
	if until.IsZero() {
		until = parsed.ThisUpdate.Add(4 * time.Hour)
	}
	if parsed.Status != ocsp.Good || parsed.ThisUpdate.After(now.Add(5*time.Minute)) || parsed.ThisUpdate.Before(now.Add(-7*24*time.Hour)) || !until.After(now) {
		return "", 0, fmt.Errorf("OCSP response is not fresh and good")
	}
	return base64.StdEncoding.EncodeToString(data), until.Unix(), nil
}

func (a *Agent) refreshOCSP(ctx context.Context, plan *configir.Plan) bool {
	changed := false
	seen := map[string]bool{}
	for _, site := range plan.Sites {
		if site.TLS == nil || !site.TLS.OCSPStapling || site.CertificateID == "" {
			continue
		}
		key := site.CertificateID + "/" + plan.Certificates[site.CertificateID]
		if seen[key] {
			continue
		}
		seen[key] = true
		a.mu.Lock()
		material, ok := a.certificates[key]
		a.mu.Unlock()
		if !ok || material.OCSPUntil > time.Now().Add(time.Hour).Unix() {
			continue
		}
		body, until, err := fetchOCSP(ctx, material)
		if err != nil {
			a.log.Warn("OCSP response unavailable", "certificate_id", site.CertificateID)
			continue
		}
		if body == material.OCSP && until == material.OCSPUntil {
			continue
		}
		material.OCSP, material.OCSPUntil = body, until
		a.mu.Lock()
		a.certificates[key] = material
		a.mu.Unlock()
		changed = true
	}
	if changed {
		a.mu.Lock()
		data, err := json.Marshal(a.certificates)
		a.mu.Unlock()
		if err == nil {
			if err = fsutil.WriteFileAtomic(filepath.Join(a.cfg.StateDir, "certificates.json"), data, 0o600); err != nil {
				a.log.Warn("cannot persist OCSP refresh")
			}
		}
	}
	return changed
}

func (a *Agent) triggerOCSP() {
	select {
	case a.ocspCh <- struct{}{}:
	default:
	}
}

// ocspLoop refreshes the OCSP responses of the plan in effect every five
// minutes and after every apply (never during one: a slow responder must
// not hold up the configuration) and pushes the site table when one
// changed.
func (a *Agent) ocspLoop(ctx context.Context) {
	for {
		a.mu.Lock()
		plan := a.plan
		a.mu.Unlock()
		if plan != nil {
			refreshCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			changed := a.refreshOCSP(refreshCtx, plan)
			cancel()
			if changed {
				a.activationMu.Lock()
				a.mu.Lock()
				current := a.plan
				a.mu.Unlock()
				if current == plan {
					copyPlan := *plan
					copyPlan.Sites = slices.Clone(plan.Sites)
					if a.attachCertificates(&copyPlan) == nil {
						table := a.siteTable(&copyPlan)
						if a.pushWithRetry(ctx, table) == nil {
							a.mu.Lock()
							a.plan = &copyPlan
							a.desired = table
							a.mu.Unlock()
						}
					}
				}
				a.activationMu.Unlock()
			}
		}
		t := time.NewTimer(5 * time.Minute)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		case <-a.ocspCh:
			t.Stop()
		}
	}
}
