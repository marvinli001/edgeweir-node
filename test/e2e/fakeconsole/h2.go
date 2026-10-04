package main

// HTTP/2 to origins and end-to-end gRPC (OriginPool.protocol and grpc,
// feature origin-http2-v1): the test origins of their sites and the gRPC
// client the test script drives through the helper API.
//
//	h2.test       origin console:8090 (HTTP/1.1 and h2c), HTTP/2, cached for
//	              60 s, an active health check of /health every 5 s
//	h2tls.test    origin https://console:8445 (ALPN h2 and http/1.1), SNI
//	              origin.test, HTTP/2
//	h2bad.test    origin console:8091 (HTTP/1.1 only), HTTP/2 (502)
//	grpc.test     origin console:8090, HTTP/2 with gRPC, the OWASP CRS
//	              blocking
//	grpctls.test  origin https://console:8445, SNI origin.test, HTTP/2 with
//	              gRPC
//
// The origins answer /proto with "<protocol> <Host> <ALPN or ->", /body
// with "<protocol> <bytes of the request body>", /health
// with 200 (counted by protocol, GET /h2-probes), /ws as a WebSocket echo,
// and the gRPC methods /e2e.Echo/Unary, /e2e.Echo/Bidi and /e2e.Echo/Fail
// (messages are raw bytes in gRPC's length-prefixed framing; Fail answers
// status 5 in trailers after its headers, an unknown method status 12 in
// a trailers-only response).
//
//	GET /grpc?host=&target=node:80  calls the three methods through the node
//	              over h2c: "unary <status> <grpc-status> <message>",
//	              "bidi <echoes> <grpc-status>" (each message waits for the
//	              echo of the one before, so it fails unless every hop
//	              streams both ways), "fail <status> <grpc-status>
//	              <grpc-message>", "unknown <status> <grpc-status>" (a
//	              trailers-only response: the status in the headers), or
//	              "<call> error <error>"
//	GET /h2-probes  "<protocol> <count>" per protocol of the /health
//	              requests the HTTP/2 origins received
//	GET /ws?host=&target=node:80  a WebSocket echo of "hello" through the
//	              node: the echo ("ws <protocol the origin saw> hello"), or
//	              "error <error>"

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
)

// h2Probes counts the /health requests of the HTTP/2 origins by protocol.
var h2Probes sync.Map

// grpcFrame is msg in gRPC's length-prefixed message framing, uncompressed.
func grpcFrame(msg []byte) []byte {
	b := make([]byte, 5+len(msg))
	binary.BigEndian.PutUint32(b[1:5], uint32(len(msg)))
	copy(b[5:], msg)
	return b
}

// readFrame reads one gRPC message.
func readFrame(r io.Reader) ([]byte, error) {
	var h [5]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(h[1:])
	if h[0] != 0 || n > 1<<20 {
		return nil, errors.New("unexpected frame")
	}
	b := make([]byte, n)
	_, err := io.ReadFull(r, b)
	return b, err
}

func alpnOf(r *http.Request) string {
	if r.TLS == nil {
		return "-"
	}
	return r.TLS.NegotiatedProtocol
}

func h2Handler(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
		serveGRPC(w, r)
		return
	}
	switch r.URL.Path {
	case "/proto":
		fmt.Fprintf(w, "%s %s %s\n", r.Proto, r.Host, alpnOf(r))
	case "/body":
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fmt.Fprintf(w, "%s %d\n", r.Proto, n)
	case "/health":
		v, _ := h2Probes.LoadOrStore(r.Proto, new(atomic.Int64))
		v.(*atomic.Int64).Add(1)
	case "/ws":
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer c.CloseNow()
		typ, msg, err := c.Read(r.Context())
		if err == nil {
			_ = c.Write(r.Context(), typ, append([]byte("ws "+r.Proto+" "), msg...))
		}
		_ = c.Close(websocket.StatusNormalClosure, "")
	default:
		fmt.Fprintf(w, "%s %s\n", r.URL.Path, r.Proto)
	}
}

// serveGRPC answers the gRPC methods; the status travels in the trailers.
func serveGRPC(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Content-Type", "application/grpc")
	h.Set("Trailer", "Grpc-Status, Grpc-Message")
	status, message := "0", ""
	switch r.URL.Path {
	case "/e2e.Echo/Unary":
		msg, err := readFrame(r.Body)
		if err != nil {
			status, message = "3", "no message"
			break
		}
		reply := fmt.Sprintf("echo:%s proto=%s host=%s te=%s alpn=%s", msg, r.Proto, r.Host, r.Header.Get("Te"), alpnOf(r))
		_, _ = w.Write(grpcFrame([]byte(reply)))
	case "/e2e.Echo/Bidi":
		// Headers first: the client sends its next message only after the
		// echo of the one before.
		w.WriteHeader(http.StatusOK)
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		for {
			msg, err := readFrame(r.Body)
			if err != nil {
				break
			}
			_, _ = w.Write(grpcFrame(append([]byte("echo:"), msg...)))
			_ = rc.Flush()
		}
	case "/e2e.Echo/Fail":
		// Headers first, the status in real trailers.
		w.WriteHeader(http.StatusOK)
		_ = http.NewResponseController(w).Flush()
		status, message = "5", "no such thing"
	default:
		// Trailers-only: nothing written, so the status goes out with the
		// headers.
		status, message = "12", "unknown method"
	}
	h.Set("Grpc-Status", status)
	if message != "" {
		h.Set("Grpc-Message", message)
	}
}

// serveH2Origins serves the HTTP/2 test origins: :8090 HTTP/1.1 and h2c,
// :8445 HTTPS for origin.test (certificate of ca) with ALPN h2 and
// http/1.1, :8091 HTTP/1.1 only.
func serveH2Origins(ca *pkitest.CA) {
	cert, err := ca.IssueServer([]string{"origin.test"}, nil)
	if err != nil {
		log.Fatal(err)
	}
	plain, both := new(http.Protocols), new(http.Protocols)
	plain.SetHTTP1(true)
	plain.SetUnencryptedHTTP2(true)
	both.SetHTTP1(true)
	both.SetHTTP2(true)
	servers := []*http.Server{
		{Addr: ":8090", Protocols: plain},
		{Addr: ":8445", Protocols: both, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}},
		{Addr: ":8091"},
	}
	for _, srv := range servers {
		srv.Handler, srv.ReadHeaderTimeout = http.HandlerFunc(h2Handler), 10*time.Second
		go func() {
			if srv.TLSConfig != nil {
				log.Fatal(srv.ListenAndServeTLS("", ""))
			}
			log.Fatal(srv.ListenAndServe())
		}()
	}
	log.Print("HTTP/2 origins on :8090 (h2c), :8445 (h2 over TLS), :8091 (HTTP/1.1 only)")
}

// h2Site sends its requests to origin:port over HTTP/2.
func h2Site(id, domain string, port uint32) *nodev1.Site {
	s := site(id, domain, "console", port)
	s.OriginPool.Protocol = nodev1.OriginProtocol_ORIGIN_PROTOCOL_HTTP2
	return s
}

// h2TLSSite sends its requests to https://console:8445 (SNI origin.test)
// over HTTP/2.
func h2TLSSite(id, domain string) *nodev1.Site {
	s := h2Site(id, domain, 8445)
	s.OriginPool.Origins[0].Scheme = nodev1.OriginScheme_ORIGIN_SCHEME_HTTPS
	s.OriginPool.Origins[0].Sni = "origin.test"
	return s
}

// healthChecked probes /health of the site's origins every 5 seconds.
func healthChecked(s *nodev1.Site) *nodev1.Site {
	s.OriginPool.ActiveHealthCheck = &nodev1.ActiveHealthCheck{
		Path: "/health", IntervalSeconds: 5, TimeoutSeconds: 2, HealthyThreshold: 1, UnhealthyThreshold: 1,
	}
	return s
}

// grpcSite proxies gRPC end to end; nothing is cached.
func grpcSite(s *nodev1.Site) *nodev1.Site {
	s.OriginPool.Grpc = true
	s.CacheRules = nil
	return s
}

// h2Sites are the sites of HTTP/2 to origins and gRPC.
func h2Sites() []*nodev1.Site {
	crs := grpcSite(h2Site("site-grpc", "grpc.test", 8090))
	crs.Waf = &nodev1.SiteWaf{Mode: "block", ParanoiaLevel: 1, AnomalyThreshold: 5, RequestBodyLimit: 131072}
	return []*nodev1.Site{
		healthChecked(h2Site("site-h2", "h2.test", 8090)),
		h2TLSSite("site-h2tls", "h2tls.test"),
		h2Site("site-h2bad", "h2bad.test", 8091),
		crs,
		grpcSite(h2TLSSite("site-grpctls", "grpctls.test")),
	}
}

// grpcCheck calls the gRPC methods through the node (h2c to target).
func grpcCheck(w http.ResponseWriter, r *http.Request) {
	host, target := r.URL.Query().Get("host"), cmpOr(r.URL.Query().Get("target"), "node:80")
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	t := &http.Transport{Protocols: protocols, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}}
	defer t.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	call := func(method string, body io.Reader) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+host+"/e2e.Echo/"+method, body)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("Te", "trailers")
		return t.RoundTrip(req)
	}

	resp, err := call("Unary", bytes.NewReader(grpcFrame([]byte("hello"))))
	if err != nil {
		fmt.Fprintf(w, "unary error %v\n", err)
	} else {
		msg, ferr := readFrame(resp.Body)
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if ferr != nil {
			msg = []byte("read: " + ferr.Error())
		}
		fmt.Fprintf(w, "unary %d %s %s\n", resp.StatusCode, cmpOr(resp.Trailer.Get("Grpc-Status"), "-"), msg)
	}

	pr, pw := io.Pipe()
	resp, err = call("Bidi", pr)
	if err != nil {
		fmt.Fprintf(w, "bidi error %v\n", err)
	} else {
		echoes := 0
		for i := 1; i <= 3; i++ {
			want := fmt.Sprintf("ping-%d", i)
			if _, err := pw.Write(grpcFrame([]byte(want))); err != nil {
				break
			}
			msg, err := readFrame(resp.Body)
			if err != nil || string(msg) != "echo:"+want {
				break
			}
			echoes++
		}
		_ = pw.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		fmt.Fprintf(w, "bidi %d %s\n", echoes, cmpOr(resp.Trailer.Get("Grpc-Status"), "-"))
	}

	resp, err = call("Fail", bytes.NewReader(nil))
	if err != nil {
		fmt.Fprintf(w, "fail error %v\n", err)
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		fmt.Fprintf(w, "fail %d %s %s\n", resp.StatusCode, cmpOr(resp.Trailer.Get("Grpc-Status"), "-"), resp.Trailer.Get("Grpc-Message"))
	}

	resp, err = call("Unknown", bytes.NewReader(nil))
	if err != nil {
		fmt.Fprintf(w, "unknown error %v\n", err)
	} else {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		fmt.Fprintf(w, "unknown %d %s\n", resp.StatusCode, cmpOr(resp.Header.Get("Grpc-Status"), "-"))
	}
}

// wsCheck sends "hello" over a WebSocket through the node.
func wsCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	target := cmpOr(r.URL.Query().Get("target"), "node:80")
	c, _, err := websocket.Dial(ctx, "ws://"+target+"/ws", &websocket.DialOptions{Host: r.URL.Query().Get("host")})
	if err != nil {
		fmt.Fprintf(w, "error %v", err)
		return
	}
	defer c.CloseNow()
	if err := c.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		fmt.Fprintf(w, "error %v", err)
		return
	}
	_, msg, err := c.Read(ctx)
	if err != nil {
		fmt.Fprintf(w, "error %v", err)
		return
	}
	_, _ = w.Write(msg)
	_ = c.Close(websocket.StatusNormalClosure, "")
}

// h2ProbeCounts writes "<protocol> <count>" per protocol of /health requests.
func h2ProbeCounts(w http.ResponseWriter, _ *http.Request) {
	var lines []string
	h2Probes.Range(func(k, v any) bool {
		lines = append(lines, fmt.Sprintf("%s %d", k, v.(*atomic.Int64).Load()))
		return true
	})
	slices.Sort(lines)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
}
