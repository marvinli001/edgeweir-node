// Command console is the minimal console of the SSH install test
// (test/sshinstall): NodeService.Enroll only, plus a plain HTTP side for
// the test script. It is not part of any release artifact.
//
// Enroll follows the console (ADR-0067, Enroll idempotent by key): a CSR
// whose public key already belongs to a node gets that node back with a
// new certificate when the token is the one that node used, or an unused
// token of the node's cluster; any other token is refused. A node is never
// created twice for one key.
//
// HTTP side (--http):
//
//	GET  /pin                  the CA pin (hex SHA-256)
//	POST /token?t=T&cluster=C  add a single-use token of cluster C
//	                           (default cluster-ssh)
//	POST /mode?delay=D&lose=N  delay each Enroll answer by D; lose the
//	                           answers of the next N enrollments (the
//	                           certificate is issued, the node gets an error)
//	GET  /state                {"enrollments": n, "nodes": {id: spki}}
//	                           (clusters are not shown)
//	GET  /mirror/...           files of --mirror (install.sh's --mirror)
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1/nodev1connect"
	"github.com/marvinli001/edgeweir-node/internal/pki/pkitest"
)

// token is a single-use enrollment token.
type token struct {
	cluster string
	owner   string // node id that used it; "" unused
}

type console struct {
	nodev1connect.UnimplementedNodeServiceHandler
	ca *pkitest.CA

	mu          sync.Mutex
	tokens      map[string]*token // by token
	nodes       map[string]string // node id -> SPKI SHA-256
	clusters    map[string]string // node id -> cluster
	enrollments int
	delay       time.Duration
	lose        int
}

func spki(csrPEM string) (string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", errors.New("no CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", err
	}
	if err := csr.CheckSignature(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

func (c *console) Enroll(ctx context.Context, req *connect.Request[nodev1.EnrollRequest]) (*connect.Response[nodev1.EnrollResponse], error) {
	key, err := spki(req.Msg.GetCsrPem())
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	c.mu.Lock()
	tok, known := c.tokens[req.Msg.GetToken()]
	nodeID := ""
	for id, k := range c.nodes {
		if k == key {
			nodeID = id
		}
	}
	allowed := known && (tok.owner == nodeID || (tok.owner == "" && (nodeID == "" || c.clusters[nodeID] == tok.cluster)))
	if !allowed {
		c.mu.Unlock()
		return nil, connect.NewError(connect.CodePermissionDenied, errors.New("invalid, expired or already used enrollment token"))
	}
	if nodeID == "" {
		nodeID = "node-" + strconv.Itoa(len(c.nodes)+1)
		c.nodes[nodeID] = key
		c.clusters[nodeID] = tok.cluster
	}
	tok.owner = nodeID
	c.enrollments++
	lose := c.lose > 0
	if lose {
		c.lose--
	}
	delay, cluster := c.delay, c.clusters[nodeID]
	c.mu.Unlock()
	certPEM, cert, err := c.ca.SignCSR([]byte(req.Msg.GetCsrPem()), nodeID, 24*time.Hour)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err)
	}
	log.Printf("enroll: %s (%s) host %s", nodeID, key[:12], req.Msg.GetInfo().GetHostname())
	select {
	case <-time.After(delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if lose {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("answer lost (test)"))
	}
	return connect.NewResponse(&nodev1.EnrollResponse{
		NodeId: nodeID, ClusterId: cluster, NodeName: nodeID,
		CertificatePem: string(certPEM), CaCertificatePem: string(c.ca.PEM), NotAfter: timestamppb.New(cert.NotAfter),
	}), nil
}

func main() {
	listen := flag.String("listen", ":8443", "node channel (HTTPS)")
	side := flag.String("http", ":8080", "test side (HTTP)")
	mirror := flag.String("mirror", "/mirror", "directory served under /mirror/")
	name := flag.String("name", "console", "DNS name in the server certificate")
	flag.Parse()
	ca, err := pkitest.NewCA("Edgeweir SSH Test CA")
	if err != nil {
		log.Fatal(err)
	}
	c := &console{ca: ca, tokens: map[string]*token{}, nodes: map[string]string{}, clusters: map[string]string{}}
	cert, err := ca.IssueServer([]string{*name, "localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	if err != nil {
		log.Fatal(err)
	}
	path, h := nodev1connect.NewNodeServiceHandler(c)
	mux := http.NewServeMux()
	mux.Handle(path, h)
	srv := &http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, NextProtos: []string{"h2", "http/1.1"}}

	sm := http.NewServeMux()
	sm.HandleFunc("GET /pin", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, ca.Pin()) })
	sm.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		cluster := r.URL.Query().Get("cluster")
		if cluster == "" {
			cluster = "cluster-ssh"
		}
		c.mu.Lock()
		c.tokens[r.URL.Query().Get("t")] = &token{cluster: cluster}
		c.mu.Unlock()
	})
	sm.HandleFunc("POST /mode", func(w http.ResponseWriter, r *http.Request) {
		d, _ := time.ParseDuration(r.URL.Query().Get("delay"))
		n, _ := strconv.Atoi(r.URL.Query().Get("lose"))
		c.mu.Lock()
		c.delay, c.lose = d, n
		c.mu.Unlock()
	})
	sm.HandleFunc("GET /state", func(w http.ResponseWriter, _ *http.Request) {
		c.mu.Lock()
		defer c.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"enrollments": c.enrollments, "nodes": c.nodes})
	})
	sm.Handle("GET /mirror/", http.StripPrefix("/mirror/", http.FileServer(http.Dir(*mirror))))
	go func() { log.Fatal(http.ListenAndServe(*side, sm)) }()
	log.Printf("node channel on %s, pin %s", *listen, ca.Pin())
	log.Fatal(srv.ListenAndServeTLS("", ""))
}
