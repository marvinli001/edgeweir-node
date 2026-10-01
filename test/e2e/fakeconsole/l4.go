package main

// Layer-4 applications of the container smoke test. The console container
// also runs their origins:
//
//	TCP 7000  echo "a": a line "NAME" is answered with "a"
//	TCP 7003  echo "b" (the same for "b")
//	UDP 7001  echo of each datagram
//	TCP 7002  reads a PROXY protocol header (v1 or v2), answers one JSON
//	          line {version, source, source_port, destination,
//	          destination_port} and then echoes
//
// and the applications (every revision carries the current set):
//
//	l4-echo   TCP 9100 -> console:9 (nothing listens, weight 100, one
//	          failure takes it out) and the echo "a"
//	l4-udp    UDP 9100 -> UDP echo
//	l4-pp1    TCP 9101 -> PROXY reader, PROXY protocol v1
//	l4-pp2    TCP 9102 -> PROXY reader, PROXY protocol v2
//	l4-relay  TCP 9103, PROXY protocol from clients and v2 to the PROXY
//	          reader (the relay); block list 198.51.100.66/32
//	l4-limit  TCP 9104 -> echo "a", one connection at a time
//
// Helper API (the node's stream ports are reached inside the compose
// network):
//
//	GET  /l4/tcp?port=&send=&pp=&lines=  connect to node:port (a PROXY v1
//	          header with client address pp first when set), send `send`
//	          and a newline, answer what came back (up to `lines` lines,
//	          default 1) or "closed" / "timeout"
//	GET  /l4/udp?port=&send=  one datagram, the answer or "timeout"
//	GET  /l4/pp?port=&version=&pp=  the PROXY header the reader saw must
//	          be of that version and carry this connection's address (or
//	          pp:40000 -> 192.0.2.9:443 when pp is set): "ok <src> <dst>"
//	GET  /l4/limit  a second connection to l4-limit is refused while the
//	          first is open and accepted after it closed: "ok"
//	POST /l4/long?op=open|check  open a connection to l4-echo and keep
//	          it; check sends a line on it: "ok" when it comes back
//	POST /l4/add-port  publish l4-extra (TCP 9105 -> echo "a")
//	POST /l4/hot  publish l4-echo with the echo "b" as its only origin
//	GET  /l4-stats  "<app> <connections> <refused> <peak> <bytes received>
//	          <bytes sent>" per application, summed over the uploaded minutes

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"github.com/marvinli001/edgeweir-node/internal/testutil/fakeconsole"
)

var (
	l4Mu   sync.Mutex
	l4Apps = initialL4Apps()
)

func l4App(id string, protocol nodev1.L4Protocol, port uint32, origins ...*nodev1.L4Origin) *nodev1.L4App {
	return &nodev1.L4App{
		Id: id, Protocol: protocol, Port: port, Origins: origins,
		MaxFails: 1, FailTimeoutSeconds: 300, ConnectTimeoutMs: 2000, IdleTimeoutSeconds: 600,
	}
}

func l4Origin(id string, port uint32, weight uint32) *nodev1.L4Origin {
	return &nodev1.L4Origin{Id: id, Address: "console", Port: port, Weight: weight}
}

// initialL4Apps are every application but l4-extra (added by POST
// /l4/add-port), sorted by id.
func initialL4Apps() []*nodev1.L4App {
	const tcp, udp = nodev1.L4Protocol_L4_PROTOCOL_TCP, nodev1.L4Protocol_L4_PROTOCOL_UDP
	pp1 := l4App("l4-pp1", tcp, 9101, l4Origin("reader", 7002, 1))
	pp1.ProxyProtocolVersion = 1
	pp2 := l4App("l4-pp2", tcp, 9102, l4Origin("reader", 7002, 1))
	pp2.ProxyProtocolVersion = 2
	relay := l4App("l4-relay", tcp, 9103, l4Origin("reader", 7002, 1))
	relay.AcceptProxyProtocol, relay.ProxyProtocolVersion = true, 2
	relay.BlockListIds = []string{"l4-blocked"}
	limit := l4App("l4-limit", tcp, 9104, l4Origin("a", 7000, 1))
	limit.MaxConnections = 1
	udpApp := l4App("l4-udp", udp, 9100, l4Origin("echo", 7001, 1))
	udpApp.IdleTimeoutSeconds = 30
	return []*nodev1.L4App{
		l4App("l4-echo", tcp, 9100, l4Origin("a", 7000, 1), l4Origin("dead", 9, 100)),
		limit, pp1, pp2, relay, udpApp,
	}
}

// currentL4 returns the applications every revision carries.
func currentL4() []*nodev1.L4App {
	l4Mu.Lock()
	defer l4Mu.Unlock()
	return slices.Clone(l4Apps)
}

// l4Lists are the IP lists of the applications.
var l4Lists = []*nodev1.IpList{{Id: "l4-blocked", Name: "blocked", Kind: "block", Entries: []string{"198.51.100.66/32"}}}

// serveL4Origins runs the applications' origins (see above).
func serveL4Origins() {
	go serveTCP(":7000", func(c net.Conn) { echoNamed(c, "a") })
	go serveTCP(":7003", func(c net.Conn) { echoNamed(c, "b") })
	go serveTCP(":7002", readProxyHeader)
	pc, err := net.ListenPacket("udp", ":7001")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65536)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	log.Printf("layer-4 origins on TCP 7000, 7002, 7003 and UDP 7001")
}

func serveTCP(addr string, handle func(net.Conn)) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer c.Close()
			handle(c)
		}()
	}
}

func echoNamed(c net.Conn, name string) {
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if line == "NAME\n" {
			line = name + "\n"
		}
		if line != "" {
			if _, werr := io.WriteString(c, line); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// proxyHeader is what the reader saw.
type proxyHeader struct {
	Version         int    `json:"version"`
	Source          string `json:"source"`
	SourcePort      int    `json:"source_port"`
	Destination     string `json:"destination"`
	DestinationPort int    `json:"destination_port"`
	Error           string `json:"error,omitempty"`
}

var v2Signature = []byte("\r\n\r\n\x00\r\nQUIT\n")

func parseProxyHeader(r *bufio.Reader) proxyHeader {
	sig, err := r.Peek(12)
	if err != nil {
		return proxyHeader{Error: err.Error()}
	}
	if bytes.Equal(sig, v2Signature) {
		head := make([]byte, 16)
		if _, err := io.ReadFull(r, head); err != nil {
			return proxyHeader{Error: err.Error()}
		}
		body := make([]byte, binary.BigEndian.Uint16(head[14:]))
		if _, err := io.ReadFull(r, body); err != nil {
			return proxyHeader{Error: err.Error()}
		}
		h := proxyHeader{Version: 2}
		if head[12] != 0x21 {
			h.Error = fmt.Sprintf("command byte %#x", head[12])
			return h
		}
		var size int
		switch head[13] {
		case 0x11:
			size = 4
		case 0x21:
			size = 16
		default:
			h.Error = fmt.Sprintf("family byte %#x", head[13])
			return h
		}
		if len(body) < 2*size+4 {
			h.Error = "short address block"
			return h
		}
		src, _ := netip.AddrFromSlice(body[:size])
		dst, _ := netip.AddrFromSlice(body[size : 2*size])
		h.Source, h.Destination = src.String(), dst.String()
		h.SourcePort = int(binary.BigEndian.Uint16(body[2*size:]))
		h.DestinationPort = int(binary.BigEndian.Uint16(body[2*size+2:]))
		return h
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return proxyHeader{Error: err.Error()}
	}
	f := strings.Fields(strings.TrimSuffix(line, "\r\n"))
	if len(f) != 6 || f[0] != "PROXY" || (f[1] != "TCP4" && f[1] != "TCP6") {
		return proxyHeader{Version: 1, Error: fmt.Sprintf("header %q", line)}
	}
	sp, _ := strconv.Atoi(f[4])
	dp, _ := strconv.Atoi(f[5])
	return proxyHeader{Version: 1, Source: f[2], Destination: f[3], SourcePort: sp, DestinationPort: dp}
}

// readProxyHeader answers the PROXY header it read as a JSON line, then
// echoes.
func readProxyHeader(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	h := parseProxyHeader(r)
	b, _ := json.Marshal(h)
	if _, err := c.Write(append(b, '\n')); err != nil || h.Error != "" {
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	echoNamed(&readerConn{Conn: c, r: r}, "reader")
}

type readerConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *readerConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// dialNode connects to node:port, writing a PROXY v1 header for client
// address pp first when it is set.
func dialNode(port, pp string) (net.Conn, error) {
	ip, err := nodeIPv4()
	if err != nil {
		return nil, err
	}
	c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, port), 3*time.Second)
	if err != nil {
		return nil, err
	}
	if pp != "" {
		if _, err := fmt.Fprintf(c, "PROXY TCP4 %s 192.0.2.9 40000 443\r\n", pp); err != nil {
			c.Close()
			return nil, err
		}
	}
	return c, nil
}

// readLines reads n lines within 3 seconds: "closed" when the node closed
// the connection without sending anything, "timeout" when nothing came.
func readLines(c net.Conn, r *bufio.Reader, n int) string {
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	var out strings.Builder
	for range n {
		line, err := r.ReadString('\n')
		out.WriteString(line)
		if err != nil {
			var ne net.Error
			switch {
			case out.Len() > 0:
				return out.String()
			case errors.As(err, &ne) && ne.Timeout():
				return "timeout"
			default:
				return "closed"
			}
		}
	}
	return out.String()
}

// longConn is the connection POST /l4/long keeps open.
var (
	longMu   sync.Mutex
	longConn net.Conn
	longR    *bufio.Reader
	longN    int
)

func registerL4(mux *http.ServeMux, c *fakeconsole.Console, publish func() uint64) {
	mux.HandleFunc("GET /l4/tcp", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		conn, err := dialNode(q.Get("port"), q.Get("pp"))
		if err != nil {
			fmt.Fprintf(w, "error %v", err)
			return
		}
		defer conn.Close()
		lines, _ := strconv.Atoi(q.Get("lines"))
		_, _ = fmt.Fprintf(conn, "%s\n", q.Get("send"))
		fmt.Fprint(w, readLines(conn, bufio.NewReader(conn), max(lines, 1)))
	})
	mux.HandleFunc("GET /l4/udp", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		ip, err := nodeIPv4()
		if err != nil {
			fmt.Fprintf(w, "error %v", err)
			return
		}
		conn, err := net.Dial("udp", net.JoinHostPort(ip, q.Get("port")))
		if err != nil {
			fmt.Fprintf(w, "error %v", err)
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(q.Get("send")))
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 65536)
		n, err := conn.Read(buf)
		if err != nil {
			fmt.Fprint(w, "timeout")
			return
		}
		w.Write(buf[:n])
	})
	mux.HandleFunc("GET /l4/pp", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		conn, err := dialNode(q.Get("port"), q.Get("pp"))
		if err != nil {
			fmt.Fprintf(w, "error %v", err)
			return
		}
		defer conn.Close()
		_, _ = io.WriteString(conn, "pp-check\n")
		got := readLines(conn, bufio.NewReader(conn), 2)
		lines := strings.SplitN(got, "\n", 2)
		var h proxyHeader
		if err := json.Unmarshal([]byte(lines[0]), &h); err != nil {
			fmt.Fprintf(w, "fail: %q", got)
			return
		}
		local := conn.LocalAddr().(*net.TCPAddr)
		remote := conn.RemoteAddr().(*net.TCPAddr)
		wantSrc, wantSport := local.IP.String(), local.Port
		wantDst, wantDport := remote.IP.String(), remote.Port
		if pp := q.Get("pp"); pp != "" {
			wantSrc, wantSport, wantDst, wantDport = pp, 40000, "192.0.2.9", 443
		}
		version, _ := strconv.Atoi(q.Get("version"))
		if h.Error != "" || h.Version != version || h.Source != wantSrc || h.SourcePort != wantSport ||
			h.Destination != wantDst || h.DestinationPort != wantDport || len(lines) < 2 || lines[1] != "pp-check\n" {
			fmt.Fprintf(w, "fail: got %+v and %q, want v%d %s:%d -> %s:%d", h, lines[1:], version, wantSrc, wantSport, wantDst, wantDport)
			return
		}
		fmt.Fprintf(w, "ok %s:%d %s:%d", h.Source, h.SourcePort, h.Destination, h.DestinationPort)
	})
	mux.HandleFunc("GET /l4/limit", func(w http.ResponseWriter, _ *http.Request) {
		first, err := dialNode("9104", "")
		if err != nil {
			fmt.Fprintf(w, "error %v", err)
			return
		}
		_, _ = io.WriteString(first, "first\n")
		if got := readLines(first, bufio.NewReader(first), 1); got != "first\n" {
			first.Close()
			fmt.Fprintf(w, "first connection: %q", got)
			return
		}
		second, err := dialNode("9104", "")
		if err != nil {
			first.Close()
			fmt.Fprintf(w, "error %v", err)
			return
		}
		_, _ = io.WriteString(second, "second\n")
		got := readLines(second, bufio.NewReader(second), 1)
		second.Close()
		first.Close()
		if got != "closed" {
			fmt.Fprintf(w, "second connection while the first is open: %q", got)
			return
		}
		time.Sleep(500 * time.Millisecond)
		third, err := dialNode("9104", "")
		if err != nil {
			fmt.Fprintf(w, "error %v", err)
			return
		}
		defer third.Close()
		_, _ = io.WriteString(third, "third\n")
		if got := readLines(third, bufio.NewReader(third), 1); got != "third\n" {
			fmt.Fprintf(w, "connection after the first closed: %q", got)
			return
		}
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("POST /l4/long", func(w http.ResponseWriter, r *http.Request) {
		longMu.Lock()
		defer longMu.Unlock()
		if r.URL.Query().Get("op") == "open" {
			if longConn != nil {
				longConn.Close()
			}
			conn, err := dialNode("9100", "")
			if err != nil {
				fmt.Fprintf(w, "error %v", err)
				return
			}
			longConn, longR, longN = conn, bufio.NewReader(conn), 0
		}
		if longConn == nil {
			fmt.Fprint(w, "no connection")
			return
		}
		longN++
		want := fmt.Sprintf("ping-%d\n", longN)
		if _, err := io.WriteString(longConn, want); err != nil {
			fmt.Fprintf(w, "write: %v", err)
			return
		}
		if got := readLines(longConn, longR, 1); got != want {
			fmt.Fprintf(w, "got %q, want %q", got, want)
			return
		}
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("POST /l4/add-port", func(w http.ResponseWriter, _ *http.Request) {
		l4Mu.Lock()
		if !slices.ContainsFunc(l4Apps, func(a *nodev1.L4App) bool { return a.GetId() == "l4-extra" }) {
			l4Apps = append(l4Apps, l4App("l4-extra", nodev1.L4Protocol_L4_PROTOCOL_TCP, 9105, l4Origin("a", 7000, 1)))
			slices.SortFunc(l4Apps, func(a, b *nodev1.L4App) int { return strings.Compare(a.GetId(), b.GetId()) })
		}
		l4Mu.Unlock()
		fmt.Fprint(w, publish())
	})
	mux.HandleFunc("POST /l4/hot", func(w http.ResponseWriter, _ *http.Request) {
		l4Mu.Lock()
		for i, a := range l4Apps {
			if a.GetId() == "l4-echo" {
				hot := l4App("l4-echo", a.GetProtocol(), a.GetPort(), l4Origin("b", 7003, 1))
				hot.IdleTimeoutSeconds = 900
				l4Apps[i] = hot
			}
		}
		l4Mu.Unlock()
		fmt.Fprint(w, publish())
	})
	mux.HandleFunc("GET /l4-stats", func(w http.ResponseWriter, _ *http.Request) {
		type sums struct{ conn, refused, peak, rx, tx uint64 }
		byApp := map[string]*sums{}
		for _, s := range c.L4Stats() {
			b := byApp[s.GetAppId()]
			if b == nil {
				b = &sums{}
				byApp[s.GetAppId()] = b
			}
			b.conn += s.GetConnections()
			b.refused += s.GetRefused()
			b.peak = max(b.peak, s.GetPeakConcurrent())
			b.rx += s.GetBytesReceived()
			b.tx += s.GetBytesSent()
		}
		for _, id := range slices.Sorted(func(yield func(string) bool) {
			for k := range byApp {
				if !yield(k) {
					return
				}
			}
		}) {
			b := byApp[id]
			fmt.Fprintf(w, "%s %d %d %d %d %d\n", id, b.conn, b.refused, b.peak, b.rx, b.tx)
		}
	})
}
