package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/dataplane"
)

// accesslogInterval is how often `edgeweir-node accesslog` polls the live
// view; the data plane keeps recording for five seconds after each call.
const accesslogInterval = 250 * time.Millisecond

var siteIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// cmdAccesslog prints the requests this node serves as they happen (the
// data plane's live view, ADR-0041 §6), whatever the sites' sample rates,
// until SIGINT or SIGTERM. Missed requests (expired or over the data plane's
// rate) are counted on stderr.
func cmdAccesslog(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("accesslog", stderr)
	controlSocket := fs.String("control-socket", defaultControlSocket, "unix socket of the data plane control API")
	socket := fs.String("socket", "", "short for --control-socket")
	site := fs.String("site", "", "only the requests of this site id (default: every request, unknown hosts included)")
	asJSON := fs.Bool("json", false, "print JSON Lines instead of text")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if *site != "" && !siteIDRE.MatchString(*site) {
		fmt.Fprintf(stderr, "accesslog: invalid --site %q\n", *site)
		return 2
	}
	path := *controlSocket
	if *socket != "" {
		path = *socket
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := tailAccessLog(ctx, dataplane.NewClient(path), *site, *asJSON, accesslogInterval, stdout, stderr); err != nil {
		fmt.Fprintln(stderr, "accesslog:", err)
		return 1
	}
	return 0
}

// tailAccessLog polls the live view every interval and prints its entries
// until ctx ends (nil then). A failing first call is an error; later
// failures are reported once and retried.
func tailAccessLog(ctx context.Context, c *dataplane.Client, site string, asJSON bool, interval time.Duration, stdout, stderr io.Writer) error {
	call := func(after uint64) (*dataplane.TapPage, error) {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		return c.Tap(cctx, after, site)
	}
	page, err := call(0)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	after := page.Seq
	enc := json.NewEncoder(stdout)
	failing := false
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		page, err := call(after)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if !failing {
				fmt.Fprintf(stderr, "accesslog: %v (retrying)\n", err)
				failing = true
			}
			continue
		}
		if failing {
			fmt.Fprintln(stderr, "accesslog: the control socket answers again")
			failing = false
		}
		for _, e := range page.Entries {
			if asJSON {
				if err := enc.Encode(jsonLine(e)); err != nil {
					return err
				}
			} else if _, err := fmt.Fprintln(stdout, textLine(e)); err != nil {
				return err
			}
		}
		if page.Missed > 0 {
			fmt.Fprintf(stderr, "accesslog: %d requests missed\n", page.Missed)
		}
		after = page.Seq
	}
}

// entryTime is an entry's time in UTC.
func entryTime(e dataplane.TapEntry) time.Time {
	return time.UnixMilli(int64(e.Time*1000 + 0.5)).UTC()
}

// field makes a value printable as one field: control characters dropped,
// spaces encoded, "-" when empty.
func field(s string, limit int) string {
	s = strings.ReplaceAll(dataplane.Text(s, limit), " ", "%20")
	if s == "" {
		return "-"
	}
	return s
}

// textLine is the text form of an entry: time (UTC, milliseconds), client
// address, method, host, path, status, bytes sent, duration, cache status
// ("-" without one) and the block reason when there is one.
func textLine(e dataplane.TapEntry) string {
	var b strings.Builder
	b.WriteString(entryTime(e).Format("2006-01-02T15:04:05.000Z07:00"))
	for _, v := range []string{field(e.ClientIP, 64), field(e.Method, 32), field(e.Host, 253), field(e.Path, 2048),
		strconv.FormatUint(uint64(e.Status), 10), strconv.FormatUint(e.BytesSent, 10),
		strconv.FormatUint(uint64(e.DurationMS), 10) + "ms", field(e.CacheStatus, 32)} {
		b.WriteByte(' ')
		b.WriteString(v)
	}
	if e.BlockReason != "" {
		b.WriteString(" blocked=")
		b.WriteString(e.BlockReason)
	}
	return b.String()
}

// jsonEntry is the JSON Lines form of an entry: its fields, the time as an
// RFC 3339 UTC string.
type jsonEntry struct {
	Time string `json:"time"`
	dataplane.TapEntry
}

func jsonLine(e dataplane.TapEntry) jsonEntry {
	return jsonEntry{Time: entryTime(e).Format("2006-01-02T15:04:05.000Z07:00"), TapEntry: e}
}
