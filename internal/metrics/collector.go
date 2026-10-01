package metrics

import (
	"errors"
	"math"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
)

// MinInterval: samples closer together than this reuse the previous rates
// (a heartbeat right after another would give noisy rates).
const MinInterval = time.Second

// Collector measures host metrics; rates are taken between two calls of
// Collect.
type Collector struct {
	// Root is the proc file system ("" disables the collector).
	Root string
	// Loopback reports whether an interface is a loopback interface
	// (default: "lo" or the interface's loopback flag).
	Loopback func(name string) bool
	// Now is the clock (tests).
	Now func() time.Time

	mu      sync.Mutex
	at      time.Time
	cpu     CPUTimes
	hasCPU  bool
	tx      map[string]uint64
	percent float64
	egress  uint64
}

// New returns the collector of this platform: /proc on Linux, a disabled
// one elsewhere.
func New() *Collector { return &Collector{Root: defaultRoot} }

// Enabled reports whether the collector measures anything (metrics-v1).
func (c *Collector) Enabled() bool { return c != nil && c.Root != "" }

func isLoopback(name string) bool {
	if name == "lo" {
		return true
	}
	ifi, err := net.InterfaceByName(name)
	return err == nil && ifi.Flags&net.FlagLoopback != 0
}

func (c *Collector) read(name string) (*os.File, error) {
	return os.Open(filepath.Join(c.Root, name))
}

// Collect returns the metrics now (nil when disabled); the rates are 0 on
// the first call. Metrics whose file cannot be read stay 0, and the error
// says which.
func (c *Collector) Collect() (*nodev1.NodeMetrics, error) {
	if !c.Enabled() {
		return nil, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.Now != nil {
		now = c.Now()
	}
	loopback := c.Loopback
	if loopback == nil {
		loopback = isLoopback
	}
	m := &nodev1.NodeMetrics{}
	var errs []error
	if f, err := c.read("loadavg"); err == nil {
		m.Load1, m.Load5, m.Load15, err = ParseLoadavg(f)
		_ = f.Close()
		errs = append(errs, err)
	} else {
		errs = append(errs, err)
	}
	if f, err := c.read("meminfo"); err == nil {
		var total, available uint64
		total, available, err = ParseMeminfo(f)
		_ = f.Close()
		m.MemoryTotalBytes, m.MemoryUsedBytes = total, total-available
		errs = append(errs, err)
	} else {
		errs = append(errs, err)
	}

	elapsed := now.Sub(c.at)
	if c.at.IsZero() || elapsed >= MinInterval {
		cpu, cpuErr := c.readStat()
		tx, txErr := c.readNetDev()
		errs = append(errs, cpuErr, txErr)
		switch {
		case cpuErr != nil:
			c.percent, c.hasCPU = 0, false
		case c.hasCPU:
			c.percent = CPUPercent(c.cpu, cpu)
			c.cpu = cpu
		default:
			c.percent, c.cpu, c.hasCPU = 0, cpu, true
		}
		switch {
		case txErr != nil:
			c.egress, c.tx = 0, nil
		case c.tx != nil && !c.at.IsZero():
			bits := float64(EgressBytes(c.tx, tx, loopback)) * 8 / elapsed.Seconds()
			c.egress = uint64(min(bits, math.MaxUint64/2))
			c.tx = tx
		default:
			c.egress, c.tx = 0, tx
		}
		c.at = now
	}
	m.CpuPercent, m.EgressBps = c.percent, c.egress
	return m, errors.Join(errs...)
}

func (c *Collector) readStat() (CPUTimes, error) {
	f, err := c.read("stat")
	if err != nil {
		return CPUTimes{}, err
	}
	defer f.Close()
	return ParseStat(f)
}

func (c *Collector) readNetDev() (map[string]uint64, error) {
	f, err := c.read(filepath.Join("net", "dev"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseNetDev(f)
}
