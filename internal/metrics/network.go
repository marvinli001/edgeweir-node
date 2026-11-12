package metrics

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ParseNetwork keeps uint64 RX and TX counters without converting through floats.
func ParseNetwork(r io.Reader, loopback func(string) bool) ([]*nodev1.InterfaceCounters, error) {
	var out []*nodev1.InterfaceCounters
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		name, rest, ok := strings.Cut(scanner.Text(), ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		fields := strings.Fields(rest)
		if len(fields) < 16 {
			return nil, fmt.Errorf("/proc/net/dev: incomplete interface %s", name)
		}
		if loopback(name) {
			continue
		}
		rx, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return nil, err
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return nil, err
		}
		out = append(out, &nodev1.InterfaceCounters{Name: name, BytesReceived: rx, BytesSent: tx})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *Collector) readNetwork(now time.Time, loopback func(string) bool) (*nodev1.NetworkCounters, error) {
	boot, err := os.ReadFile(filepath.Join(c.Root, "sys/kernel/random/boot_id"))
	if err != nil {
		return nil, err
	}
	bootID := strings.TrimSpace(string(boot))
	if len(bootID) != 36 {
		return nil, fmt.Errorf("invalid Linux boot identity")
	}
	f, err := c.read("net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	interfaces, err := ParseNetwork(f, loopback)
	if err != nil {
		return nil, err
	}
	return &nodev1.NetworkCounters{BootId: bootID, SampledAt: timestamppb.New(now), Interfaces: interfaces}, nil
}
