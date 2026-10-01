// Package metrics measures the host metrics the agent reports with every
// heartbeat (feature metrics-v1, ReportStatusRequest.metrics):
//
//	cpu_percent        host-wide CPU use between two reports, from the
//	                   aggregate "cpu" line of /proc/stat (busy = all time
//	                   but idle and iowait; guest time is already part of
//	                   user and nice)
//	load1/5/15         /proc/loadavg
//	memory             /proc/meminfo: MemTotal, used = MemTotal -
//	                   MemAvailable (MemFree + Buffers + Cached on kernels
//	                   without MemAvailable)
//	egress_bps         bits per second sent on non-loopback interfaces
//	                   between two reports, from the tx bytes of
//	                   /proc/net/dev (the network namespace of the agent)
//
// active_connections comes from the data plane (nginx $connections_active,
// see the agent). The parsers are pure; Collector reads the files under a
// root (/proc). Only Linux builds measure anything.
package metrics

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// CPUTimes are the aggregate CPU times of /proc/stat in clock ticks.
type CPUTimes struct {
	// Total is user + nice + system + idle + iowait + irq + softirq +
	// steal; Idle is idle + iowait.
	Total uint64
	Idle  uint64
}

// ParseStat reads the aggregate "cpu" line of /proc/stat.
func ParseStat(r io.Reader) (CPUTimes, error) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		values := fields[1:]
		if len(values) < 4 {
			return CPUTimes{}, fmt.Errorf("/proc/stat: cpu line has %d values", len(values))
		}
		var t CPUTimes
		// guest and guest_nice (values 8 and 9) are included in user and nice.
		for i, f := range values[:min(len(values), 8)] {
			v, err := strconv.ParseUint(f, 10, 64)
			if err != nil {
				return CPUTimes{}, fmt.Errorf("/proc/stat: cpu value %q: %w", f, err)
			}
			t.Total += v
			if i == 3 || i == 4 { // idle, iowait
				t.Idle += v
			}
		}
		return t, nil
	}
	if err := s.Err(); err != nil {
		return CPUTimes{}, err
	}
	return CPUTimes{}, errors.New("/proc/stat: no cpu line")
}

// CPUPercent is the CPU use between two samples, 0-100.
func CPUPercent(prev, cur CPUTimes) float64 {
	if cur.Total <= prev.Total || cur.Idle < prev.Idle {
		return 0
	}
	total := float64(cur.Total - prev.Total)
	idle := float64(cur.Idle - prev.Idle)
	return min(max((total-idle)/total*100, 0), 100)
}

// ParseLoadavg reads the 1, 5 and 15 minute load averages.
func ParseLoadavg(r io.Reader) (load1, load5, load15 float64, err error) {
	b, err := io.ReadAll(io.LimitReader(r, 4096))
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("/proc/loadavg: %q", b)
	}
	var v [3]float64
	for i := range v {
		if v[i], err = strconv.ParseFloat(fields[i], 64); err != nil || v[i] < 0 {
			return 0, 0, 0, fmt.Errorf("/proc/loadavg: %q", fields[i])
		}
	}
	return v[0], v[1], v[2], nil
}

// ParseMeminfo returns the total and available memory in bytes.
func ParseMeminfo(r io.Reader) (total, available uint64, err error) {
	kb := map[string]uint64{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		name, rest, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if len(fields) > 1 && fields[1] != "kB" {
			continue
		}
		kb[name] = v
	}
	if err := s.Err(); err != nil {
		return 0, 0, err
	}
	t, ok := kb["MemTotal"]
	if !ok || t == 0 {
		return 0, 0, errors.New("/proc/meminfo: no MemTotal")
	}
	a, ok := kb["MemAvailable"]
	if !ok { // kernels before 3.14
		a = kb["MemFree"] + kb["Buffers"] + kb["Cached"]
	}
	return t * 1024, min(a, t) * 1024, nil
}

// ParseNetDev returns the bytes sent by each interface of /proc/net/dev.
func ParseNetDev(r io.Reader) (map[string]uint64, error) {
	out := map[string]uint64{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		name, rest, ok := strings.Cut(s.Text(), ":")
		if !ok {
			continue // the two header lines
		}
		name = strings.TrimSpace(name)
		fields := strings.Fields(rest)
		if name == "" || len(fields) < 9 {
			return nil, fmt.Errorf("/proc/net/dev: malformed line for %q", name)
		}
		tx, err := strconv.ParseUint(fields[8], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("/proc/net/dev: %s tx bytes %q: %w", name, fields[8], err)
		}
		out[name] = tx
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// EgressBytes is the number of bytes sent between two samples by the
// interfaces in both that are not loopback; a counter that went back (an
// interface re-created) counts 0.
func EgressBytes(prev, cur map[string]uint64, loopback func(string) bool) uint64 {
	var sum uint64
	for name, c := range cur {
		p, ok := prev[name]
		if !ok || c < p || loopback(name) {
			continue
		}
		sum += c - p
	}
	return sum
}
