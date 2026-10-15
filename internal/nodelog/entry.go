// Package nodelog collects the node's own warnings, errors and events for
// the console (feature node-logs-v1): the agent's and the supervisor's
// slog records through Handler, OpenResty's error log through ParseNginx.
// A Collector removes secrets, caps the size of each entry, folds repeated
// entries, limits the rate per source and keeps a bounded buffer that its
// owner drains (the agent) or serves (the supervisor, GET /logs).
package nodelog

import (
	"time"

	nodev1 "github.com/marvinli001/edgeweir-node/internal/gen/edgeweir/node/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Feature is the capability the agent reports while it uploads node logs.
const Feature = "node-logs-v1"

// Level of an entry.
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
)

// Source of an entry.
type Source string

const (
	SourceAgent      Source = "agent"
	SourceSupervisor Source = "supervisor"
	SourceNginx      Source = "nginx"
	SourceLua        Source = "lua"
)

// Events are the info records that become entries (slog attribute
// EventKey); other info records stay local.
const (
	EventAgentStarted          = "agent_started"
	EventConfigApplied         = "config_applied"
	EventLastKnownGood         = "last_known_good"
	EventEngineStarted         = "engine_started"
	EventCertificateRenewed    = "certificate_renewed"
	EventChannelSwitched       = "channel_switched"
	EventUpgradeApplied        = "upgrade_applied"
	EventEngineLogsUnavailable = "engine_logs_unavailable"
)

var events = map[string]bool{
	EventAgentStarted: true, EventConfigApplied: true, EventLastKnownGood: true,
	EventEngineStarted: true, EventCertificateRenewed: true, EventChannelSwitched: true,
	EventUpgradeApplied: true, EventEngineLogsUnavailable: true,
}

// IsEvent reports whether name is one of the events.
func IsEvent(name string) bool { return events[name] }

// Limits of one entry (the console checks the same).
const (
	MaxMessage    = 2048
	MaxFields     = 16
	MaxFieldKey   = 64
	MaxFieldValue = 512
)

// Entry is one warning, error or event.
type Entry struct {
	Time      time.Time         `json:"time"`
	Level     Level             `json:"level"`
	Source    Source            `json:"source"`
	Component string            `json:"component,omitempty"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
	Repeated  uint32            `json:"repeated,omitempty"`
	Truncated bool              `json:"truncated,omitempty"`
	Event     string            `json:"event,omitempty"`
}

var protoLevels = map[Level]nodev1.NodeLogLevel{
	LevelInfo:  nodev1.NodeLogLevel_NODE_LOG_LEVEL_INFO,
	LevelWarn:  nodev1.NodeLogLevel_NODE_LOG_LEVEL_WARN,
	LevelError: nodev1.NodeLogLevel_NODE_LOG_LEVEL_ERROR,
}

var protoSources = map[Source]nodev1.NodeLogSource{
	SourceAgent:      nodev1.NodeLogSource_NODE_LOG_SOURCE_AGENT,
	SourceSupervisor: nodev1.NodeLogSource_NODE_LOG_SOURCE_SUPERVISOR,
	SourceNginx:      nodev1.NodeLogSource_NODE_LOG_SOURCE_NGINX,
	SourceLua:        nodev1.NodeLogSource_NODE_LOG_SOURCE_LUA,
}

// Proto returns the entry as the node channel carries it.
func (e Entry) Proto() *nodev1.NodeLogEntry {
	return &nodev1.NodeLogEntry{
		Time:      timestamppb.New(e.Time),
		Level:     protoLevels[e.Level],
		Source:    protoSources[e.Source],
		Component: e.Component,
		Message:   e.Message,
		Fields:    e.Fields,
		Repeated:  e.Repeated,
		Truncated: e.Truncated,
		Event:     e.Event,
	}
}

// valid reports whether the entry has a known level and source, and an
// event exactly when it is an info entry.
func (e Entry) valid() bool {
	if _, ok := protoLevels[e.Level]; !ok {
		return false
	}
	if _, ok := protoSources[e.Source]; !ok {
		return false
	}
	if e.Level == LevelInfo {
		return IsEvent(e.Event)
	}
	return e.Event == ""
}
