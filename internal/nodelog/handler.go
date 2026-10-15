package nodelog

import (
	"context"
	"log/slog"
	"time"
)

// EventKey is the slog attribute that makes an info record an entry (one
// of the events).
const EventKey = "event"

// skipKey marks records that stay local: the node log upload's own
// messages, and OpenResty's lines (ParseNginx turns them into entries).
const skipKey = "nodelog.skip"

// Skip is the attribute (logger.With(nodelog.Skip)) of records that never
// become entries. The handler removes it before the records go on.
var Skip = slog.Bool(skipKey, true)

// Handler passes every record to its base handler and adds warnings,
// errors and events of the process to a collector. Its level is that of
// the base handler for local output; warnings and events become entries
// whatever it is.
type Handler struct {
	base   slog.Handler
	add    func(Entry)
	source Source
	fields []field
	prefix string
	skip   bool
}

type field struct{ key, value string }

// NewHandler returns a handler that passes records to base and the
// process's entries (source) to add.
func NewHandler(base slog.Handler, add func(Entry), source Source) *Handler {
	return &Handler{base: base, add: add, source: source}
}

// Enabled reports whether records of level are handled: by the base
// handler, or as entries (info records may carry an event).
func (h *Handler) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo || h.base.Enabled(ctx, level)
}

// Handle passes r on and adds it as an entry when it is one.
func (h *Handler) Handle(ctx context.Context, r slog.Record) error {
	skip := h.skip
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == skipKey {
			skip = true
			return false
		}
		return true
	})
	var err error
	if h.base.Enabled(ctx, r.Level) {
		local := r
		if skip && !h.skip {
			// Without the marker (only the handler reads it).
			local = slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
			r.Attrs(func(a slog.Attr) bool {
				if a.Key != skipKey {
					local.AddAttrs(a)
				}
				return true
			})
		}
		err = h.base.Handle(ctx, local)
	}
	if skip || h.add == nil || r.Level < slog.LevelInfo {
		return err
	}
	e := Entry{Time: r.Time, Level: LevelInfo, Source: h.source, Message: r.Message}
	switch {
	case r.Level >= slog.LevelError:
		e.Level = LevelError
	case r.Level >= slog.LevelWarn:
		e.Level = LevelWarn
	}
	fields := make(map[string]string, len(h.fields)+r.NumAttrs())
	take := func(f field) {
		switch f.key {
		case "component":
			e.Component = f.value
		case EventKey:
			e.Event = f.value
		default:
			fields[f.key] = f.value
		}
	}
	for _, f := range h.fields {
		take(f)
	}
	r.Attrs(func(a slog.Attr) bool {
		for _, f := range flatten(h.prefix, a, nil) {
			take(f)
		}
		return true
	})
	// Only the events of info records; warnings and errors carry none.
	if e.Level == LevelInfo {
		if !IsEvent(e.Event) {
			return err
		}
	} else {
		e.Event = ""
	}
	e.Fields = fields
	h.add(e)
	return err
}

// WithAttrs returns a handler with attrs added to every record.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.fields = append([]field(nil), h.fields...)
	kept := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		if a.Key == skipKey {
			next.skip = true
			continue
		}
		kept = append(kept, a)
		next.fields = flatten(h.prefix, a, next.fields)
	}
	next.base = h.base.WithAttrs(kept)
	return &next
}

// WithGroup returns a handler that puts later attributes into group name.
func (h *Handler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	next := *h
	next.prefix = h.prefix + name + "."
	next.base = h.base.WithGroup(name)
	return &next
}

// flatten appends the fields of a (groups as dotted keys) to out.
func flatten(prefix string, a slog.Attr, out []field) []field {
	v := a.Value.Resolve()
	if v.Kind() == slog.KindGroup {
		p := prefix
		if a.Key != "" {
			p += a.Key + "."
		}
		for _, g := range v.Group() {
			out = flatten(p, g, out)
		}
		return out
	}
	if a.Key == "" {
		return out
	}
	var s string
	switch v.Kind() {
	case slog.KindTime:
		s = v.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindAny:
		if e, ok := v.Any().(error); ok {
			s = e.Error()
		} else {
			s = v.String()
		}
	default:
		s = v.String()
	}
	return append(out, field{prefix + a.Key, s})
}
