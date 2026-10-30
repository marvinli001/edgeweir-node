package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/marvinli001/edgeweir-node/internal/mdconv"
	"github.com/marvinli001/edgeweir-node/internal/sandbox"
)

// MarkdownOptions configure the Markdown converter (Markdown for Agents).
type MarkdownOptions struct {
	// Workers bounds concurrent conversions (0: no converter).
	Workers int
	// Memory bounds the sum of the running conversions' estimates.
	Memory int64
	// Timeout bounds one conversion.
	Timeout time.Duration
	// Executable runs the conversions (ChildCommand); default this
	// process's binary.
	Executable string
}

// serveMarkdownSocket serves the Markdown converter on the Markdown socket
// (upstream edgeweir_markdown). Like the image socket it belongs to
// nginx's user; only it and root can connect.
func (a *Agent) serveMarkdownSocket(ctx context.Context, spawn func(string, func(context.Context))) error {
	opts := a.cfg.Markdown
	params := a.cfg.Render.WithDefaults()
	path := params.MarkdownSocket
	if opts.Workers <= 0 || path == "" {
		return nil
	}
	exe := opts.Executable
	if exe == "" {
		exe = sandbox.SelfExecutable()
	}
	if st, err := os.Lstat(path); err == nil {
		if st.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("markdown socket %s is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("markdown socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return err
	}
	if err := chownToUser(a.cfg.Render.User, path); err != nil {
		l.Close()
		return err
	}
	converter := mdconv.New(mdconv.Config{
		Upstreams: params.OriginLayerSocketsByName(),
		Workers:   opts.Workers,
		Memory:    opts.Memory,
		Timeout:   opts.Timeout,
		Command:   sandbox.SelfCommand(exe),
		Log:       a.log.With("component", "mdconv"),
	})
	// No write timeout: answers that are not converted stream as long as
	// the origin layer sends (the edge bounds the hop).
	server := &http.Server{Handler: converter, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 10 * time.Second,
		MaxHeaderBytes: 64 << 10}
	spawn("mdconv", func(ctx context.Context) {
		go func() { <-ctx.Done(); _ = server.Close(); converter.Close() }()
		if err := server.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			a.log.Error("Markdown socket stopped", "err", err)
		}
	})
	return nil
}
