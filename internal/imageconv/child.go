package imageconv

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strconv"
)

// Exit codes of the child (edgeweir-node imgconv).
const (
	exitOK          = 0
	exitFailed      = 1
	exitUsage       = 2
	exitUnsupported = 3
)

// ChildCommand is the hidden subcommand that converts one image.
const ChildCommand = "imgconv"

// childArgs returns the child's arguments for one conversion.
func childArgs(kind Kind, format Format, quality int, info Info, memory, maxInput int64) []string {
	return []string{ChildCommand,
		"--kind", string(kind), "--format", string(format), "--quality", strconv.Itoa(quality),
		"--width", strconv.Itoa(info.Width), "--height", strconv.Itoa(info.Height),
		"--orientation", strconv.Itoa(info.Orientation),
		"--memory", strconv.FormatInt(memory, 10), "--max-input", strconv.FormatInt(maxInput, 10)}
}

// RunChild is the child process: it limits itself (address space for
// memory plus headroom, no files, a few descriptors, no capabilities),
// reads the image from stdin and writes the converted image to stdout.
// Exit status 3 means the image is not convertible.
func RunChild(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(ChildCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	kind := fs.String("kind", "", "source type: jpeg or png")
	format := fs.String("format", "", "output format: webp or avif")
	quality := fs.Int("quality", 0, "quality 1-100")
	width := fs.Int("width", 0, "width read from the headers")
	height := fs.Int("height", 0, "height read from the headers")
	orientation := fs.Int("orientation", 1, "EXIF orientation 1-8")
	memory := fs.Int64("memory", 0, "memory this conversion may use, in bytes")
	maxInput := fs.Int64("max-input", maxSize, "largest input in bytes")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	k, f := Kind(*kind), Format(*format)
	if (k != JPEG && k != PNG) || (f != WebP && f != AVIF) || *quality < 1 || *quality > 100 ||
		*width < 1 || *height < 1 || *memory < 1 || *maxInput < 1 || *maxInput > maxSize {
		fmt.Fprintln(stderr, "imgconv: invalid arguments")
		return exitUsage
	}
	if err := limitSelf(*memory); err != nil {
		fmt.Fprintln(stderr, "imgconv: limits:", err)
		return exitFailed
	}
	data, err := io.ReadAll(io.LimitReader(stdin, *maxInput+1))
	if err != nil {
		fmt.Fprintln(stderr, "imgconv: read:", err)
		return exitFailed
	}
	if int64(len(data)) > *maxInput {
		fmt.Fprintln(stderr, "imgconv: input too large")
		return exitUnsupported
	}
	out, err := Convert(data, k, f, *quality, Info{Width: *width, Height: *height, Orientation: *orientation})
	if err != nil {
		fmt.Fprintln(stderr, "imgconv:", err)
		if errors.Is(err, ErrUnsupported) {
			return exitUnsupported
		}
		return exitFailed
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "imgconv: write:", err)
		return exitFailed
	}
	return exitOK
}

// SelfExecutable is the binary conversions run: this process's own
// (/proc/self/exe on Linux, so a replaced binary on disk changes nothing
// until the agent restarts).
func SelfExecutable() string {
	if runtime.GOOS == "linux" {
		return "/proc/self/exe"
	}
	exe, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return exe
}

// SelfCommand returns Config.Command for exe: the child gets no
// environment but GOMAXPROCS=1 (one CPU per conversion; the agent's
// environment may hold secrets) and dies with the agent.
func SelfCommand(exe string) func(ctx context.Context, args []string) *exec.Cmd {
	return func(ctx context.Context, args []string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, exe, args...)
		cmd.Env = []string{"GOMAXPROCS=1"}
		childProcess(cmd)
		return cmd
	}
}
