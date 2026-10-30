package mdconv

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"unicode/utf8"

	"github.com/marvinli001/edgeweir-node/internal/sandbox"
)

// Exit codes of the child (edgeweir-node mdconv).
const (
	exitOK          = 0
	exitFailed      = 1
	exitUsage       = 2
	exitUnsupported = 3
)

// ChildCommand is the hidden subcommand that converts one document.
const ChildCommand = "mdconv"

// childArgs returns the child's arguments for one conversion.
func childArgs(pageURL, contentType string, memory, maxInput int64) []string {
	return []string{ChildCommand, "--url", pageURL, "--content-type", contentType,
		"--memory", strconv.FormatInt(memory, 10), "--max-input", strconv.FormatInt(maxInput, 10)}
}

// RunChild is the child process: it limits itself (sandbox.Limit), reads
// the HTML from stdin and writes its Markdown to stdout. Exit status 3
// means the document is not convertible (too large, or nothing to
// convert); nothing is written then.
func RunChild(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(ChildCommand, flag.ContinueOnError)
	fs.SetOutput(stderr)
	pageURL := fs.String("url", "", "the request's absolute URL (links resolve against it)")
	contentType := fs.String("content-type", "", "the response's Content-Type")
	memory := fs.Int64("memory", 0, "memory this conversion may use, in bytes")
	maxInput := fs.Int64("max-input", MaxInput, "largest input in bytes")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *pageURL == "" || *memory < 1 || *maxInput < 1 || *maxInput > MaxInput {
		fmt.Fprintln(stderr, "mdconv: invalid arguments")
		return exitUsage
	}
	if err := sandbox.Limit(*memory); err != nil {
		fmt.Fprintln(stderr, "mdconv: limits:", err)
		return exitFailed
	}
	data, err := readAllLimited(stdin, *maxInput)
	if errors.Is(err, errTooLarge) {
		fmt.Fprintln(stderr, "mdconv: input too large")
		return exitUnsupported
	}
	if err != nil {
		fmt.Fprintln(stderr, "mdconv: read:", err)
		return exitFailed
	}
	out, err := Convert(data, *contentType, *pageURL)
	if errors.Is(err, ErrEmpty) {
		fmt.Fprintln(stderr, "mdconv:", err)
		return exitUnsupported
	}
	if err != nil {
		fmt.Fprintln(stderr, "mdconv:", err)
		return exitFailed
	}
	if !utf8.Valid(out) {
		fmt.Fprintln(stderr, "mdconv: output is not UTF-8")
		return exitFailed
	}
	if _, err := stdout.Write(out); err != nil {
		fmt.Fprintln(stderr, "mdconv: write:", err)
		return exitFailed
	}
	return exitOK
}
