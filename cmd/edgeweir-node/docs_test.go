package main

// Documentation-consistency checks for the wrap-up audit item N-M11
// (dev-docs/audits/2026-09-25-wrapup.md in the console checkout): the docs
// have to follow the code, so the lists they check are read from the code.

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// repoRoot is the repository root, seen from this package's directory.
const repoRoot = "../.."

func readDoc(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(repoRoot, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readmes(t *testing.T) []string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(repoRoot, "README*.md"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no README*.md: %v", err)
	}
	names := make([]string, len(paths))
	for i, p := range paths {
		names[i] = filepath.Base(p)
	}
	return names
}

var helpFlag = regexp.MustCompile(`(?m)^  -([a-z0-9][a-z0-9-]*)`)

// commandFlags returns the flags a command's flag set defines, from its -h output.
func commandFlags(t *testing.T, command string) []string {
	t.Helper()
	var out bytes.Buffer
	if code := realMain([]string{command, "-h"}, &out, &out); code != 0 {
		t.Fatalf("%s -h: exit %d: %s", command, code, out.String())
	}
	var names []string
	for _, m := range helpFlag.FindAllStringSubmatch(out.String(), -1) {
		names = append(names, m[1])
	}
	if !slices.Contains(names, "state-dir") {
		t.Fatalf("%s -h: found flags %v, want state-dir among them: did the help format change?", command, names)
	}
	return names
}

var tableFlag = regexp.MustCompile("^\\| `--([a-z0-9-]+)` \\|")

// flagTable returns the flags in the Markdown table whose header starts
// with "| `<command>` flag" (or "参数"), or nil when there is no such table.
func flagTable(text, command string) []string {
	header := regexp.MustCompile("^\\| `" + regexp.QuoteMeta(command) + "` (?:flag|参数) \\|")
	var names []string
	in := false
	for _, line := range strings.Split(text, "\n") {
		switch {
		case header.MatchString(line):
			in = true
		case in && strings.HasPrefix(line, "|"):
			if m := tableFlag.FindStringSubmatch(line); m != nil {
				names = append(names, m[1])
			}
		case in:
			return names
		}
	}
	return names
}

// N-M11: every flag of enroll, run and probe has a row in the README flag tables,
// and every row there is a flag the command still has.
func TestReadmeFlagTablesMatchFlagSets(t *testing.T) {
	for _, command := range []string{"enroll", "run", "probe"} {
		flags := commandFlags(t, command)
		for _, file := range readmes(t) {
			documented := flagTable(readDoc(t, file), command)
			if documented == nil {
				t.Errorf("%s: no `%s` flag table", file, command)
				continue
			}
			for _, name := range flags {
				if !slices.Contains(documented, name) {
					t.Errorf("%s: `%s` flag --%s is not documented", file, command, name)
				}
			}
			for _, name := range documented {
				if !slices.Contains(flags, name) {
					t.Errorf("%s: documents `%s --%s`, which does not exist", file, command, name)
				}
			}
		}
	}
}

// N-M11: the state files that hold secrets or purge state are documented
// together with their protection.
func TestDocsDescribeStateFileProtection(t *testing.T) {
	stateDir := regexp.MustCompile("`/var/lib/edgeweir-node`[^\\n]*0700")
	plainText := regexp.MustCompile(`(?i)plain ?text|明文`)
	for _, file := range append(readmes(t), "SECURITY.md") {
		text := readDoc(t, file)
		if !stateDir.MatchString(text) {
			t.Errorf("%s: the state directory is not documented with mode 0700", file)
		}
		for _, name := range []string{"credentials.json", "purge.json"} {
			mode := regexp.MustCompile("`" + regexp.QuoteMeta(name) + "`\\s*[（(][^）)\\n]*0600")
			if !mode.MatchString(text) {
				t.Errorf("%s: `%s` is not documented with mode 0600", file, name)
			}
		}
		saysPlainText := false
		for _, line := range strings.Split(text, "\n") {
			if strings.Contains(line, "`credentials.json`") && plainText.MatchString(line) {
				saysPlainText = true
			}
		}
		if !saysPlainText {
			t.Errorf("%s: does not say that credentials.json holds the S3 keys in plain text", file)
		}
	}
}

var (
	clauseEnd = regexp.MustCompile(`[。；;！？!?|\n]|\.\s`)
	ssh       = regexp.MustCompile(`\bSSH\b`)
	// Sentences about GoEdge describe its control plane, which did keep SSH credentials.
	aboutGoEdge  = regexp.MustCompile(`GoEdge|RingH23`)
	neverStoredZ = regexp.MustCompile(`(?:绝不|从不|不)(?:保存|存储|存|入库)[^。；，,]{0,6}SSH`)
	neverStoredE = regexp.MustCompile(`(?i)(?:\bnever|\bnot|n't)\s+(?:stores?|keeps?|saves?)\s+(?:any\s+)?(?:node\s+)?SSH\b|\bSSH credentials are never stored`)
	mayBeStored  = regexp.MustCompile(`(?i)加密|encrypt|默认|by default|可选|明确选择|optional|\bopt(?:s|ed)?[ -]?in\b|\bunless\b`)
	storeVerb    = regexp.MustCompile(`(?i)保存|存储|入库|存入|\bstor(?:e|es|ed|ing)\b|\bsav(?:e|es|ed|ing)\b`)
	negation     = regexp.MustCompile(`(?i)绝不|从不|不|没有|\bnever\b|\bnot\b|n't\b|\bno\b`)
)

// N-M11: SECURITY.md says the console never stores SSH credentials and has
// no clause saying they are, or may be, stored.
func TestSecurityNeverStoresSSHCredentials(t *testing.T) {
	text := readDoc(t, "SECURITY.md")
	says := false
	for _, clause := range clauseEnd.Split(text, -1) {
		if !ssh.MatchString(clause) || aboutGoEdge.MatchString(clause) {
			continue
		}
		if neverStoredZ.MatchString(clause) || neverStoredE.MatchString(clause) {
			says = true
		}
		if mayBeStored.MatchString(clause) {
			t.Errorf("SECURITY.md: SSH credentials may be stored: %q", clause)
		}
		for _, loc := range storeVerb.FindAllStringIndex(clause, -1) {
			before := []rune(clause[:loc[0]])
			before = before[max(0, len(before)-12):]
			if !negation.MatchString(string(before)) {
				t.Errorf("SECURITY.md: SSH credentials are stored (%q): %q", clause[loc[0]:loc[1]], clause)
			}
		}
	}
	if !says {
		t.Error("SECURITY.md does not say that SSH credentials are never stored")
	}
}

// N-M11: the docs name the proto tag the Makefile generates from.
func TestDocsNameTheMakefileProtoTag(t *testing.T) {
	m := regexp.MustCompile(`(?m)^PROTO_TAG\s*\??=\s*(\S+)`).FindStringSubmatch(readDoc(t, "Makefile"))
	if m == nil {
		t.Fatal("Makefile: no PROTO_TAG")
	}
	want := m[1]
	tag := regexp.MustCompile(`proto/v\d+\.\d+\.\d+`)
	files := append(readmes(t), "ARCHITECTURE.md")
	// CLAUDE.md is git-ignored: checked in checkouts that have it.
	if _, err := os.Stat(filepath.Join(repoRoot, "CLAUDE.md")); err == nil {
		files = append(files, "CLAUDE.md")
	}
	for _, file := range files {
		found := tag.FindAllString(readDoc(t, file), -1)
		if len(found) == 0 {
			t.Errorf("%s: names no proto tag", file)
		}
		for _, got := range found {
			if got != want {
				t.Errorf("%s: names %s, Makefile PROTO_TAG is %s", file, got, want)
			}
		}
	}
}
