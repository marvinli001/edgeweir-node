// Package mdconv converts HTML responses to Markdown for agents (Markdown
// for Agents, Site.markdown). The edge layer sends a request whose Accept
// names text/markdown to the agent's Markdown socket with
// X-Edgeweir-Markdown; Server passes it on to the origin layer it names and
// converts an HTML answer in a child process (edgeweir-node mdconv), or
// answers with what the origin layer sent when it cannot.
package mdconv

import (
	"errors"
	"strings"
)

// Header is the request header the edge layer sets on Markdown requests
// (lua/edgeweir/markdown.lua): "up=<origin layer upstream>".
const Header = "X-Edgeweir-Markdown"

// ConvertedHeader marks converted responses; it is cached with them and
// hidden from clients (the edge layer counts it,
// MinuteStats.markdown_responses).
const ConvertedHeader = "X-Edgeweir-Markdown-Converted"

// TokensHeader carries the converted document's estimated token count to
// clients, as Cloudflare's Markdown for Agents does.
const TokensHeader = "X-Markdown-Tokens"

// ContentSignal is the Content-Signal a converted response carries when the
// origin sent none (contentsignals.org; Cloudflare's default).
const ContentSignal = "ai-train=yes, search=yes, ai-input=yes"

// MaxInput is the largest HTML converted, after any gzip decoding (6 MiB,
// Cloudflare's limit).
const MaxInput = 6 << 20

var errHeader = errors.New("invalid " + Header)

// ParseHeader returns the origin layer named by "up=<upstream>".
func ParseHeader(v string) (string, error) {
	up, ok := strings.CutPrefix(v, "up=")
	if !ok || up == "" || strings.ContainsAny(up, "; \t") {
		return "", errHeader
	}
	return up, nil
}
