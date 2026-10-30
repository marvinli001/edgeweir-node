package mdconv

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/JohannesKaufmann/html-to-markdown/v2/converter"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/base"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/commonmark"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/strikethrough"
	"github.com/JohannesKaufmann/html-to-markdown/v2/plugin/table"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
	"golang.org/x/net/html/charset"
)

// ErrEmpty is a document that converts to nothing (no metadata, no text,
// no JSON-LD): the HTML is kept.
var ErrEmpty = errors.New("the document converts to nothing")

// dropped are elements that are never content: scripts and styles (JSON-LD
// is read before), embedded objects and graphics, templates and form
// controls.
var dropped = map[atom.Atom]bool{
	atom.Script: true, atom.Style: true, atom.Noscript: true, atom.Template: true,
	atom.Link: true, atom.Meta: true, atom.Base: true, atom.Title: true,
	atom.Svg: true, atom.Canvas: true, atom.Iframe: true, atom.Frame: true, atom.Frameset: true,
	atom.Object: true, atom.Embed: true, atom.Audio: true, atom.Video: true, atom.Source: true, atom.Track: true,
	atom.Input: true, atom.Select: true, atom.Option: true, atom.Optgroup: true, atom.Textarea: true,
	atom.Button: true, atom.Label: true, atom.Datalist: true, atom.Dialog: true,
}

// droppedRoles are ARIA landmark roles of page chrome.
var droppedRoles = map[string]bool{"banner": true, "navigation": true, "contentinfo": true, "search": true, "complementary": true}

// sectioning are the elements inside which header, footer and aside belong
// to their section (an article's header holds its title) rather than to the
// page.
var sectioning = map[atom.Atom]bool{atom.Article: true, atom.Main: true, atom.Section: true, atom.Aside: true, atom.Nav: true}

// Convert returns the Markdown of an HTML document: YAML frontmatter from
// its meta tags (title, description, image), the main content as
// CommonMark with tables and strikethrough, and its JSON-LD in a fenced
// json block (the layout of Cloudflare's Markdown for Agents). contentType
// is the response's Content-Type (its charset, else the document's own
// declaration, else UTF-8); pageURL is the request's absolute URL, against
// which (or the document's <base>) links and images become absolute.
func Convert(src []byte, contentType, pageURL string) ([]byte, error) {
	if len(bytes.TrimSpace(src)) == 0 {
		return nil, ErrEmpty
	}
	r, err := charset.NewReader(bytes.NewReader(src), contentType)
	if err != nil {
		return nil, err
	}
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}
	meta := collect(doc)
	baseURL := resolveBase(pageURL, meta.base)
	root := contentRoot(doc)
	strip(root, sectioning[root.DataAtom])
	tidy(root)

	conv := converter.NewConverter(converter.WithPlugins(
		base.NewBasePlugin(),
		commonmark.NewCommonmarkPlugin(),
		table.NewTablePlugin(table.WithSkipEmptyRows(true)),
		strikethrough.NewStrikethroughPlugin(),
	))
	body, err := conv.ConvertNode(root, converter.WithDomain(baseURL))
	if err != nil {
		return nil, err
	}
	body = bytes.TrimSpace(body)

	var out bytes.Buffer
	front := [][2]string{
		{"title", first(meta.title, meta.ogTitle, meta.docTitle)},
		{"description", first(meta.description, meta.ogDescription)},
		{"image", absolute(baseURL, meta.ogImage)},
	}
	var fields []string
	for _, f := range front {
		if f[1] != "" {
			fields = append(fields, f[0]+": "+yamlScalar(f[1]))
		}
	}
	if len(fields) > 0 {
		out.WriteString("---\n")
		out.WriteString(strings.Join(fields, "\n"))
		out.WriteString("\n---\n\n")
	}
	if len(body) > 0 {
		out.Write(body)
		out.WriteString("\n")
	}
	if len(meta.jsonLD) > 0 {
		if len(body) > 0 {
			out.WriteString("\n")
		}
		out.WriteString("```json\n")
		out.WriteString(strings.Join(meta.jsonLD, "\n"))
		out.WriteString("\n```\n")
	}
	if out.Len() == 0 {
		return nil, ErrEmpty
	}
	return out.Bytes(), nil
}

// metadata is what the document's head and scripts say about it.
type metadata struct {
	title, ogTitle, docTitle   string
	description, ogDescription string
	ogImage                    string
	base                       string
	jsonLD                     []string
}

// collect reads the meta tags (the first of each), the document title, the
// first <base href> and the JSON-LD scripts (each compacted onto one line;
// invalid ones are skipped).
func collect(doc *html.Node) metadata {
	var m metadata
	baseSeen := false
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.DataAtom {
			case atom.Meta:
				content := clean(attr(n, "content"))
				switch name := strings.ToLower(strings.TrimSpace(attr(n, "name"))); name {
				case "title":
					m.title = first(m.title, content)
				case "description":
					m.description = first(m.description, content)
				}
				prop := strings.ToLower(strings.TrimSpace(attr(n, "property")))
				if prop == "" {
					// Some pages write Open Graph tags with name.
					prop = strings.ToLower(strings.TrimSpace(attr(n, "name")))
				}
				switch prop {
				case "og:title":
					m.ogTitle = first(m.ogTitle, content)
				case "og:description":
					m.ogDescription = first(m.ogDescription, content)
				case "og:image", "og:image:url", "og:image:secure_url":
					m.ogImage = first(m.ogImage, strings.TrimSpace(attr(n, "content")))
				}
			case atom.Title:
				if m.docTitle == "" && n.FirstChild != nil && !inside(n, atom.Svg) {
					m.docTitle = clean(text(n))
				}
			case atom.Base:
				if !baseSeen {
					if href, ok := attrOK(n, "href"); ok {
						m.base, baseSeen = strings.TrimSpace(href), true
					}
				}
			case atom.Script:
				if typ, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(attr(n, "type"))), ";"); strings.TrimSpace(typ) == "application/ld+json" {
					var buf bytes.Buffer
					if err := json.Compact(&buf, []byte(strings.TrimSpace(text(n)))); err == nil && buf.Len() > 0 {
						m.jsonLD = append(m.jsonLD, buf.String())
					}
				}
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return m
}

// contentRoot returns the element to convert: the document's only visible
// <main> (or role="main") when it has exactly one, else its <body>.
func contentRoot(doc *html.Node) *html.Node {
	var mains []*html.Node
	var body *html.Node
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			if n.DataAtom == atom.Body && body == nil {
				body = n
			}
			if hidden(n) || n.DataAtom == atom.Template {
				return
			}
			if n.DataAtom == atom.Main || strings.EqualFold(strings.TrimSpace(attr(n, "role")), "main") {
				mains = append(mains, n)
				return
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	if len(mains) == 1 {
		return mains[0]
	}
	if body != nil {
		return body
	}
	return doc
}

// strip removes what is not content below n: the dropped elements, hidden
// ones, comments, navigation, landmark roles of page chrome, and header,
// footer and aside outside any sectioning element (the page's banner, footer
// and sidebars; within an article they are its own). inSection reports
// whether n is inside a sectioning element.
func strip(n *html.Node, inSection bool) {
	for c := n.FirstChild; c != nil; {
		next := c.NextSibling
		if remove(c, inSection) {
			n.RemoveChild(c)
		} else if c.Type == html.ElementNode {
			strip(c, inSection || sectioning[c.DataAtom])
		}
		c = next
	}
}

func remove(n *html.Node, inSection bool) bool {
	switch n.Type {
	case html.CommentNode:
		return true
	case html.ElementNode:
	default:
		return false
	}
	if dropped[n.DataAtom] || hidden(n) || n.DataAtom == atom.Nav {
		return true
	}
	if droppedRoles[strings.ToLower(strings.TrimSpace(attr(n, "role")))] {
		return true
	}
	switch n.DataAtom {
	case atom.Header, atom.Footer, atom.Aside:
		return !inSection
	}
	return false
}

// tidy removes links without text or image (heading anchors, icon
// links whose icon was dropped) and list items that hold only a link with
// hreflang (language switchers), and ends every table cell with a space, so
// that the cells of a table Markdown cannot hold (lists or headings in
// cells) stay apart as text (the table plugin trims its cells).
func tidy(n *html.Node) {
	for c := n.FirstChild; c != nil; {
		next := c.NextSibling
		if c.Type == html.ElementNode {
			switch {
			case c.DataAtom == atom.A && strings.TrimSpace(text(c)) == "" && !contains(c, atom.Img):
				n.RemoveChild(c)
			case c.DataAtom == atom.Li && languageLink(c):
				n.RemoveChild(c)
			default:
				tidy(c)
				if c.DataAtom == atom.Td || c.DataAtom == atom.Th {
					c.AppendChild(&html.Node{Type: html.TextNode, Data: " "})
				}
			}
		}
		c = next
	}
}

// languageLink reports a list item whose only content is a link with
// hreflang.
func languageLink(li *html.Node) bool {
	var link *html.Node
	for c := li.FirstChild; c != nil; c = c.NextSibling {
		switch {
		case c.Type == html.TextNode && strings.TrimSpace(c.Data) == "":
		case c.Type == html.ElementNode && c.DataAtom == atom.A && link == nil:
			link = c
		default:
			return false
		}
	}
	if link == nil {
		return false
	}
	_, ok := attrOK(link, "hreflang")
	return ok
}

func contains(n *html.Node, a atom.Atom) bool {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && (c.DataAtom == a || contains(c, a)) {
			return true
		}
	}
	return false
}

// hidden reports an element its page never shows: the hidden attribute
// (except hidden="until-found"), aria-hidden="true" or an inline
// display:none.
func hidden(n *html.Node) bool {
	if v, ok := attrOK(n, "hidden"); ok && !strings.EqualFold(strings.TrimSpace(v), "until-found") {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(attr(n, "aria-hidden")), "true") {
		return true
	}
	style := strings.ToLower(attr(n, "style"))
	return strings.Contains(strings.ReplaceAll(style, " ", ""), "display:none")
}

// resolveBase returns the URL relative links resolve against: the
// document's <base href> resolved against the page's URL, or the page's.
func resolveBase(pageURL, baseHref string) string {
	page, err := url.Parse(pageURL)
	if err != nil {
		return pageURL
	}
	if baseHref == "" {
		return page.String()
	}
	ref, err := url.Parse(baseHref)
	if err != nil {
		return page.String()
	}
	resolved := page.ResolveReference(ref)
	if resolved.Scheme != "http" && resolved.Scheme != "https" {
		return page.String()
	}
	return resolved.String()
}

// absolute resolves ref against baseURL ("" stays "").
func absolute(baseURL, ref string) string {
	if ref == "" {
		return ""
	}
	b, err := url.Parse(baseURL)
	if err != nil {
		return ref
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

// yamlScalar returns s as a YAML scalar: plain when that reads back as
// the same string, else double-quoted (a JSON string is a valid YAML
// double-quoted scalar).
func yamlScalar(s string) string {
	if plainYAML(s) {
		return s
	}
	q, _ := json.Marshal(s)
	return string(q)
}

func plainYAML(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}
	if strings.ContainsRune("-?:,[]{}#&*!|>'\"%@`", rune(s[0])) {
		return false
	}
	if strings.Contains(s, ": ") || strings.Contains(s, " #") || strings.HasSuffix(s, ":") {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '\u2028' || r == '\u2029' || r == '\ufeff' {
			return false
		}
	}
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off", "null", "~", "y", "n":
		return false
	}
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return false
	}
	return true
}

// clean collapses whitespace runs to single spaces and trims.
func clean(s string) string {
	return strings.Join(strings.FieldsFunc(s, unicode.IsSpace), " ")
}

func first(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func attr(n *html.Node, key string) string {
	v, _ := attrOK(n, key)
	return v
}

func attrOK(n *html.Node, key string) (string, bool) {
	for _, a := range n.Attr {
		if a.Namespace == "" && a.Key == key {
			return a.Val, true
		}
	}
	return "", false
}

func text(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.TextNode {
			b.WriteString(n.Data)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(n)
	return b.String()
}

func inside(n *html.Node, a atom.Atom) bool {
	for p := n.Parent; p != nil; p = p.Parent {
		if p.Type == html.ElementNode && p.DataAtom == a {
			return true
		}
	}
	return false
}

// EstimateTokens returns a rough token count of Markdown (X-Markdown-
// Tokens): about four bytes per token for ASCII text and one token per
// character of other scripts (CJK and the like tokenize near one each).
func EstimateTokens(md []byte) int {
	ascii, other := 0, 0
	for len(md) > 0 {
		r, size := utf8.DecodeRune(md)
		md = md[size:]
		if r < utf8.RuneSelf {
			ascii++
		} else {
			other++
		}
	}
	return (ascii+3)/4 + other
}

// readAllLimited reads at most max bytes of r; more is errTooLarge. What
// was read comes back with any error.
func readAllLimited(r io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err == nil && int64(len(b)) > max {
		err = errTooLarge
	}
	return b, err
}

var errTooLarge = errors.New("larger than the conversion limit")
