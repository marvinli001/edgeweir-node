# Golden pages

`pages/*.html` are inputs of `TestConvertGolden`, `pages/*.md` the expected
Markdown (`go test ./internal/mdconv -update` rewrites them; review the diff).
`pages.json` gives each page's URL and Content-Type.

Saved copies of public pages (2026-10-30), kept under their licenses:

| File | Source | License |
| --- | --- | --- |
| `wikipedia-en.html` | https://en.wikipedia.org/wiki/Markdown | CC BY-SA 4.0, Wikipedia contributors |
| `wikipedia-zh.html` | https://zh.wikipedia.org/zh-cn/Markdown | CC BY-SA 4.0, 维基百科贡献者 |
| `mdn-accept.html` | https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept | CC BY-SA 2.5, Mozilla Contributors |
| `cloudflare-docs.html` | https://developers.cloudflare.com/fundamentals/reference/markdown-for-agents/ | CC BY 4.0, Cloudflare, Inc. |
| `go-tutorial.html` | https://go.dev/doc/tutorial/getting-started | CC BY 4.0, The Go Authors |
| `python-json.html` | https://docs.python.org/3/library/json.html | PSF License, Python Software Foundation |

`edge-cases.html` and `gbk.html` (GBK-encoded) are written for these tests.
