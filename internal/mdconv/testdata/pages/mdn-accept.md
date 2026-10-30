---
title: Accept header - HTTP | MDN
description: The HTTP Accept request and response header indicates which content types, expressed as MIME types, the sender is able to understand. In requests, the server uses content negotiation to select one of the proposals and informs the client of the choice with the Content-Type response header. In responses, it provides information about which content types the server can understand in messages to the requested resource, so that the content type can be used in subsequent requests to the resource.
image: https://developer.mozilla.org/mdn-social-image.46ac2375.png
---

# Accept header

Baseline

Widely available

This feature is well established and works across many devices and browser versions. It’s been available across browsers since July 2015.

- [See full compatibility](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#browser_compatibility)
- [Learn more](https://developer.mozilla.org/en-US/docs/Glossary/Baseline/Compatibility)

The HTTP **`Accept`** [request](https://developer.mozilla.org/en-US/docs/Glossary/Request_header) and [response header](https://developer.mozilla.org/en-US/docs/Glossary/Response_header) indicates which content types, expressed as [MIME types](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types), the sender is able to understand. In requests, the server uses [content negotiation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Content_negotiation) to select one of the proposals and informs the client of the choice with the [`Content-Type`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type) response header. In responses, it provides information about which content types the server can understand in messages to the requested resource, so that the content type can be used in subsequent requests to the resource.

Browsers set required values for this header based on the context of the request. For example, a browser uses different values in a request when fetching a CSS stylesheet, image, video, or a script.

| Header type                                                                                                        | [Request header](https://developer.mozilla.org/en-US/docs/Glossary/Request_header), [Response header](https://developer.mozilla.org/en-US/docs/Glossary/Response_header) |
|--------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| [Forbidden request header](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_request_header)             | No                                                                                                                                                                       |
| [CORS-safelisted request header](https://developer.mozilla.org/en-US/docs/Glossary/CORS-safelisted_request_header) | Yes*                                                                                                                                                                     |

\* Values can't contain [CORS-unsafe request header bytes](https://fetch.spec.whatwg.org/#cors-unsafe-request-header-byte "External link (opens in new tab)"), including `"():<>?@[\]{},`, Delete `0x7F`, and control characters `0x00` to `0x19`, except for Tab `0x09`.

## [Syntax](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#syntax)

http

```
Accept: <media-type>/<MIME_subtype>
Accept: <media-type>/*
Accept: */*

// Multiple types, weighted with the quality value syntax
Accept: text/html, application/xhtml+xml, application/xml;q=0.9, image/webp, */*;q=0.8
```

## [Directives](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#directives)

[`<media-type>/<subtype>`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#media-typesubtype)

A single, precise [media type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types), like `text/html`.

[`<media-type>/*`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#media-type)

A media type without a subtype. For example, `image/*` corresponds to `image/png`, `image/svg`, `image/gif`, and other image types.

[`*/*`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#sect)

Any media type.

[`;q=` (q-factor weighting)](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#q)

A value in order of preference expressed using a relative [quality value](https://developer.mozilla.org/en-US/docs/Glossary/Quality_values) called the *weight*.

## [Examples](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#examples)

### [Using default Accept request headers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#using_default_accept_request_headers)

HTTP requests made using command-line tools such as [curl](https://curl.se/ "External link (opens in new tab)") and [wget](https://www.gnu.org/software/wget/ "External link (opens in new tab)") use `*/*` as the default `Accept` value:

http

```
GET / HTTP/1.1
Host: example.com
User-Agent: curl/8.7.1
Accept: */*
```

Browser navigation typically has the following `Accept` request header value:

http

```
GET /en-US/ HTTP/2
Host: developer.mozilla.org
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
…
```

After receiving the document, the default `Accept` values in requests for images on the `developer.mozilla.org` example look like this:

http

```
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
```

### [Configuring Accept request headers for JSON responses](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#configuring_accept_request_headers_for_json_responses)

Systems that involve API interaction commonly request `application/json` responses. Here's an example of a [`GET`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/GET) request where the client specifically requests a JSON response:

http

```
GET /users/123 HTTP/1.1
Host: example.com
Authorization: Bearer abcd123
Accept: application/json
```

## [Specifications](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#specifications)

Specification 

[HTTP Semantics  
\# field.accept](https://httpwg.org/specs/rfc9110.html#field.accept)

## [Browser compatibility](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#browser_compatibility)

## [See also](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept#see_also)

- HTTP [content negotiation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Content_negotiation)
- [List of default Accept values](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Content_negotiation/List_of_default_Accept_values)
- [CORS safelist request header restrictions](https://developer.mozilla.org/en-US/docs/Glossary/CORS-safelisted_request_header#additional_restrictions)
- A header with the result of the content negotiation: [`Content-Type`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type)
- Other similar headers: [`TE`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/TE), [`Accept-Encoding`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-Encoding), [`Accept-Language`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept-Language)

## Help improve MDN

[Learn how to contribute](https://developer.mozilla.org/en-US/docs/MDN/Community/Getting_started)

This page was last modified on Sep 12, 2026 by [MDN contributors](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Accept/contributors.txt).

[View this page on GitHub](https://github.com/mdn/content/blob/main/files/en-us/web/http/reference/headers/accept/index.md?plain=1 "Folder: en-us/web/http/reference/headers/accept (Opens in a new tab)") • [Report a problem with this content](https://github.com/mdn/content/issues/new?template=page-report.yml&mdn-url=https%3A%2F%2Fdeveloper.mozilla.org%2Fen-US%2Fdocs%2FWeb%2FHTTP%2FReference%2FHeaders%2FAccept&metadata=%3C%21--%20Do%20not%20make%20changes%20below%20this%20line%20--%3E%0A%3Cdetails%3E%0A%3Csummary%3EPage%20report%20details%3C%2Fsummary%3E%0A%0A%2A%20Folder%3A%20%60en-us%2Fweb%2Fhttp%2Freference%2Fheaders%2Faccept%60%0A%2A%20MDN%20URL%3A%20https%3A%2F%2Fdeveloper.mozilla.org%2Fen-US%2Fdocs%2FWeb%2FHTTP%2FReference%2FHeaders%2FAccept%0A%2A%20GitHub%20URL%3A%20https%3A%2F%2Fgithub.com%2Fmdn%2Fcontent%2Fblob%2Fmain%2Ffiles%2Fen-us%2Fweb%2Fhttp%2Freference%2Fheaders%2Faccept%2Findex.md%0A%2A%20Last%20commit%3A%20https%3A%2F%2Fgithub.com%2Fmdn%2Fcontent%2Fcommit%2Fe3a2272d272f21ea38e5fff9bd6ccec2d0dfb1a8%0A%2A%20Document%20last%20modified%3A%202026-09-12T19%3A07%3A17.000Z%0A%0A%3C%2Fdetails%3E "This will take you to GitHub to file a new issue.")
