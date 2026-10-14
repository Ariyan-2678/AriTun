package server

import (
	"bytes"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// A multi tunnel serves every local port below one public URL space:
//
//	https://sub.example/20128/  ->  local http://127.0.0.1:20128/
//
// The app behind the tunnel is unaware of the "/20128" segment, so it keeps
// emitting root-relative links, redirects and asset URLs for "/". The helpers
// below rewrite those responses to carry the prefix, the way a sub-path
// reverse proxy has to.

// rewriteMultiResponse adapts one proxied response to the prefixed URL space.
// prefix is the bare port segment path ("/20128"), reqHost the Host the
// browser used. Header rewrites always run; the body is only rewritten when
// it is a text type we understand and is not left compressed.
func rewriteMultiResponse(resp *http.Response, prefix, reqHost string) {
	if resp == nil || resp.Header == nil || prefix == "" {
		return
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		if nv := mapURLValue(loc, prefix, reqHost); nv != loc {
			resp.Header.Set("Location", nv)
		}
	}

	if ref := resp.Header.Get("Refresh"); ref != "" {
		resp.Header.Set("Refresh", replaceValueRe(refreshURLRe, ref, func(v string) string {
			return mapURLValue(strings.TrimSpace(v), prefix, reqHost)
		}))
	}

	if cookies := resp.Header.Values("Set-Cookie"); len(cookies) > 0 {
		out := make([]string, len(cookies))
		for i, c := range cookies {
			out[i] = replaceValueRe(cookiePathRe, c, func(v string) string {
				if v == "/" {
					// Path=/ already covers the prefixed paths; leave it.
					return v
				}
				return mapURLValue(v, prefix, reqHost)
			})
		}
		resp.Header["Set-Cookie"] = out
	}

	rewriteMultiBody(resp, prefix, reqHost)
}

// rewriteMultiBody rewrites text bodies in place. Streaming and compressed
// bodies are left untouched: reading them would break SSE, video or any
// encoding the transport did not already decode.
func rewriteMultiBody(resp *http.Response, prefix, reqHost string) {
	if resp.Body == nil || resp.Body == http.NoBody {
		return
	}
	if !bodyAllowedForStatus(resp.StatusCode) {
		return
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return
	}
	rewrite := bodyRewriteFunc(resp.Header.Get("Content-Type"), prefix, reqHost)
	if rewrite == nil {
		return
	}

	// Cap what we buffer so a huge "text/html" response cannot blow up
	// memory. When the body does not fit, hand back the original stream.
	const maxRewriteBody = 8 << 20
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(resp.Body, maxRewriteBody+1))
	if err != nil || n > maxRewriteBody {
		resp.Body = &readCloser{
			Reader: io.MultiReader(bytes.NewReader(buf.Bytes()), resp.Body),
			Closer: resp.Body,
		}
		return
	}
	resp.Body.Close()

	newBody := rewrite(buf.String())
	resp.Body = io.NopCloser(strings.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Set("Content-Length", strconv.Itoa(len(newBody)))
}

// bodyRewriteFunc returns the transformer for a known text content type, or
// nil for everything else (json, media, event-stream, ...).
func bodyRewriteFunc(contentType, prefix, reqHost string) func(string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil
	}
	switch mt {
	case "text/html", "application/xhtml+xml":
		return func(s string) string { return rewriteHTML(s, prefix, reqHost) }
	case "text/css":
		return func(s string) string { return rewriteCSS(s, prefix, reqHost) }
	case "application/javascript", "text/javascript", "application/x-javascript",
		"text/jscript", "application/ecmascript", "text/ecmascript":
		return func(s string) string { return rewriteScript(s, prefix, reqHost) }
	}
	return nil
}

// mapURLValue moves one reference into the prefixed URL space. Values that
// point elsewhere (other hosts, protocol-relative URLs, data:, relative
// paths) come back unchanged, and a value already carrying the prefix is
// never prefixed twice.
func mapURLValue(v, prefix, reqHost string) string {
	if v == "" || prefix == "" {
		return v
	}
	if strings.HasPrefix(v, "//") {
		return v
	}
	if strings.HasPrefix(v, "/") {
		if v == prefix || strings.HasPrefix(v, prefix+"/") {
			return v
		}
		return prefix + v
	}
	if u, ok := absoluteHTTPURL(v); ok {
		if !sameHost(u.Host, reqHost) {
			return v
		}
		if u.Path == prefix || strings.HasPrefix(u.Path, prefix+"/") {
			return v
		}
		u.Path = prefix + u.Path
		return u.String()
	}
	return v
}

// absoluteHTTPURL reports whether v is an absolute http(s)/ws(s) URL.
func absoluteHTTPURL(v string) (*url.URL, bool) {
	i := strings.Index(v, "://")
	if i <= 0 {
		return nil, false
	}
	switch strings.ToLower(v[:i]) {
	case "http", "https", "ws", "wss":
	default:
		return nil, false
	}
	u, err := url.Parse(v)
	if err != nil {
		return nil, false
	}
	return u, true
}

func sameHost(a, b string) bool {
	ha, hb := hostOnly(a), hostOnly(b)
	return ha != "" && ha == hb
}

// hostOnly lowercases a host and drops its port and brackets, if any.
func hostOnly(h string) string {
	h = strings.ToLower(h)
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return strings.Trim(h, "[]")
}

// rewriteHTML prefixes every URL-bearing attribute, inline style, style
// block and script block in an HTML document.
func rewriteHTML(s, prefix, reqHost string) string {
	s = replaceValueRe(htmlAttrRe, s, func(v string) string {
		return mapURLValue(v, prefix, reqHost)
	})
	s = replaceValueRe(srcsetRe, s, func(v string) string {
		return rewriteSrcset(v, prefix, reqHost)
	})
	s = replaceValueRe(metaRefreshRe, s, func(v string) string {
		return mapURLValue(strings.TrimSpace(v), prefix, reqHost)
	})
	s = replaceValueRe(styleAttrDoubleRe, s, func(v string) string {
		return rewriteCSS(v, prefix, reqHost)
	})
	s = replaceValueRe(styleAttrSingleRe, s, func(v string) string {
		return rewriteCSS(v, prefix, reqHost)
	})
	s = replaceValueRe(styleTagRe, s, func(v string) string {
		return rewriteCSS(v, prefix, reqHost)
	})
	s = replaceValueRe(scriptTagRe, s, func(v string) string {
		return rewriteScript(v, prefix, reqHost)
	})
	return s
}

// rewriteSrcset prefixes each candidate URL of a srcset attribute value,
// keeping descriptors and whitespace intact.
func rewriteSrcset(v, prefix, reqHost string) string {
	parts := strings.Split(v, ",")
	for i, p := range parts {
		trimmed := strings.TrimLeft(p, " \t")
		if trimmed == "" {
			continue
		}
		rest := ""
		first := trimmed
		if j := strings.IndexAny(trimmed, " \t"); j >= 0 {
			first, rest = trimmed[:j], trimmed[j:]
		}
		if nv := mapURLValue(first, prefix, reqHost); nv != first {
			parts[i] = p[:len(p)-len(trimmed)] + nv + rest
		}
	}
	return strings.Join(parts, ",")
}

// rewriteCSS prefixes url(...) references and string-form @import rules.
func rewriteCSS(s, prefix, reqHost string) string {
	s = replaceValueRe(cssURLRe, s, func(v string) string {
		return mapURLValue(v, prefix, reqHost)
	})
	s = replaceValueRe(cssImportRe, s, func(v string) string {
		return mapURLValue(v, prefix, reqHost)
	})
	return s
}

// rewriteScript prefixes URL-shaped string literals in JS source. This is
// what keeps SPA routers and fetch() calls working below a path prefix.
func rewriteScript(s, prefix, reqHost string) string {
	s = replaceValueRe(jsAbsRe, s, func(v string) string {
		return mapURLValue(v, prefix, reqHost)
	})
	s = replaceValueRe(jsPathRe, s, func(v string) string {
		return mapURLValue(v, prefix, reqHost)
	})
	return s
}

// replaceValueRe rewrites the trailing capture group of every match, which by
// convention is the URL value sitting at the end of the pattern. Everything
// before it in the match is copied through untouched.
func replaceValueRe(re *regexp.Regexp, s string, fn func(string) string) string {
	matches := re.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, m := range matches {
		vi := len(m) - 2
		if m[vi] < 0 {
			b.WriteString(s[last:m[1]])
			last = m[1]
			continue
		}
		b.WriteString(s[last:m[vi]])
		b.WriteString(fn(s[m[vi]:m[vi+1]]))
		last = m[vi+1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// bodyAllowedForStatus mirrors net/http's unexported rule: 1xx, 204 and 304
// responses never carry a body.
func bodyAllowedForStatus(status int) bool {
	return !(status >= 100 && status <= 199 || status == 204 || status == 304)
}

// readCloser pairs a reader with the closer of the stream it was built from,
// so a body we read part of still releases the connection.
type readCloser struct {
	io.Reader
	io.Closer
}

// Patterns all end with the value group so replaceValueRe can use them.
var (
	// href="/x", src='/x', action="/x", ... Values starting with "/" are
	// root-relative; anything else is judged by mapURLValue.
	htmlAttrRe = regexp.MustCompile(`(?i)\b(?:href|src|action|formaction|poster|background|content|data-src|data-href)\s*=\s*['"]([^'"]*)`)

	// srcset="/a.png 1x, /b.png 2x"
	srcsetRe = regexp.MustCompile(`(?i)\bsrcset\s*=\s*['"]([^'"]*)`)

	// <meta http-equiv="refresh" content="0; url=/dashboard">
	metaRefreshRe = regexp.MustCompile(`(?i)\bcontent\s*=\s*['"]([^'"]*\burl\s*=\s*)([^'"]+)`)

	// style="background:url(/x)" — both quote forms, since CSS inside may
	// contain the opposite quote.
	styleAttrDoubleRe = regexp.MustCompile(`(?i)\bstyle\s*=\s*"([^"]*)"`)
	styleAttrSingleRe = regexp.MustCompile(`(?i)\bstyle\s*=\s*'([^']*)'`)

	styleTagRe  = regexp.MustCompile(`(?is)<style\b[^>]*>(.*?)</style>`)
	scriptTagRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)

	// Refresh: 0; url=/dashboard
	refreshURLRe = regexp.MustCompile(`(?i)\burl\s*=\s*([^;\r\n]+)`)

	// Path=/dashboard in a Set-Cookie header (semicolon-delimited, so a bare
	// "Path=/" ends the group immediately).
	cookiePathRe = regexp.MustCompile(`(?i)(;\s*path\s*=\s*)(/[^;\s]*)`)

	// url(/x) or url("/x") in CSS; the group ends before the closing paren
	// or quote, which stay in the source.
	cssURLRe    = regexp.MustCompile(`(?i)\burl\(\s*['"]?([^'")\s]+)`)
	cssImportRe = regexp.MustCompile(`(?i)@import\s+['"]([^'"]+)`)

	// "/api/x", '/x', `/x${y}` — a quoted string that starts with a single
	// slash. Protocol-relative "//" is rejected by mapURLValue.
	jsPathRe = regexp.MustCompile("[\"'`](/[^\"'`]*)")
	// "https://same-host/x" inside JS source.
	jsAbsRe = regexp.MustCompile("(?i)[\"'`](https?://[^\"'`]*)")
)
