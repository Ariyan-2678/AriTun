package server

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

const (
	testPrefix  = "/20128"
	testReqHost = "gentle-wolf-151.tunnel.p911net.ir"
)

func TestMapURLValue(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"root relative", "/dashboard", "/20128/dashboard"},
		{"root slash", "/", "/20128/"},
		{"already prefixed", "/20128/dashboard", "/20128/dashboard"},
		{"already prefixed deeper", "/20128/assets/x.png", "/20128/assets/x.png"},
		{"other prefixed path", "/20129/x", "/20128/20129/x"},
		{"protocol relative", "//cdn.example.com/x.js", "//cdn.example.com/x.js"},
		{"other host", "https://evil.example/x", "https://evil.example/x"},
		{"other host with path", "https://example.com/20128/x", "https://example.com/20128/x"},
		{"same host", "https://gentle-wolf-151.tunnel.p911net.ir/dashboard", "https://gentle-wolf-151.tunnel.p911net.ir/20128/dashboard"},
		{"same host with port", "https://gentle-wolf-151.tunnel.p911net.ir:443/x", "https://gentle-wolf-151.tunnel.p911net.ir:443/20128/x"},
		{"same host already prefixed", "https://gentle-wolf-151.tunnel.p911net.ir/20128/x", "https://gentle-wolf-151.tunnel.p911net.ir/20128/x"},
		{"relative untouched", "assets/x.png", "assets/x.png"},
		{"fragment untouched", "#top", "#top"},
		{"query only", "?q=1", "?q=1"},
		{"data uri", "data:image/png;base64,AAAA", "data:image/png;base64,AAAA"},
		{"javascript uri", "javascript:void(0)", "javascript:void(0)"},
		{"mailto", "mailto:a@b.c", "mailto:a@b.c"},
		{"ws same host", "ws://gentle-wolf-151.tunnel.p911net.ir/socket", "ws://gentle-wolf-151.tunnel.p911net.ir/20128/socket"},
		{"empty", "", ""},
	}
	for _, c := range cases {
		got := mapURLValue(c.in, testPrefix, testReqHost)
		if got != c.want {
			t.Errorf("%s: mapURLValue(%q) = %q, want %q", c.name, c.in, got, c.want)
		}
	}
}

func TestMapURLValueIdempotent(t *testing.T) {
	for _, in := range []string{"/dashboard", "/", "/x?y=1", "https://" + testReqHost + "/x"} {
		once := mapURLValue(in, testPrefix, testReqHost)
		twice := mapURLValue(once, testPrefix, testReqHost)
		if once != twice {
			t.Errorf("mapURLValue not idempotent for %q: %q -> %q", in, once, twice)
		}
	}
}

func TestRewriteHTML(t *testing.T) {
	in := strings.Join([]string{
		`<html><head>`,
		`<link rel="stylesheet" href="/style.css">`,
		`<script src="app.js"></script>`,
		`<meta http-equiv="refresh" content="0; url=/dashboard">`,
		`</head><body>`,
		`<a href="/about">about</a>`,
		`<a href="https://` + testReqHost + `/team">team</a>`,
		`<a href="https://other.example/x">other</a>`,
		`<a href="//cdn.example/x">cdn</a>`,
		`<a href="#top">top</a>`,
		`<img srcset="/a.png 1x, /b.png 2x" src="/c.png">`,
		`<form action='/submit'></form>`,
		`<div style="background:url(/bg.png)"></div>`,
		`<script>window.BASE = "/api"; fetch("/api/session");</script>`,
		`</body></html>`,
	}, "\n")

	want := strings.Join([]string{
		`<html><head>`,
		`<link rel="stylesheet" href="/20128/style.css">`,
		`<script src="app.js"></script>`,
		`<meta http-equiv="refresh" content="0; url=/20128/dashboard">`,
		`</head><body>`,
		`<a href="/20128/about">about</a>`,
		`<a href="https://` + testReqHost + `/20128/team">team</a>`,
		`<a href="https://other.example/x">other</a>`,
		`<a href="//cdn.example/x">cdn</a>`,
		`<a href="#top">top</a>`,
		`<img srcset="/20128/a.png 1x, /20128/b.png 2x" src="/20128/c.png">`,
		`<form action='/20128/submit'></form>`,
		`<div style="background:url(/20128/bg.png)"></div>`,
		`<script>window.BASE = "/20128/api"; fetch("/20128/api/session");</script>`,
		`</body></html>`,
	}, "\n")

	got := rewriteHTML(in, testPrefix, testReqHost)
	if got != want {
		t.Errorf("rewriteHTML mismatch:\n got: %s\nwant: %s", got, want)
	}
	if again := rewriteHTML(got, testPrefix, testReqHost); again != got {
		t.Errorf("rewriteHTML not idempotent:\n once: %s\ntwice: %s", got, again)
	}
}

func TestRewriteCSS(t *testing.T) {
	in := `body{background:url(/img/bg.png)} @import "/theme.css"; a{background:url("../x.png")} b{background:url(data:image/png;base64,AA)}`
	want := `body{background:url(/20128/img/bg.png)} @import "/20128/theme.css"; a{background:url("../x.png")} b{background:url(data:image/png;base64,AA)}`
	if got := rewriteCSS(in, testPrefix, testReqHost); got != want {
		t.Errorf("rewriteCSS = %q, want %q", got, want)
	}
}

func TestRewriteScript(t *testing.T) {
	in := `fetch("/api/x"); navigate('/'); const u = "https://` + testReqHost + `/me"; const c = "https://cdn.example/x"; const p = "//cdn.example/y"; split('/');`
	want := `fetch("/20128/api/x"); navigate('/20128/'); const u = "https://` + testReqHost + `/20128/me"; const c = "https://cdn.example/x"; const p = "//cdn.example/y"; split('/20128/');`
	if got := rewriteScript(in, testPrefix, testReqHost); got != want {
		t.Errorf("rewriteScript = %q, want %q", got, want)
	}
}

func TestRewriteMultiResponseHeaders(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Location", "/dashboard")
	resp.Header.Set("Refresh", "0; url=/home")
	resp.Header["Set-Cookie"] = []string{
		"sid=abc; Path=/app; HttpOnly",
		"flag=1; Path=/; Secure",
	}

	rewriteMultiResponse(resp, testPrefix, testReqHost)

	if got := resp.Header.Get("Location"); got != "/20128/dashboard" {
		t.Errorf("Location = %q, want %q", got, "/20128/dashboard")
	}
	if got := resp.Header.Get("Refresh"); got != "0; url=/20128/home" {
		t.Errorf("Refresh = %q, want %q", got, "0; url=/20128/home")
	}
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) != 2 {
		t.Fatalf("Set-Cookie count = %d, want 2", len(cookies))
	}
	if !strings.Contains(cookies[0], "Path=/20128/app") {
		t.Errorf("cookie 0 = %q, want Path=/20128/app", cookies[0])
	}
	if !strings.Contains(cookies[1], "Path=/;") {
		t.Errorf("cookie 1 = %q, want bare Path=/ kept", cookies[1])
	}
}

func TestRewriteMultiResponseCrossHostLocation(t *testing.T) {
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Location", "https://other.example/x")
	rewriteMultiResponse(resp, testPrefix, testReqHost)
	if got := resp.Header.Get("Location"); got != "https://other.example/x" {
		t.Errorf("cross-host Location rewritten to %q", got)
	}

	resp = &http.Response{Header: http.Header{}}
	resp.Header.Set("Location", "https://"+testReqHost+"/20128/x")
	rewriteMultiResponse(resp, testPrefix, testReqHost)
	if got := resp.Header.Get("Location"); got != "https://"+testReqHost+"/20128/x" {
		t.Errorf("already-prefixed absolute Location = %q", got)
	}
}

func TestRewriteMultiResponseHTMLBody(t *testing.T) {
	body := `<a href="/about">about</a><script src="/app.js"></script>`
	resp := &http.Response{
		StatusCode:    200,
		Header:        http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}

	rewriteMultiResponse(resp, testPrefix, testReqHost)

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	want := `<a href="/20128/about">about</a><script src="/20128/app.js"></script>`
	if string(got) != want {
		t.Errorf("body = %q, want %q", got, want)
	}
	if resp.ContentLength != int64(len(want)) {
		t.Errorf("ContentLength = %d, want %d", resp.ContentLength, len(want))
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(want)) {
		t.Errorf("Content-Length header = %q, want %q", cl, strconv.Itoa(len(want)))
	}
}

func TestRewriteMultiResponseSkipsOtherTypes(t *testing.T) {
	cases := []struct {
		name string
		hdr  http.Header
		body string
	}{
		{"json", http.Header{"Content-Type": {"application/json"}}, `{"path":"/x"}`},
		{"event stream", http.Header{"Content-Type": {"text/event-stream"}}, "data: /x\n\n"},
		{"no content type", http.Header{}, `<a href="/x">`},
		{"media", http.Header{"Content-Type": {"video/mp4"}, "Content-Encoding": {"gzip"}}, "binary"},
	}
	for _, c := range cases {
		resp := &http.Response{
			StatusCode: 200,
			Header:     c.hdr,
			Body:       io.NopCloser(strings.NewReader(c.body)),
		}
		rewriteMultiResponse(resp, testPrefix, testReqHost)
		got, _ := io.ReadAll(resp.Body)
		if string(got) != c.body {
			t.Errorf("%s: body rewritten to %q", c.name, got)
		}
	}
}

func TestRewriteMultiResponseCompressedHTMLSkipped(t *testing.T) {
	body := "<a href=\"/x\">compressed</a>"
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":     {"text/html"},
			"Content-Encoding": {"gzip"},
		},
		Body: io.NopCloser(strings.NewReader(body)),
	}
	rewriteMultiResponse(resp, testPrefix, testReqHost)
	got, _ := io.ReadAll(resp.Body)
	if string(got) != body {
		t.Errorf("compressed body rewritten to %q", got)
	}
	if ce := resp.Header.Get("Content-Encoding"); ce != "gzip" {
		t.Errorf("Content-Encoding = %q, want gzip kept", ce)
	}
}

func TestRewriteMultiResponseNoBodyStatuses(t *testing.T) {
	for _, status := range []int{204, 304} {
		resp := &http.Response{
			StatusCode: status,
			Header:     http.Header{"Content-Type": {"text/html"}},
			Body:       io.NopCloser(strings.NewReader("")),
		}
		rewriteMultiResponse(resp, testPrefix, testReqHost)
		if resp.Header.Get("Content-Length") != "" {
			t.Errorf("status %d: Content-Length set on bodyless response", status)
		}
	}
}
