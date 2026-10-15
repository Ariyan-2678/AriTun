package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// ---- ACL ----

func TestParseOneCIDR(t *testing.T) {
	cases := []struct {
		in      string
		wantErr bool
	}{
		{"10.0.0.0/8", false},
		{"192.168.1.0/24", false},
		{"203.0.113.5", false}, // bare IP -> /32
		{"::1/128", false},
		{"2001:db8::/32", false},
		{"", true},
		{"not-an-ip", true},
		{"10.0.0.0/33", true},
		{"999.1.1.1", true},
	}
	for _, c := range cases {
		_, err := parseOneCIDR(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("parseOneCIDR(%q) err=%v, wantErr=%v", c.in, err, c.wantErr)
		}
	}
}

func TestParseCIDRSkipsBlanks(t *testing.T) {
	got, err := parseCIDRs([]string{"10.0.0.0/8", "", "  ", "192.168.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d prefixes, want 2", len(got))
	}
}

func TestCheckACL(t *testing.T) {
	allow, _ := parseCIDRs([]string{"10.0.0.0/8", "192.168.1.5"})
	deny, _ := parseCIDRs([]string{"10.1.0.0/16"})

	mustAddr := func(s string) netip.Addr {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}

	cases := []struct {
		ip    string
		allow bool
	}{
		{"10.2.0.1", true},     // in allow, not in deny
		{"10.1.0.1", false},    // in deny (wins)
		{"192.168.1.5", true},  // bare IP in allow
		{"192.168.1.6", false}, // not in allow
		{"8.8.8.8", false},     // not in allow
	}
	for _, c := range cases {
		if got := checkACL(mustAddr(c.ip), allow, deny); got != c.allow {
			t.Errorf("checkACL(%s, allow, deny) = %v, want %v", c.ip, got, c.allow)
		}
	}

	// Empty allow list: everyone except deny.
	emptyAllow := []netip.Prefix(nil)
	if !checkACL(mustAddr("8.8.8.8"), emptyAllow, deny) {
		t.Error("empty allow should permit non-denied IPs")
	}
	if checkACL(mustAddr("10.1.0.1"), emptyAllow, deny) {
		t.Error("deny should still reject with empty allow")
	}
}

func TestVisitorIP(t *testing.T) {
	cases := []struct {
		xff, remote, want string
	}{
		{"203.0.113.9", "10.0.0.1:1234", "203.0.113.9"},
		{"203.0.113.9, 10.0.0.2", "10.0.0.1:1234", "203.0.113.9"}, // first hop
		{"", "10.0.0.1:1234", "10.0.0.1"},
		{"garbage", "10.0.0.1:1234", "10.0.0.1"}, // fall back to remote
	}
	for _, c := range cases {
		got := visitorIP(c.xff, c.remote)
		if got.String() != c.want {
			t.Errorf("visitorIP(%q, %q) = %s, want %s", c.xff, c.remote, got, c.want)
		}
	}
}

// ---- rate limiter ----

func TestRateLimiterUnlimited(t *testing.T) {
	if newRateLimiter(0) != nil {
		t.Error("rate 0 should produce a nil (unlimited) limiter")
	}
	var nilLimiter *rateLimiter
	if !nilLimiter.allow() {
		t.Error("nil limiter must allow")
	}
}

func TestRateLimiterBurstThenRefill(t *testing.T) {
	r := newRateLimiter(5) // 5 rps, burst 5
	for i := 0; i < 5; i++ {
		if !r.allow() {
			t.Fatalf("request %d should be allowed within burst", i)
		}
	}
	if r.allow() {
		t.Fatal("6th immediate request should be rejected")
	}
	// Wait for refill.
	time.Sleep(250 * time.Millisecond) // ~1.25 tokens
	if !r.allow() {
		t.Error("should allow after refill")
	}
}

// ---- bandwidth limiter ----

func TestBandwidthLimiterUnlimited(t *testing.T) {
	if newBandwidthLimiter(0) != nil {
		t.Error("bandwidth 0 should produce a nil limiter")
	}
	var b *bandwidthLimiter
	if err := b.wait(context.Background(), 1<<20); err != nil {
		t.Errorf("nil limiter wait should be nil, got %v", err)
	}
}

func TestBandwidthLimiterWait(t *testing.T) {
	b := newBandwidthLimiter(1024) // 1 KiB/s
	start := time.Now()
	// Ask for ~1 second worth of budget immediately: burst is 1024, so the
	// first 1024 bytes go through instantly.
	if err := b.wait(context.Background(), 1024); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("burst should be instant, took %v", elapsed)
	}
	// A second chunk needs to wait for refill.
	start = time.Now()
	if err := b.wait(context.Background(), 1024); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
		t.Errorf("second chunk should have waited for refill, took %v", elapsed)
	}
}

func TestBandwidthLimiterContextCancel(t *testing.T) {
	b := newBandwidthLimiter(1)         // 1 byte/s — very slow
	_ = b.wait(context.Background(), 1) // drain the burst
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := b.wait(ctx, 100); err == nil {
		t.Error("expected context deadline error")
	}
}

// ---- token store ----

func TestTokenStoreAddLookupRemove(t *testing.T) {
	ts := newTokenStore("") // in-memory only
	secret, err := ts.Add("ci", []string{PermHTTP})
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) < 32 {
		t.Errorf("secret too short: %s", secret)
	}

	rec := ts.lookup(secret)
	if rec == nil || rec.Name != "ci" {
		t.Fatalf("lookup failed: %+v", rec)
	}

	info := &TokenInfo{Name: rec.Name, Permissions: rec.Permissions}
	if !info.Has(PermHTTP) {
		t.Error("ci token should have http")
	}
	if info.Has(PermTCP) {
		t.Error("ci token should not have tcp")
	}

	if !ts.Remove(secret) {
		t.Error("remove should succeed")
	}
	if ts.lookup(secret) != nil {
		t.Error("token should be gone after remove")
	}
}

func TestTokenStorePermissionValidation(t *testing.T) {
	ts := newTokenStore("")
	if _, err := ts.Add("bad", []string{"ftp"}); err == nil {
		t.Error("unknown permission should be rejected")
	}
	if _, err := ts.Add("", []string{PermHTTP}); err == nil {
		t.Error("empty name should be rejected")
	}
	if _, err := ts.Add("x", nil); err == nil {
		t.Error("empty permissions should be rejected")
	}
}

func TestTokenInfoNilAllowsEverything(t *testing.T) {
	var info *TokenInfo
	if !info.Has(PermHTTP) || !info.Has(PermTCP) || !info.Has(PermMulti) {
		t.Error("nil TokenInfo (dev mode) should allow every type")
	}
}

func TestRootTokenHasAllPerms(t *testing.T) {
	info := &TokenInfo{Name: "root", Permissions: allPerms}
	for _, p := range []string{PermHTTP, PermTCP, PermMulti} {
		if !info.Has(p) {
			t.Errorf("root should have %s", p)
		}
	}
}

func TestWildcardPerm(t *testing.T) {
	info := &TokenInfo{Name: "w", Permissions: []string{"*"}}
	if !info.Has(PermHTTP) || !info.Has(PermTCP) {
		t.Error("* should allow everything")
	}
}

func TestMaskToken(t *testing.T) {
	if got := maskToken("short"); got != "****" {
		t.Errorf("maskToken(short) = %s", got)
	}
	long := "0123456789abcdef0123456789abcdef"
	got := maskToken(long)
	if got != "0123…cdef" {
		t.Errorf("maskToken(long) = %s", got)
	}
}

// ---- inspector ----

func TestInspectorRing(t *testing.T) {
	in := newInspector(3)
	for i := 0; i < 5; i++ {
		in.record(RequestLog{Time: time.Now(), Method: "GET", URL: string(rune('a' + i))})
	}
	recent := in.Recent(0)
	if len(recent) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(recent))
	}
	// The last three recorded: c, d, e (indices 2,3,4).
	if recent[0].URL != "c" || recent[1].URL != "d" || recent[2].URL != "e" {
		t.Errorf("unexpected order: %+v", recent)
	}
	if in.total.Load() != 5 {
		t.Errorf("total = %d, want 5", in.total.Load())
	}
}

func TestInspectorRecentLimit(t *testing.T) {
	in := newInspector(10)
	for i := 0; i < 5; i++ {
		in.record(RequestLog{Time: time.Now()})
	}
	if got := len(in.Recent(2)); got != 2 {
		t.Errorf("Recent(2) = %d entries, want 2", got)
	}
}

// ---- countingWriter ----

func TestCountingWriterCapturesStatusAndBytes(t *testing.T) {
	rec := &noopResponseWriter{}
	cw := &countingWriter{ResponseWriter: rec}
	cw.WriteHeader(httpStatusTeapot)
	cw.Write([]byte("hello"))
	if statusOf(cw) != httpStatusTeapot {
		t.Errorf("status = %d", statusOf(cw))
	}
	if cw.bytes != 5 {
		t.Errorf("bytes = %d, want 5", cw.bytes)
	}
}

// httpStatusTeapot avoids importing net/http just for a constant in the test.
const httpStatusTeapot = 418

// noopResponseWriter is a minimal http.ResponseWriter for tests.
type noopResponseWriter struct {
	header http.Header
	code   int
	body   []byte
}

func (w *noopResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}
func (w *noopResponseWriter) Write(p []byte) (int, error) {
	w.body = append(w.body, p...)
	return len(p), nil
}
func (w *noopResponseWriter) WriteHeader(code int) { w.code = code }

// ---- header capture / redaction ----

func TestCaptureHeadersRedactsSecrets(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer abc")
	h.Set("X-Api-Key", "abc")
	h.Set("Cookie", "a=1")
	h.Set("Set-Cookie", "a=1")
	h.Set("Content-Type", "application/json")
	h.Set("X-Long", strings.Repeat("z", headerValueCap+10))

	got := captureHeaders(h)
	for _, k := range []string{"Authorization", "X-Api-Key", "Cookie", "Set-Cookie"} {
		if got[k] != redactedHeader {
			t.Errorf("%s = %q, want %q", k, got[k], redactedHeader)
		}
	}
	if got["Content-Type"] != "application/json" {
		t.Errorf("Content-Type = %q", got["Content-Type"])
	}
	if len(got["X-Long"]) > headerValueCap+len("…") {
		t.Errorf("oversized header value not bounded: %d bytes", len(got["X-Long"]))
	}
	if captureHeaders(nil) != nil {
		t.Error("empty header map should stay nil so the JSON payload stays compact")
	}
}

func TestIsTextualContentType(t *testing.T) {
	textual := []string{
		"text/html", "TEXT/PLAIN; charset=utf-8", "application/json",
		"application/xml; charset=utf-8", "application/javascript",
		"application/ld+json", "application/vnd.api+json",
	}
	binary := []string{"image/png", "application/octet-stream", "video/mp4",
		"application/pdf", "font/woff2", ""}
	for _, ct := range textual {
		if !isTextualContentType(ct) {
			t.Errorf("isTextualContentType(%q) = false, want true", ct)
		}
	}
	for _, ct := range binary {
		if isTextualContentType(ct) {
			t.Errorf("isTextualContentType(%q) = true, want false", ct)
		}
	}
}

// ---- copy-as-curl ----

func TestBuildCurlRedactsSecrets(t *testing.T) {
	headers := captureHeaders(http.Header{
		"Authorization": []string{"Bearer super-secret"},
		"Accept":        []string{"application/json"},
		"X-Api-Key":     []string{"k123"},
		"Cookie":        []string{"session=abc"},
		"Host":          []string{"ignored.example.com"},
	})
	got := buildCurl("POST", "https://tunnel.example.com/api?x=1", headers, `{"a":1}`)
	want := "curl -X POST 'https://tunnel.example.com/api?x=1'" +
		" -H 'Accept: application/json'" +
		" -H 'Authorization: [redacted]'" +
		" -H 'Cookie: [redacted]'" +
		" -H 'X-Api-Key: [redacted]'" +
		" -d '{\"a\":1}'"
	if got != want {
		t.Errorf("buildCurl =\n  %s\nwant\n  %s", got, want)
	}
	for _, secret := range []string{"super-secret", "k123", "session=abc", "ignored.example.com"} {
		if strings.Contains(got, secret) {
			t.Errorf("curl command leaks %q: %s", secret, got)
		}
	}
}

func TestShellQuoteEscapesSingleQuote(t *testing.T) {
	if got := shellQuote("it's"); got != `'it'\''s'` {
		t.Errorf("shellQuote = %s", got)
	}
	if got := shellQuote(""); got != "''" {
		t.Errorf("shellQuote(\"\") = %s", got)
	}
}

func TestCurlURLReconstructsSchemeAndHost(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://demo.aritun.test/a?x=1", nil)
	if got := curlURL(r); got != "http://demo.aritun.test/a?x=1" {
		t.Errorf("curlURL = %s", got)
	}
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := curlURL(r); got != "https://demo.aritun.test/a?x=1" {
		t.Errorf("curlURL with X-Forwarded-Proto = %s", got)
	}
	r.Header.Set("X-Forwarded-Proto", "https, http")
	if got := curlURL(r); got != "https://demo.aritun.test/a?x=1" {
		t.Errorf("curlURL with a proxy list = %s", got)
	}
}

// ---- response body preview ----

func TestCountingWriterBodyPreviewCap(t *testing.T) {
	rec := &noopResponseWriter{}
	cw := &countingWriter{ResponseWriter: rec}
	cw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	payload := bytes.Repeat([]byte("x"), bodyPreviewCap*3)
	if _, err := cw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if got := len(cw.bodyPreview()); got != bodyPreviewCap {
		t.Errorf("preview = %d bytes, want %d", got, bodyPreviewCap)
	}
	if got := len(rec.body); got != len(payload) {
		t.Errorf("wrote %d of %d bytes through — the cap must not buffer the stream", got, len(payload))
	}
	if cw.bytes != int64(len(payload)) {
		t.Errorf("bytes = %d, want %d", cw.bytes, len(payload))
	}
	// Chunks after the cap pass through without extending the preview.
	if _, err := cw.Write([]byte("tail")); err != nil {
		t.Fatal(err)
	}
	if got := len(cw.bodyPreview()); got != bodyPreviewCap {
		t.Errorf("preview grew to %d after the cap", got)
	}
	if got := len(rec.body); got != len(payload)+4 {
		t.Errorf("tail not written through: %d bytes", got)
	}
}

func TestCountingWriterSkipsBinaryBodyPreview(t *testing.T) {
	rec := &noopResponseWriter{}
	cw := &countingWriter{ResponseWriter: rec}
	cw.Header().Set("Content-Type", "image/png")
	if _, err := cw.Write([]byte{0x89, 'P', 'N', 'G', 0x0d}); err != nil {
		t.Fatal(err)
	}
	if got := cw.bodyPreview(); got != "" {
		t.Errorf("binary preview = %q, want empty", got)
	}
	if len(rec.body) != 5 {
		t.Errorf("binary bytes must still pass through, got %d", len(rec.body))
	}
	if got := cw.responseHeaders(); got["Content-Type"] != "image/png" {
		t.Errorf("response headers = %v", got)
	}
}

func TestCountingWriterSniffsUnlabelledText(t *testing.T) {
	rec := &noopResponseWriter{}
	cw := &countingWriter{ResponseWriter: rec}
	if _, err := cw.Write([]byte("<html><body>hi</body></html>")); err != nil {
		t.Fatal(err)
	}
	if cw.bodyPreview() == "" {
		t.Error("text body without a Content-Type should still be previewed")
	}
}

// ---- recordRequest ----

func TestRecordRequestKeepsOldFieldsAndAddsDetail(t *testing.T) {
	s := &Server{insp: newInspector(4)}
	tun := &Tunnel{Session: &Session{name: "laptop"}}
	tun.ID = "t_abc123"
	tun.Subdomain = "demo"
	r := httptest.NewRequest(http.MethodPost, "http://demo.test/hello", strings.NewReader(`{"a":1}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer super-secret")
	r = CaptureBody(r)
	if _, err := io.ReadAll(r.Body); err != nil {
		t.Fatal(err) // the proxy draining the body must see every byte
	}

	rec := &noopResponseWriter{}
	cw := &countingWriter{ResponseWriter: rec}
	cw.Header().Set("Content-Type", "application/json")
	cw.WriteHeader(http.StatusCreated)
	if _, err := cw.Write([]byte(`{"ok":true}`)); err != nil {
		t.Fatal(err)
	}

	s.recordRequest(tun, r, cw, time.Now())

	logs := s.insp.Recent(0)
	if len(logs) != 1 {
		t.Fatalf("recorded %d entries, want 1", len(logs))
	}
	l := logs[0]
	// The fields server.go already populated must survive the swap.
	if l.Method != http.MethodPost || l.URL != "/hello" || l.Status != http.StatusCreated {
		t.Errorf("core fields wrong: %+v", l)
	}
	if l.Bytes != int64(len(`{"ok":true}`)) {
		t.Errorf("bytes = %d", l.Bytes)
	}
	if l.TunnelID != "t_abc123" || l.Client != "laptop" || l.RemoteIP != "192.0.2.1" {
		t.Errorf("routing fields wrong: %+v", l)
	}
	// New detail.
	if l.ReqHeaders["Authorization"] != redactedHeader {
		t.Errorf("request Authorization = %q, want %q", l.ReqHeaders["Authorization"], redactedHeader)
	}
	if l.RespHeaders["Content-Type"] != "application/json" {
		t.Errorf("response headers = %v", l.RespHeaders)
	}
	if l.BodyPreview != `{"ok":true}` {
		t.Errorf("body preview = %q", l.BodyPreview)
	}
	if !strings.Contains(l.Curl, `curl -X POST 'http://demo.test/hello'`) {
		t.Errorf("curl = %s", l.Curl)
	}
	if !strings.Contains(l.Curl, `-d '{"a":1}'`) {
		t.Errorf("curl is missing the request body: %s", l.Curl)
	}
	if strings.Contains(l.Curl, "super-secret") {
		t.Errorf("curl leaks the authorization header: %s", l.Curl)
	}
}

// ---- audit log ----

func TestAuditRingBoundsAndOrder(t *testing.T) {
	a := newAuditLog(3)
	for i := 0; i < 5; i++ {
		if err := a.Add(AuditEntry{Action: fmt.Sprintf("act%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	got := a.Recent(0)
	if len(got) != 3 {
		t.Fatalf("Recent(0) = %d entries, want 3", len(got))
	}
	for i, want := range []string{"act2", "act3", "act4"} {
		if got[i].Action != want {
			t.Errorf("entry %d = %q, want %q", i, got[i].Action, want)
		}
	}
	if got[0].Time.IsZero() {
		t.Error("Add should stamp the entry time")
	}
	if n := len(a.Recent(2)); n != 2 {
		t.Errorf("Recent(2) = %d entries, want 2", n)
	}
}

func TestAuditFileSinkRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	a := newAuditLog(10)
	if err := a.setSink(path); err != nil {
		t.Fatal(err)
	}
	want := AuditEntry{Action: "tunnel.pause", Actor: "10.0.0.1", Target: "t_ab12", Detail: "demo"}
	if err := a.Add(want); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got AuditEntry
	if err := json.Unmarshal(bytes.TrimSpace(b), &got); err != nil {
		t.Fatalf("sink line is not a JSON AuditEntry: %v", err)
	}
	if got.Action != want.Action || got.Actor != want.Actor ||
		got.Target != want.Target || got.Detail != want.Detail {
		t.Errorf("round trip mismatch: %+v", got)
	}
	if got.Time.IsZero() {
		t.Error("sink entry should carry a timestamp")
	}

	// The ring outlives the file sink.
	if err := a.Add(AuditEntry{Action: "auth.login"}); err != nil {
		t.Errorf("ring should keep working after Close: %v", err)
	}
	if len(a.Recent(0)) != 2 {
		t.Errorf("ring holds %d entries, want 2", len(a.Recent(0)))
	}
}

func TestInitAuditWithoutPathStaysRingOnly(t *testing.T) {
	if err := InitAudit(""); err != nil {
		t.Fatalf("InitAudit: %v", err)
	}
	a := globalAudit()
	if a == nil {
		t.Fatal("globalAudit should exist after InitAudit")
	}
	if err := a.Add(AuditEntry{Action: "auth.fail", Actor: "admin"}); err != nil {
		t.Errorf("ring-only audit should not error: %v", err)
	}
	if got := a.Recent(1); len(got) != 1 || got[0].Action != "auth.fail" {
		t.Errorf("Recent(1) = %+v", got)
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestTunnelActionAndTokenHandlersWriteAuditEntries(t *testing.T) {
	s := &Server{
		reg:    newRegistry(),
		tokens: newTokenStore(""),
		log:    testLogger(),
	}
	tun := &Tunnel{Session: &Session{name: "laptop"}}
	tun.ID = "t_aud1"
	tun.Type = protocol.TypeHTTP
	tun.Subdomain = "aud"
	if err := s.reg.Add(tun); err != nil {
		t.Fatal(err)
	}
	before := len(globalAudit().Recent(0))

	// pause
	req := httptest.NewRequest(http.MethodPost, "/api/tunnels/t_aud1/pause", nil)
	rec := &noopResponseWriter{}
	s.handleAPITunnelAction(rec, req)
	if !tun.paused.Load() {
		t.Error("pause should mark the tunnel paused")
	}
	// resume
	req = httptest.NewRequest(http.MethodPost, "/api/tunnels/t_aud1/resume", nil)
	s.handleAPITunnelAction(&noopResponseWriter{}, req)
	if tun.paused.Load() {
		t.Error("resume should clear the paused flag")
	}
	// token create + revoke by name
	req = httptest.NewRequest(http.MethodPost, "/api/tokens",
		strings.NewReader(`{"name":"ci","permissions":["http"]}`))
	rec = &noopResponseWriter{}
	s.handleAPITokens(rec, req)
	var created struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.body, &created); err != nil {
		t.Fatalf("create response: %v (%s)", err, rec.body)
	}
	if created.Token == "" {
		t.Fatal("expected a token in the create response")
	}
	req = httptest.NewRequest(http.MethodDelete, "/api/tokens?name=ci", nil)
	s.handleAPITokens(&noopResponseWriter{}, req)

	entries := globalAudit().Recent(0)
	if got := len(entries) - before; got != 4 {
		t.Fatalf("recorded %d audit entries, want 4", got)
	}
	actions := []string{"tunnel.pause", "tunnel.resume", "token.create", "token.revoke"}
	for i, want := range actions {
		if entries[before+i].Action != want {
			t.Errorf("entry %d action = %q, want %q", i, entries[before+i].Action, want)
		}
	}
	if entries[before].Target != "t_aud1" || entries[before].Actor != "192.0.2.1" {
		t.Errorf("pause entry = %+v", entries[before])
	}
	for _, e := range entries[before:] {
		if strings.Contains(e.Target+e.Detail, created.Token) {
			t.Errorf("audit entry leaks the token: %+v", e)
		}
	}
}

func TestHandleAPIAudit(t *testing.T) {
	s := &Server{log: testLogger()}
	if err := globalAudit().Add(AuditEntry{Action: "auth.login", Actor: "admin"}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/audit?n=1", nil)
	rec := &noopResponseWriter{}
	s.handleAPIAudit(rec, req)
	if rec.header.Get("Content-Type") != "application/json" {
		t.Errorf("content type = %q", rec.header.Get("Content-Type"))
	}
	var payload struct {
		Entries []AuditEntry `json:"entries"`
	}
	if err := json.Unmarshal(rec.body, &payload); err != nil {
		t.Fatalf("decode: %v (%s)", err, rec.body)
	}
	if len(payload.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(payload.Entries))
	}
	if payload.Entries[0].Action != "auth.login" {
		t.Errorf("entry = %+v", payload.Entries[0])
	}

	req = httptest.NewRequest(http.MethodPost, "/api/audit", nil)
	rec = &noopResponseWriter{}
	s.handleAPIAudit(rec, req)
	if rec.code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want %d", rec.code, http.StatusMethodNotAllowed)
	}
}

// ---- health ----

func TestApplyHealth(t *testing.T) {
	s := New(Config{}, testLogger())
	sess := &Session{srv: s, name: "health-client"}
	tun := &Tunnel{Tunnel: protocol.Tunnel{ID: "t_h1", Type: protocol.TypeHTTP, Subdomain: "h1"}, Session: sess}
	tun.health.Store(true)
	if err := s.reg.Add(tun); err != nil {
		t.Fatalf("add tunnel: %v", err)
	}

	// A report from the owning session flips health off.
	sess.applyHealth([]protocol.Tunnel{{ID: "t_h1", Healthy: false}})
	if tun.health.Load() {
		t.Error("applyHealth should have marked the tunnel unhealthy")
	}

	// ...and back on.
	sess.applyHealth([]protocol.Tunnel{{ID: "t_h1", Healthy: true}})
	if !tun.health.Load() {
		t.Error("applyHealth should have marked the tunnel healthy again")
	}

	// Reports for another session's tunnel are ignored.
	other := &Session{srv: s, name: "other"}
	otherTun := &Tunnel{Tunnel: protocol.Tunnel{ID: "t_h2", Type: protocol.TypeHTTP, Subdomain: "h2"}, Session: other}
	otherTun.health.Store(true)
	if err := s.reg.Add(otherTun); err != nil {
		t.Fatalf("add other tunnel: %v", err)
	}
	sess.applyHealth([]protocol.Tunnel{{ID: "t_h2", Healthy: false}})
	if !otherTun.health.Load() {
		t.Error("applyHealth updated a tunnel owned by a different session")
	}

	// Unknown ids are ignored without panic.
	sess.applyHealth([]protocol.Tunnel{{ID: "t_missing", Healthy: false}, {Healthy: false}})
}

func TestHealthMetricReflectsState(t *testing.T) {
	s := New(Config{}, testLogger())
	sess := &Session{srv: s, name: "m"}
	tun := &Tunnel{Tunnel: protocol.Tunnel{ID: "t_m1", Type: protocol.TypeHTTP, Subdomain: "m"}, Session: sess, counters: &tunnelCounters{}}
	tun.health.Store(false)
	if err := s.reg.Add(tun); err != nil {
		t.Fatalf("add: %v", err)
	}
	rec := &noopResponseWriter{}
	s.renderMetrics(rec, nil)
	if v, ok := promValue(string(rec.body), "aritun_tunnel_healthy"); !ok || v != 0 {
		t.Errorf("aritun_tunnel_healthy = %v (present=%v), want 0", v, ok)
	}
	tun.health.Store(true)
	rec = &noopResponseWriter{}
	s.renderMetrics(rec, nil)
	if v, ok := promValue(string(rec.body), "aritun_tunnel_healthy"); !ok || v != 1 {
		t.Errorf("aritun_tunnel_healthy = %v (present=%v), want 1", v, ok)
	}
}
