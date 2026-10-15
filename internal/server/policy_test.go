package server

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
	"time"
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
		{"10.2.0.1", true},      // in allow, not in deny
		{"10.1.0.1", false},     // in deny (wins)
		{"192.168.1.5", true},   // bare IP in allow
		{"192.168.1.6", false},  // not in allow
		{"8.8.8.8", false},      // not in allow
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
	b := newBandwidthLimiter(1) // 1 byte/s — very slow
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
func (w *noopResponseWriter) Write(p []byte) (int, error) { w.body = append(w.body, p...); return len(p), nil }
func (w *noopResponseWriter) WriteHeader(code int)        { w.code = code }
