package server

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// ---- adminLimiter unit ----

func TestAdminLimiterNilAllowsEverything(t *testing.T) {
	var l *adminLimiter
	if !l.allow("127.0.0.1") {
		t.Error("nil admin limiter must allow")
	}
	// setLimit on nil is a no-op, not a panic.
	l.setLimit(1, 1)
}

func TestAdminLimiterUnlimited(t *testing.T) {
	if newAdminLimiter(0, 10) != nil {
		t.Error("rate 0 should produce a nil (unlimited) limiter")
	}
}

func TestAdminLimiterBurstThenRefill(t *testing.T) {
	l := newAdminLimiter(5, 5) // 5 rps, burst 5
	for i := 0; i < 5; i++ {
		if !l.allow("10.0.0.1") {
			t.Fatalf("request %d should fit in the burst", i)
		}
	}
	if l.allow("10.0.0.1") {
		t.Fatal("6th immediate request should be rejected")
	}
	// Each client IP gets its own bucket.
	if !l.allow("10.0.0.2") {
		t.Error("a second client IP should start with a full burst")
	}
	time.Sleep(250 * time.Millisecond) // ~1.25 tokens
	if !l.allow("10.0.0.1") {
		t.Error("should allow after refill")
	}
}

func TestAdminLimiterSetLimitTightens(t *testing.T) {
	l := newAdminLimiter(100, 100)
	l.setLimit(2, 2)
	for i := 0; i < 2; i++ {
		if !l.allow("198.51.100.7") {
			t.Fatalf("request %d should fit the tightened burst", i)
		}
	}
	if l.allow("198.51.100.7") {
		t.Error("3rd immediate request should be rejected under the tightened limit")
	}
}

func TestAdminClientIP(t *testing.T) {
	if got := adminClientIP("192.0.2.1:54321"); got != "192.0.2.1" {
		t.Errorf("adminClientIP(hostport) = %q, want the bare host", got)
	}
	if got := adminClientIP("garbage"); got != "garbage" {
		t.Errorf("adminClientIP(garbage) = %q, want the input back", got)
	}
}

// ---- live admin handler with an aggressive limit ----

// TestAdminHandlerAggressiveRateLimit spins the admin handler directly on an
// ephemeral listener with an aggressive limit: the first burst is served,
// everything past it gets 429 until the bucket refills.
func TestAdminHandlerAggressiveRateLimit(t *testing.T) {
	s := New(Config{Domain: "ratelimit.test"}, testLogger())
	s.adminLim = newAdminLimiter(2, 10) // aggressive: 2 rps, burst 10

	ln := e2eListen(t, "admin-limited")
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan error, 1)
	go func() { stopped <- s.serveAdmin(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-stopped:
		case <-time.After(3 * time.Second):
			t.Error("serveAdmin did not stop within 3s")
		}
	})

	client := &http.Client{Timeout: 5 * time.Second}
	base := "http://" + ln.Addr().String()
	get := func(path string) (int, string, http.Header) {
		t.Helper()
		resp, err := client.Get(base + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), resp.Header
	}

	// Under the limit everything works — including every admin route.
	for _, path := range []string{"/", "/api/tunnels", "/api/bandwidth", "/metrics"} {
		if code, _, _ := get(path); code != http.StatusOK {
			t.Fatalf("GET %s: status = %d, want 200 under the limit", path, code)
		}
	}

	// Hammer past the burst; 429s must appear, and the burst must have passed.
	ok, limited := 0, 0
	var lastBody string
	var lastHdr http.Header
	for i := 0; i < 20; i++ {
		code, body, hdr := get("/")
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
			lastBody, lastHdr = body, hdr
		default:
			t.Fatalf("request %d: status = %d, want 200 or 429", i, code)
		}
	}
	if limited == 0 {
		t.Fatalf("no 429 among 20 requests — aggressive limit not enforced (%d ok)", ok)
	}
	if ok == 0 {
		t.Errorf("no 200 among 20 requests — even the burst was rejected (%d limited)", limited)
	}
	if !strings.Contains(lastBody, "too many requests") {
		t.Errorf("429 body = %q, want a short message", lastBody)
	}
	if lastHdr.Get("Retry-After") == "" {
		t.Error("429 should carry a Retry-After header")
	}

	// Refill (2 tokens/s) lets normal requests through again.
	pollUntil(t, "admin surface to recover after the burst", func() bool {
		code, _, _ := get("/")
		return code == http.StatusOK
	})
}

// ---- end-to-end harness hammer ----

// TestAdminAPIRateLimit hammers the admin API from the e2e harness with a
// test-tightened per-IP limit: requests past the burst are rejected with 429
// and normal requests succeed again once the bucket has refilled.
func TestAdminAPIRateLimit(t *testing.T) {
	env := startE2E(t, Config{})
	env.srv.adminLim.setLimit(5, 5) // tight: 5 rps, burst 5

	// Under the limit the API answers normally.
	if resp := env.adminGet("/api/tunnels"); resp.status != http.StatusOK {
		t.Fatalf("first request: status = %d, want 200 (%s)", resp.status, resp.body)
	}

	ok, limited := 0, 0
	var last e2eResponse
	for i := 0; i < 60; i++ {
		resp := env.adminGet("/api/tunnels")
		switch resp.status {
		case http.StatusOK:
			ok++
		case http.StatusTooManyRequests:
			limited++
			last = resp
		default:
			t.Fatalf("request %d: unexpected status %d (%s)", i, resp.status, resp.body)
		}
	}
	if limited == 0 {
		t.Fatalf("no 429 among 60 requests — admin rate limit not enforced (%d ok)", ok)
	}
	if ok == 0 {
		t.Errorf("no 200 among 60 requests — even the burst was rejected (%d limited)", limited)
	}
	if !strings.Contains(last.body, "too many requests") {
		t.Errorf("429 body = %q, want a short message", last.body)
	}
	if last.header.Get("Retry-After") == "" {
		t.Error("429 should carry a Retry-After header")
	}

	// Refill (5 tokens/s) lets normal requests through again.
	pollUntil(t, "admin API to recover after the burst", func() bool {
		return env.adminGet("/api/tunnels").status == http.StatusOK
	})
}
