package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// TestE2E exercises the v0.4.0 feature set end to end: a real Server and real
// client.Client instances talking the actual control protocol over loopback
// inside this process (no external binaries), with a real local HTTP service
// behind every tunnel. Each subtest owns a fresh server on ephemeral ports, so
// the tests are independent and hermetic.
func TestE2E(t *testing.T) {

	t.Run("HTTPTunnel", func(t *testing.T) {
		env := startE2E(t, Config{})
		svc := newLocalService(t, "hello-from-local")
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeHTTP,
			LocalPort: localPort(t, svc),
			Subdomain: "web",
		})
		cl.waitForTunnel("web")

		resp := env.publicGet("web", "/demo")
		if resp.status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body %q)", resp.status, resp.body)
		}
		if resp.body != "hello-from-local" {
			t.Errorf("body = %q, want the local service's body", resp.body)
		}
		if got := resp.header.Get("X-Served-By"); got != "aritun-e2e-local" {
			t.Errorf("X-Served-By = %q, want aritun-e2e-local — response did not come from the local service", got)
		}
		if got := resp.header.Get("X-Echo-Path"); got != "/demo" {
			t.Errorf("local service saw path %q, want /demo", got)
		}
		if got, want := resp.header.Get("X-Echo-Host"), "web."+e2eDomain; got != want {
			t.Errorf("local service saw host %q, want %q (original Host must survive the proxy)", got, want)
		}
	})

	t.Run("BasicAuth", func(t *testing.T) {
		env := startE2E(t, Config{})
		svc := newLocalService(t, "behind-auth")
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeHTTP,
			LocalPort: localPort(t, svc),
			Subdomain: "auth",
			BasicAuth: "alice:s3cret",
		})
		cl.waitForTunnel("auth")

		plain := env.publicGet("auth", "/")
		if plain.status != http.StatusUnauthorized {
			t.Errorf("no credentials: status = %d, want 401", plain.status)
		}
		if got := plain.header.Get("WWW-Authenticate"); !strings.Contains(got, "Basic") {
			t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
		}

		wrong := env.publicGet("auth", "/", func(r *http.Request) { r.SetBasicAuth("alice", "wrong") })
		if wrong.status != http.StatusUnauthorized {
			t.Errorf("wrong password: status = %d, want 401", wrong.status)
		}

		ok := env.publicGet("auth", "/", func(r *http.Request) { r.SetBasicAuth("alice", "s3cret") })
		if ok.status != http.StatusOK {
			t.Errorf("correct credentials: status = %d, want 200 (body %q)", ok.status, ok.body)
		}
		if ok.body != "behind-auth" {
			t.Errorf("body = %q, want behind-auth", ok.body)
		}
	})

	t.Run("ACL", func(t *testing.T) {
		env := startE2E(t, Config{})
		svc := newLocalService(t, "behind-acl")
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeHTTP,
			LocalPort: localPort(t, svc),
			Subdomain: "acl",
			Allow:     []string{"203.0.113.0/24"},
			Deny:      []string{"203.0.113.66"},
		})
		cl.waitForTunnel("acl")

		// The visitor IP is taken from X-Forwarded-For's first hop, which is
		// what Caddy sets in front of the public router.
		xff := func(ip string) func(*http.Request) {
			return func(r *http.Request) { r.Header.Set("X-Forwarded-For", ip) }
		}

		if got := env.publicGet("acl", "/", xff("203.0.113.9")).status; got != http.StatusOK {
			t.Errorf("allowed IP 203.0.113.9: status = %d, want 200", got)
		}
		if got := env.publicGet("acl", "/", xff("198.51.100.7")).status; got != http.StatusForbidden {
			t.Errorf("IP outside the allow list: status = %d, want 403", got)
		}
		if got := env.publicGet("acl", "/", xff("203.0.113.66")).status; got != http.StatusForbidden {
			t.Errorf("denied IP 203.0.113.66: status = %d, want 403 (deny beats allow)", got)
		}
	})

	t.Run("RateLimit", func(t *testing.T) {
		env := startE2E(t, Config{})
		svc := newLocalService(t, "rate-limited")
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeHTTP,
			LocalPort: localPort(t, svc),
			Subdomain: "rate",
			RateLimit: 1, // 1 rps with a burst of 1
		})
		cl.waitForTunnel("rate")

		// The bucket starts full, so exactly the first request fits; the rest
		// are rejected unless a whole second elapses between two of them.
		var codes []int
		for i := 0; i < 6; i++ {
			codes = append(codes, env.publicGet("rate", "/").status)
		}

		if codes[0] != http.StatusOK {
			t.Errorf("first request = %d, want 200 (bucket starts full)", codes[0])
		}
		ok, limited := 0, 0
		for _, c := range codes {
			switch c {
			case http.StatusOK:
				ok++
			case http.StatusTooManyRequests:
				limited++
			}
		}
		if ok == 0 {
			t.Errorf("no 200 among %v — nothing got through the burst", codes)
		}
		if limited == 0 {
			t.Errorf("no 429 among %v — rate limit not enforced", codes)
		}
	})

	t.Run("PauseResume", func(t *testing.T) {
		// t.paused is now an atomic.Bool, so the admin handler's writes and the
		// public router's reads are race-free; the test runs under -race too.
		env := startE2E(t, Config{})
		svc := newLocalService(t, "pause-me")
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeHTTP,
			LocalPort: localPort(t, svc),
			Subdomain: "pause",
		})
		tun := cl.waitForTunnel("pause")

		if resp := env.adminPost("/api/tunnels/" + tun.ID + "/pause"); resp.status != http.StatusOK {
			t.Fatalf("pause: status = %d (%s)", resp.status, resp.body)
		}
		if got := env.publicGet("pause", "/").status; got != http.StatusServiceUnavailable {
			t.Errorf("paused tunnel: status = %d, want 503", got)
		}

		if resp := env.adminPost("/api/tunnels/" + tun.ID + "/resume"); resp.status != http.StatusOK {
			t.Fatalf("resume: status = %d (%s)", resp.status, resp.body)
		}
		if got := env.publicGet("pause", "/").status; got != http.StatusOK {
			t.Errorf("resumed tunnel: status = %d, want 200", got)
		}
	})

	t.Run("Inspector", func(t *testing.T) {
		env := startE2E(t, Config{})
		svc := newLocalService(t, "inspected")
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeHTTP,
			LocalPort: localPort(t, svc),
			Subdomain: "inspect",
		})
		tun := cl.waitForTunnel("inspect")

		if resp := env.publicGet("inspect", "/inspect-check"); resp.status != http.StatusOK {
			t.Fatalf("proxied request: status = %d, want 200", resp.status)
		}

		fetch := func() []RequestLog {
			resp := env.adminGet("/api/requests?tunnel=" + tun.ID)
			if resp.status != http.StatusOK {
				t.Fatalf("/api/requests: status = %d (%s)", resp.status, resp.body)
			}
			var payload struct {
				Total    int64        `json:"total"`
				Requests []RequestLog `json:"requests"`
			}
			if err := json.Unmarshal([]byte(resp.body), &payload); err != nil {
				t.Fatalf("decode /api/requests: %v (body %q)", err, resp.body)
			}
			return payload.Requests
		}

		// The entry is recorded just after the response is written, so poll
		// instead of assuming it is already there.
		pollUntil(t, "inspector entry for /inspect-check", func() bool {
			for _, r := range fetch() {
				if r.URL == "/inspect-check" && r.Method == http.MethodGet && r.Status == http.StatusOK {
					return true
				}
			}
			return false
		})

		var entry *RequestLog
		logs := fetch()
		for i := range logs {
			if logs[i].URL == "/inspect-check" {
				entry = &logs[i]
				break
			}
		}
		if entry == nil {
			t.Fatalf("entry disappeared from /api/requests: %+v", logs)
		}
		if entry.Method != http.MethodGet {
			t.Errorf("method = %q, want GET", entry.Method)
		}
		if entry.Status != http.StatusOK {
			t.Errorf("status = %d, want 200", entry.Status)
		}
		if entry.TunnelID != tun.ID {
			t.Errorf("tunnel_id = %q, want %q", entry.TunnelID, tun.ID)
		}
		if entry.Subdomain != "inspect" {
			t.Errorf("subdomain = %q, want inspect", entry.Subdomain)
		}
		if entry.Client != "e2e-client" {
			t.Errorf("client = %q, want e2e-client", entry.Client)
		}
	})

	t.Run("PrometheusMetrics", func(t *testing.T) {
		env := startE2E(t, Config{})
		svc := newLocalService(t, "metrics")
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeHTTP,
			LocalPort: localPort(t, svc),
			Subdomain: "metrics",
		})
		cl.waitForTunnel("metrics")
		if resp := env.publicGet("metrics", "/"); resp.status != http.StatusOK {
			t.Fatalf("proxied request: status = %d, want 200", resp.status)
		}

		// Counters are incremented just after the response is written, so
		// scrape until both the global and per-tunnel counters move.
		var body string
		deadline := time.Now().Add(e2eWait)
		for {
			body = env.adminGet("/metrics").body
			global, ok1 := promValue(body, "aritun_requests_total")
			perTunnel, ok2 := promValue(body, "aritun_tunnel_requests_total")
			if ok1 && global >= 1 && ok2 && perTunnel >= 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("request counters never reached 1 in /metrics:\n%s", body)
			}
			time.Sleep(5 * time.Millisecond)
		}

		for _, want := range []string{
			"aritun_active_tunnels 1",
			"aritun_requests_total ",
			"aritun_tunnel_requests_total{",
		} {
			if !strings.Contains(body, want) {
				t.Errorf("/metrics missing %q:\n%s", want, body)
			}
		}
	})

	t.Run("MultiTokenPermissions", func(t *testing.T) {
		env := startE2E(t, Config{TokensFile: filepath.Join(t.TempDir(), "tokens.json")})
		if env.srv.tokens == nil {
			t.Fatal("named token store was not loaded from TokensFile")
		}
		secret, err := env.srv.tokens.Add("limited", []string{PermHTTP})
		if err != nil {
			t.Fatalf("create limited token: %v", err)
		}

		svc := newLocalService(t, "limited-token-ok")
		port := localPort(t, svc)
		cl := env.startClient(secret,
			protocol.Tunnel{Type: protocol.TypeHTTP, LocalPort: port, Subdomain: "tokdemo"},
			protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: port},
		)
		cl.waitForTunnel("tokdemo")

		// http permission granted: the tunnel works end to end.
		if resp := env.publicGet("tokdemo", "/"); resp.status != http.StatusOK || resp.body != "limited-token-ok" {
			t.Errorf("http tunnel on limited token: status = %d body = %q, want 200/limited-token-ok",
				resp.status, resp.body)
		}

		// tcp permission missing: rejected, never registered anywhere.
		registry := env.srv.Registry().List()
		if len(registry) != 1 {
			t.Fatalf("registry holds %d tunnel(s), want only the http tunnel", len(registry))
		}
		if registry[0].Type != protocol.TypeHTTP {
			t.Fatalf("registry holds a %q tunnel, want only http", registry[0].Type)
		}
		if snap := cl.snapshot(); len(snap) != 1 || snap[0].Type != protocol.TypeHTTP {
			t.Fatalf("client snapshot = %+v, want exactly the http tunnel", snap)
		}
		if !strings.Contains(cl.logs.String(), "not allowed to publish tcp tunnels") {
			t.Fatalf("client never saw the tcp permission error; client log:\n%s", cl.logs.String())
		}
	})

	t.Run("UDPTunnel", func(t *testing.T) {
		env := startE2E(t, Config{})
		local := newLocalUDPEcho(t)
		cl := env.startClient(e2eRootToken, protocol.Tunnel{Type: protocol.TypeUDP, LocalPort: local})

		var tun protocol.Tunnel
		pollUntil(t, "udp tunnel registered", func() bool {
			for _, tn := range cl.snapshot() {
				if tn.Type == protocol.TypeUDP && tn.Error == "" && tn.PublicPort > 0 {
					tun = tn
					return true
				}
			}
			return false
		})

		conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", tun.PublicPort))
		if err != nil {
			t.Fatalf("dial public udp port: %v", err)
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ping-udp")); err != nil {
			t.Fatalf("write datagram: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(e2eWait))
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read echoed datagram: %v", err)
		}
		if got := string(buf[:n]); got != "ping-udp" {
			t.Errorf("echoed datagram = %q, want %q", got, "ping-udp")
		}
	})
}

// newLocalUDPEcho starts a real UDP echo service on an ephemeral loopback port
// and returns its port.
func newLocalUDPEcho(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(buf[:n], addr)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}
