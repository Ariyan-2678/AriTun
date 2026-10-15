package server

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// renderMetrics emits the Prometheus text exposition format for the /metrics
// endpoint. It is hand-written (no client library) to keep dependencies light.
func (s *Server) renderMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var b strings.Builder
	now := time.Now()

	// Server-level gauges.
	activeTunnels := s.reg.Count()
	s.mu.Lock()
	activeSessions := len(s.sessions)
	s.mu.Unlock()

	fmt.Fprintf(&b, "# HELP aritun_active_tunnels Number of registered tunnels.\n")
	fmt.Fprintf(&b, "# TYPE aritun_active_tunnels gauge\n")
	fmt.Fprintf(&b, "aritun_active_tunnels %d\n", activeTunnels)

	fmt.Fprintf(&b, "# HELP aritun_active_sessions Number of connected client sessions.\n")
	fmt.Fprintf(&b, "# TYPE aritun_active_sessions gauge\n")
	fmt.Fprintf(&b, "aritun_active_sessions %d\n", activeSessions)

	fmt.Fprintf(&b, "# HELP aritun_requests_total Total proxied requests across all tunnels.\n")
	fmt.Fprintf(&b, "# TYPE aritun_requests_total counter\n")
	fmt.Fprintf(&b, "aritun_requests_total %d\n", s.insp.total.Load())

	fmt.Fprintf(&b, "# HELP aritun_uptime_seconds Server uptime.\n")
	fmt.Fprintf(&b, "# TYPE aritun_uptime_seconds gauge\n")
	fmt.Fprintf(&b, "aritun_uptime_seconds %.0f\n", now.Sub(s.startedAt).Seconds())

	// Per-tunnel counters.
	tunnels := s.reg.List()
	if len(tunnels) > 0 {
		fmt.Fprintf(&b, "# HELP aritun_tunnel_requests_total Requests per tunnel.\n")
		fmt.Fprintf(&b, "# TYPE aritun_tunnel_requests_total counter\n")
		fmt.Fprintf(&b, "# HELP aritun_tunnel_bytes_out_total Bytes sent to visitors per tunnel.\n")
		fmt.Fprintf(&b, "# TYPE aritun_tunnel_bytes_out_total counter\n")
		fmt.Fprintf(&b, "# HELP aritun_tunnel_bytes_in_total Bytes received from visitors per tunnel.\n")
		fmt.Fprintf(&b, "# TYPE aritun_tunnel_bytes_in_total counter\n")
		fmt.Fprintf(&b, "# HELP aritun_tunnel_paused Whether a tunnel is paused (1) or live (0).\n")
		fmt.Fprintf(&b, "# TYPE aritun_tunnel_paused gauge\n")
		fmt.Fprintf(&b, "# HELP aritun_tunnel_healthy Whether a tunnel's local service was last reachable (1) or not (0).\n")
		fmt.Fprintf(&b, "# TYPE aritun_tunnel_healthy gauge\n")

		// Stable order for reproducible scrapes.
		sort.Slice(tunnels, func(i, j int) bool { return tunnels[i].ID < tunnels[j].ID })
		for _, t := range tunnels {
			c := t.counters
			if c == nil {
				continue
			}
			labels := tunnelLabels(t)
			fmt.Fprintf(&b, "aritun_tunnel_requests_total%s %d\n", labels, c.requests.Load())
			fmt.Fprintf(&b, "aritun_tunnel_bytes_out_total%s %d\n", labels, c.bytesOut.Load())
			fmt.Fprintf(&b, "aritun_tunnel_bytes_in_total%s %d\n", labels, c.bytesIn.Load())
			paused := 0
			if t.paused.Load() {
				paused = 1
			}
			fmt.Fprintf(&b, "aritun_tunnel_paused%s %d\n", labels, paused)
			healthy := 0
			if t.health.Load() {
				healthy = 1
			}
			fmt.Fprintf(&b, "aritun_tunnel_healthy%s %d\n", labels, healthy)
		}
	}

	_, _ = w.Write([]byte(b.String()))
}

// tunnelLabels renders a Prometheus label set for one tunnel. Values are
// escaped per the exposition format (backslash, quote, newline).
func tunnelLabels(t *Tunnel) string {
	pairs := [][2]string{
		{"id", t.ID},
		{"type", t.Type},
		{"client", t.Session.name},
	}
	if t.Subdomain != "" {
		pairs = append(pairs, [2]string{"subdomain", t.Subdomain})
	}
	parts := make([]string, 0, len(pairs))
	for _, kv := range pairs {
		parts = append(parts, kv[0]+`="`+escapeProm(kv[1])+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func escapeProm(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
