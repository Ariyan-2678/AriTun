package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// serveAdmin exposes the dashboard and the JSON API used by `aritun status`.
func (s *Server) serveAdmin(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tunnels", s.handleAPITunnels)
	mux.HandleFunc("/api/requests", s.handleAPIRequests)
	mux.HandleFunc("/api/tokens", s.handleAPITokens)
	mux.HandleFunc("/api/audit", s.handleAPIAudit)
	mux.HandleFunc("/api/tunnels/", s.handleAPITunnelAction) // /api/tunnels/{id}/{pause|resume}
	mux.HandleFunc("/metrics", s.renderMetrics)
	mux.HandleFunc("/", s.handleDashboard)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

type tunnelView struct {
	ID             string   `json:"id"`
	Client         string   `json:"client"`
	Type           string   `json:"type"`
	LocalPort      int      `json:"local_port"`
	Subdomain      string   `json:"subdomain,omitempty"`
	PublicURL      string   `json:"public_url,omitempty"`
	PublicPort     int      `json:"public_port,omitempty"`
	AgeSeconds     int64    `json:"age_seconds"`
	Paused         bool     `json:"paused"`
	Requests       int64    `json:"requests"`
	BytesIn        int64    `json:"bytes_in"`
	BytesOut       int64    `json:"bytes_out"`
	RateLimit      int      `json:"rate_limit,omitempty"`
	BandwidthLimit int64    `json:"bandwidth_limit,omitempty"`
	Allow          []string `json:"allow,omitempty"`
	Deny           []string `json:"deny,omitempty"`
	OAuth          string   `json:"oauth,omitempty"`
	Healthy        bool     `json:"healthy"`
}

type dashboardView struct {
	ServerVersion string       `json:"server_version"`
	Domain        string       `json:"domain"`
	TunnelCount   int          `json:"tunnel_count"`
	TotalRequests int64        `json:"total_requests"`
	Tunnels       []tunnelView `json:"tunnels"`
}

func (s *Server) snapshot() dashboardView {
	tunnels := s.reg.List()
	views := make([]tunnelView, 0, len(tunnels))
	for _, t := range tunnels {
		var req, in, out int64
		if t.counters != nil {
			req = t.counters.requests.Load()
			in = t.counters.bytesIn.Load()
			out = t.counters.bytesOut.Load()
		}
		views = append(views, tunnelView{
			ID:             t.ID,
			Client:         t.Session.name,
			Type:           t.Type,
			LocalPort:      t.LocalPort,
			Subdomain:      t.Subdomain,
			PublicURL:      t.PublicURL,
			PublicPort:     t.PublicPort,
			AgeSeconds:     int64(time.Since(t.Session.createdAt).Seconds()),
			Paused:         t.paused.Load(),
			Requests:       req,
			BytesIn:        in,
			BytesOut:       out,
			RateLimit:      t.RateLimit,
			BandwidthLimit: t.BandwidthLimit,
			Allow:          t.Allow,
			Deny:           t.Deny,
			OAuth:          t.OAuth,
			Healthy:        t.health.Load(),
		})
	}
	return dashboardView{
		ServerVersion: aritunVersion,
		Domain:        s.cfg.Domain,
		TunnelCount:   len(views),
		TotalRequests: s.insp.total.Load(),
		Tunnels:       views,
	}
}

func (s *Server) handleAPITunnels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// Version is filled separately; keep the payload honest.
	view := s.snapshot()
	_ = json.NewEncoder(w).Encode(view)
}

// handleAPIRequests returns the recent-request ring for `aritun inspect` and
// the dashboard. Optional ?tunnel=<id> filters to one tunnel.
func (s *Server) handleAPIRequests(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	logs := s.insp.Recent(0)
	if tid := r.URL.Query().Get("tunnel"); tid != "" {
		filtered := logs[:0]
		for _, l := range logs {
			if l.TunnelID == tid {
				filtered = append(filtered, l)
			}
		}
		logs = filtered
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"total":    s.insp.total.Load(),
		"requests": logs,
	})
}

// handleAPIAudit serves GET /api/audit with the recent administrative
// actions, oldest first. Optional ?n=<count> bounds the response (default 100).
func (s *Server) handleAPIAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	n := 100
	if q := r.URL.Query().Get("n"); q != "" {
		if v, err := strconv.Atoi(q); err == nil && v > 0 {
			n = v
		}
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"entries": globalAudit().Recent(n),
	})
}

// handleAPITokens serves GET (list) and POST (create) on /api/tokens, and
// DELETE /api/tokens?token=... or ?name=... to revoke.
func (s *Server) handleAPITokens(w http.ResponseWriter, r *http.Request) {
	if s.tokens == nil {
		http.Error(w, "named tokens are disabled (start aritund with --tokens-file)", http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	switch r.Method {
	case http.MethodGet:
		list := s.tokens.List()
		views := make([]map[string]any, 0, len(list))
		for _, rec := range list {
			views = append(views, map[string]any{
				"name":        rec.Name,
				"token_hint":  maskToken(rec.Token),
				"permissions": rec.Permissions,
				"created_at":  rec.CreatedAt,
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"tokens": views})

	case http.MethodPost:
		var body struct {
			Name        string   `json:"name"`
			Permissions []string `json:"permissions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
			return
		}
		secret, err := s.tokens.Add(body.Name, body.Permissions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.audit(r, "token.create", body.Name,
			"permissions: "+strings.Join(body.Permissions, ","))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":        body.Name,
			"token":       secret, // full value, shown once
			"permissions": body.Permissions,
		})

	case http.MethodDelete:
		q := r.URL.Query()
		if secret := q.Get("token"); secret != "" {
			if s.tokens.Remove(secret) {
				// Only the masked form is ever logged.
				s.audit(r, "token.revoke", maskToken(secret), "revoked by secret")
				_ = json.NewEncoder(w).Encode(map[string]any{"revoked": 1})
			} else {
				http.Error(w, "token not found", http.StatusNotFound)
			}
			return
		}
		if name := q.Get("name"); name != "" {
			revoked := s.tokens.RemoveByName(name)
			if revoked > 0 {
				s.audit(r, "token.revoke", name,
					fmt.Sprintf("revoked %d token(s)", revoked))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"revoked": revoked})
			return
		}
		http.Error(w, "pass ?token=... or ?name=...", http.StatusBadRequest)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleAPITunnelAction handles /api/tunnels/{id}/{pause|resume}.
func (s *Server) handleAPITunnelAction(w http.ResponseWriter, r *http.Request) {
	// Path: /api/tunnels/<id>/<action>
	rest := strings.TrimPrefix(r.URL.Path, "/api/tunnels/")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	id, action := parts[0], parts[1]
	t := s.reg.ByID(id)
	if t == nil {
		http.Error(w, "tunnel not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")

	switch action {
	case "pause":
		t.paused.Store(true)
		s.audit(r, "tunnel.pause", id, t.Session.name)
		s.log.Info("tunnel paused", "tunnel", id, "client", t.Session.name)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "paused": true})
	case "resume":
		t.paused.Store(false)
		s.audit(r, "tunnel.resume", id, t.Session.name)
		s.log.Info("tunnel resumed", "tunnel", id, "client", t.Session.name)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": id, "paused": false})
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	view := s.snapshot()
	logs := s.insp.Recent(20)

	fmt.Fprint(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AriTun - dashboard</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 2.5rem 1.5rem; }
  main { max-width: 68rem; margin: 0 auto; }
  h1 { font-size: 1.15rem; font-weight: 600; margin: 0 0 .25rem; }
  h2 { font-size: .95rem; font-weight: 600; margin: 2rem 0 .5rem; color: #666; }
  .meta { color: #888; font-size: .82rem; margin-bottom: 1.75rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: .55rem .7rem; border-bottom: 1px solid rgba(128,128,128,.22); }
  th { font-size: .72rem; text-transform: uppercase; letter-spacing: .06em; color: #888; font-weight: 600; }
  code, a { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85rem; }
  a { color: inherit; }
  .tag { display: inline-block; padding: .1rem .45rem; border-radius: 4px;
         font-size: .7rem; font-weight: 600; letter-spacing: .04em; }
  .http { background: rgba(34,197,94,.16); color: #16a34a; }
  .tcp  { background: rgba(59,130,246,.16); color: #2563eb; }
  .multi{ background: rgba(168,85,247,.16); color: #9333ea; }
  .paused{ background: rgba(234,179,8,.18); color: #a16207; }
  .down{ background: rgba(239,68,68,.16); color: #dc2626; }
  .btn { display:inline-block; padding:.2rem .55rem; border-radius:5px; border:1px solid rgba(128,128,128,.35);
         background:transparent; color:inherit; font-size:.72rem; cursor:pointer; }
  .btn:hover { background:rgba(128,128,128,.15); }
  .empty { color: #888; padding: 2rem 0; }
  .status-2 { color:#16a34a; } .status-3 { color:#2563eb; } .status-4 { color:#a16207; } .status-5 { color:#dc2626; }
</style></head><body><main>
  <h1>AriTun</h1>
  <div class="meta">v`+view.ServerVersion+` &middot; `+fmt.Sprint(view.TunnelCount)+` active tunnel(s) &middot; `+fmt.Sprint(view.TotalRequests)+` request(s) total</div>`)
	if len(view.Tunnels) == 0 {
		fmt.Fprint(w, `<div class="empty">No tunnels yet. Start one with <code>aritun http 3000</code>.</div>`)
	} else {
		fmt.Fprint(w, `<table><thead><tr>
  <th>Type</th><th>Client</th><th>Local</th><th>Public</th><th>Req</th><th>Traffic</th><th>Uptime</th><th></th>
</tr></thead><tbody>`)
		for _, t := range view.Tunnels {
			public := t.PublicURL
			if t.Type == "tcp" || t.Type == "udp" {
				public = fmt.Sprintf("%s:%d", s.publicHost(), t.PublicPort)
			}
			local := fmt.Sprintf("%d", t.LocalPort)
			link := ""
			if (t.Type == "http" || t.Type == "multi") && t.PublicURL != "" {
				link = fmt.Sprintf(`<a href="%s" target="_blank" rel="noreferrer">%s</a>`, t.PublicURL, t.PublicURL)
			} else {
				link = "<code>" + htmlEscape(public) + "</code>"
			}
			pausedTag := ""
			if t.Paused {
				pausedTag = ` <span class="tag paused">PAUSED</span>`
			}
			if !t.Healthy {
				pausedTag += ` <span class="tag down">DOWN</span>`
			}
			action := "pause"
			label := "Pause"
			if t.Paused {
				action = "resume"
				label = "Resume"
			}
			fmt.Fprintf(w, `<tr>
  <td><span class="tag %s">%s</span>%s</td>
  <td>%s</td><td><code>%s</code></td><td>%s</td>
  <td>%d</td><td>%s</td><td>%s</td>
  <td><button class="btn" onclick="act('%s','%s')">%s</button></td>
</tr>`, t.Type, t.Type, pausedTag, htmlEscape(t.Client), local, link, t.Requests, humanBytes(t.BytesIn+t.BytesOut), humanAge(t.AgeSeconds), t.ID, action, label)
		}
		fmt.Fprint(w, `</tbody></table>`)
	}

	fmt.Fprint(w, `<h2>Recent requests</h2>`)
	if len(logs) == 0 {
		fmt.Fprint(w, `<div class="empty">No requests yet.</div>`)
	} else {
		fmt.Fprint(w, `<table><thead><tr><th>Time</th><th>Status</th><th>Method</th><th>URL</th><th>Bytes</th><th>Duration</th><th>IP</th><th>Client</th></tr></thead><tbody>`)
		for _, l := range logs {
			fmt.Fprintf(w, `<tr>
  <td>%s</td>
  <td class="status-%d">%d</td>
  <td>%s</td><td><code>%s</code></td>
  <td>%s</td><td>%dms</td>
  <td><code>%s</code></td><td>%s</td>
</tr>`, l.Time.Format("15:04:05"), l.Status/100, l.Status, htmlEscape(l.Method), htmlEscape(l.URL), humanBytes(l.Bytes), l.Duration, htmlEscape(l.RemoteIP), htmlEscape(l.Client))
		}
		fmt.Fprint(w, `</tbody></table>`)
	}

	fmt.Fprint(w, `<h2>Recent admin actions</h2>`)
	audits := globalAudit().Recent(10)
	if len(audits) == 0 {
		fmt.Fprint(w, `<div class="empty">No admin actions yet.</div>`)
	} else {
		fmt.Fprint(w, `<table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Detail</th></tr></thead><tbody>`)
		for _, e := range audits {
			fmt.Fprintf(w, `<tr>
  <td>%s</td><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td>
</tr>`, e.Time.Format("15:04:05"), htmlEscape(e.Action), htmlEscape(e.Actor),
				htmlEscape(e.Target), htmlEscape(e.Detail))
		}
		fmt.Fprint(w, `</tbody></table>`)
	}

	fmt.Fprint(w, `</main>
<script>
async function act(id, action) {
  const r = await fetch('/api/tunnels/' + id + '/' + action, {method:'POST'});
  if (r.ok) location.reload();
}
</script>
</body></html>`)
}

// publicHost guesses the address tcp tunnels should be advertised on.
func (s *Server) publicHost() string {
	if s.cfg.Domain != "" {
		return s.cfg.Domain
	}
	return "server"
}

func humanAge(sec int64) string {
	d := time.Duration(sec) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}
