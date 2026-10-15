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
	"sync"
	"time"
)

// serveAdmin exposes the dashboard and the JSON API used by `aritun status`.
// Every route is wrapped in a per-client-IP rate limiter (defense in depth:
// the admin binds loopback by default but may be exposed).
func (s *Server) serveAdmin(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tunnels", s.handleAPITunnels)
	mux.HandleFunc("/api/requests", s.handleAPIRequests)
	mux.HandleFunc("/api/tokens", s.handleAPITokens)
	mux.HandleFunc("/api/audit", s.handleAPIAudit)
	mux.HandleFunc("/api/bandwidth", s.handleAPIBandwidth)
	mux.HandleFunc("/api/tunnels/", s.handleAPITunnelAction) // /api/tunnels/{id}/{pause|resume}
	mux.HandleFunc("/metrics", s.renderMetrics)
	mux.HandleFunc("/", s.handleDashboard)

	// Keep the bandwidth chart's history ticking even when nobody is looking.
	go s.bandwidthLoop(ctx)

	srv := &http.Server{
		Handler:           s.limitAdmin(mux),
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

// limitAdmin wraps the admin mux in the per-client-IP rate limiter. The
// client IP comes from the socket address only — never from a header, which
// a caller could spoof to escape the limiter. Over the limit answers a short
// 429 with a Retry-After hint.
func (s *Server) limitAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.adminLim.allow(adminClientIP(r.RemoteAddr)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminClientIP extracts the host part of a "host:port" remote address.
func adminClientIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr
	}
	return host
}

// ---- bandwidth sampler ----

// Bandwidth sampling for the dashboard chart: the server keeps a bounded ring
// of aggregate throughput samples — one per interval, or whenever new bytes
// have moved since the last sample — and /api/bandwidth serves it.
const (
	// bandwidthInterval is the minimum spacing between samples.
	bandwidthInterval = 5 * time.Second
	// bandwidthRetention is how many samples the ring keeps (~10 minutes).
	bandwidthRetention = 120
)

// bandwidthSample is one aggregate throughput data point: the bytes moved in
// each direction since the previous sample.
type bandwidthSample struct {
	T        time.Time `json:"t"`
	BytesIn  int64     `json:"bytes_in"`
	BytesOut int64     `json:"bytes_out"`
}

// bandwidthSampler is a memory-bounded ring of bandwidthSamples.
type bandwidthSampler struct {
	mu       sync.Mutex
	interval time.Duration
	max      int
	samples  []bandwidthSample
	lastAt   time.Time
	prevIn   int64 // aggregate counters as of the previous sample
	prevOut  int64
}

func newBandwidthSampler(interval time.Duration, max int) *bandwidthSampler {
	if interval <= 0 {
		interval = bandwidthInterval
	}
	if max <= 0 {
		max = bandwidthRetention
	}
	return &bandwidthSampler{interval: interval, max: max}
}

// append records the current aggregate totals. The stored sample is the delta
// since the previous one; a shrink (a tunnel disconnecting and dropping its
// lifetime totals out of the aggregate) is clamped to zero. A sample closer
// to the previous one than the interval is dropped unless it carries new
// bytes or force is set.
func (b *bandwidthSampler) append(now time.Time, in, out int64, force bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	newBytes := in != b.prevIn || out != b.prevOut
	if !force && !newBytes && !b.lastAt.IsZero() && now.Sub(b.lastAt) < b.interval {
		return
	}
	din, dout := in-b.prevIn, out-b.prevOut
	if din < 0 {
		din = 0
	}
	if dout < 0 {
		dout = 0
	}
	b.prevIn, b.prevOut = in, out
	b.lastAt = now
	if len(b.samples) >= b.max {
		copy(b.samples, b.samples[1:])
		b.samples = b.samples[:b.max-1]
	}
	b.samples = append(b.samples, bandwidthSample{T: now, BytesIn: din, BytesOut: dout})
}

// snapshot copies the ring, oldest first.
func (b *bandwidthSampler) snapshot() []bandwidthSample {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]bandwidthSample, len(b.samples))
	copy(out, b.samples)
	return out
}

// aggregateBytes sums the lifetime byte counters across live tunnels.
func (s *Server) aggregateBytes() (in, out int64) {
	for _, t := range s.reg.List() {
		if t.counters == nil {
			continue
		}
		in += t.counters.bytesIn.Load()
		out += t.counters.bytesOut.Load()
	}
	return in, out
}

// sampleBandwidth appends a throughput sample when the ring is stale or new
// bytes have moved since the last one (or force is set).
func (s *Server) sampleBandwidth(now time.Time, force bool) {
	if s.bw == nil {
		return
	}
	in, out := s.aggregateBytes()
	s.bw.append(now, in, out, force)
}

// bandwidthLoop samples on a ticker until ctx is done, so the chart keeps
// history even when the dashboard is closed.
func (s *Server) bandwidthLoop(ctx context.Context) {
	if s.bw == nil {
		return
	}
	t := time.NewTicker(s.bw.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.sampleBandwidth(now, false)
		}
	}
}

// handleAPIBandwidth serves GET /api/bandwidth: the bounded ring of recent
// aggregate throughput samples backing the dashboard chart.
func (s *Server) handleAPIBandwidth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	s.sampleBandwidth(time.Now(), false)
	samples := []bandwidthSample{}
	interval := float64(0)
	if s.bw != nil {
		samples = s.bw.snapshot()
		interval = s.bw.interval.Seconds()
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"interval_seconds": interval,
		"samples":          samples,
	})
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
			view := map[string]any{
				"name":        rec.Name,
				"token_hint":  maskToken(rec.Token),
				"permissions": rec.Permissions,
				"created_at":  rec.CreatedAt,
				"expired":     rec.expired(),
			}
			if rec.ExpiresAt != nil {
				view["expires_at"] = *rec.ExpiresAt
			}
			views = append(views, view)
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

	case http.MethodPut:
		// Rotate issues a fresh secret for an existing named token.
		q := r.URL.Query()
		name := q.Get("name")
		if name == "" {
			http.Error(w, "pass ?name=...", http.StatusBadRequest)
			return
		}
		secret, err := s.tokens.rotate(name)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		s.audit(r, "token.rotate", name, "secret rotated")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":  name,
			"token": secret, // full value, shown once
		})

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
  .chart { width: 100%; height: 190px; display: block; }
  .legend { display: flex; gap: 1.1rem; font-size: .78rem; color: #888; margin-top: .3rem; }
  .swatch { display: inline-block; width: .7rem; height: .7rem; border-radius: 2px; margin-right: .3rem; vertical-align: -1px; }
  .sw-in { background: #2563eb; } .sw-out { background: #16a34a; }
</style></head><body><main>
  <h1>AriTun</h1>
  <div class="meta">v`+view.ServerVersion+` &middot; `+fmt.Sprint(view.TunnelCount)+` active tunnel(s) &middot; `+fmt.Sprint(view.TotalRequests)+` request(s) total</div>
  <h2>Bandwidth</h2>
  <canvas id="bwchart" class="chart"></canvas>
  <div class="legend">
    <span><span class="swatch sw-in"></span>in</span>
    <span><span class="swatch sw-out"></span>out</span>
    <span id="bwrange"></span>
  </div>`)
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

// Bandwidth chart: fetch /api/bandwidth and draw a two-series (in/out) area
// chart on a canvas. Plain canvas 2D, no dependencies. If the fetch fails the
// last drawing is kept, so a flaky admin API never breaks the dashboard.
async function bwRefresh() {
  var cv = document.getElementById('bwchart');
  if (!cv) return;
  var data;
  try {
    var r = await fetch('/api/bandwidth');
    if (!r.ok) throw new Error('' + r.status);
    data = await r.json();
  } catch (e) {
    return; // degrade gracefully: keep the previous chart
  }
  var s = (data && data.samples) || [];
  var range = document.getElementById('bwrange');
  if (range) {
    var secs = Math.round((data.interval_seconds || 0) * s.length);
    range.textContent = s.length ? ('last ' + (secs >= 60 ? Math.round(secs / 60) + ' min' : secs + ' s')) : '';
  }
  bwDraw(cv, s);
}

function bwDraw(cv, s) {
  var dpr = window.devicePixelRatio || 1;
  var w = cv.clientWidth || 640, h = cv.clientHeight || 180;
  cv.width = Math.round(w * dpr);
  cv.height = Math.round(h * dpr);
  var g = cv.getContext('2d');
  g.setTransform(dpr, 0, 0, dpr, 0, 0);
  g.clearRect(0, 0, w, h);
  var fg = getComputedStyle(document.body).color;
  var padL = 54, padR = 10, padT = 10, padB = 22;
  var iw = w - padL - padR, ih = h - padT - padB;
  g.font = '11px ui-monospace, SFMono-Regular, Menlo, monospace';

  var max = 0;
  for (var i = 0; i < s.length; i++) {
    max = Math.max(max, s[i].bytes_in || 0, s[i].bytes_out || 0);
  }
  if (!s.length || max <= 0) {
    g.fillStyle = fg;
    g.globalAlpha = 0.55;
    g.fillText(s.length ? 'no traffic in this window' : 'no samples yet', padL + 10, padT + ih / 2);
    g.globalAlpha = 1;
    return;
  }

  function fmt(n) {
    var u = ['B', 'KiB', 'MiB', 'GiB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
  }
  function xs(i) { return padL + (s.length < 2 ? iw / 2 : (iw * i) / (s.length - 1)); }
  function yOf(v) { return padT + ih - (ih * v) / max; }

  // Grid + y-axis labels.
  g.globalAlpha = 0.35;
  g.strokeStyle = fg;
  g.fillStyle = fg;
  g.lineWidth = 1;
  for (var k = 0; k <= 4; k++) {
    var y = padT + ih - (ih * k) / 4 + 0.5;
    g.beginPath(); g.moveTo(padL, y); g.lineTo(padL + iw, y); g.stroke();
    g.fillText(fmt((max * k) / 4), 4, y + 3.5);
  }
  g.globalAlpha = 1;

  // Two-series area + line.
  function series(key, color) {
    g.beginPath();
    g.moveTo(xs(0), padT + ih);
    for (var i = 0; i < s.length; i++) g.lineTo(xs(i), yOf(s[i][key] || 0));
    g.lineTo(xs(s.length - 1), padT + ih);
    g.closePath();
    g.fillStyle = color;
    g.globalAlpha = 0.16;
    g.fill();
    g.globalAlpha = 1;
    g.beginPath();
    for (var j = 0; j < s.length; j++) {
      if (j) g.lineTo(xs(j), yOf(s[j][key] || 0));
      else g.moveTo(xs(j), yOf(s[j][key] || 0));
    }
    g.strokeStyle = color;
    g.lineWidth = 1.5;
    g.stroke();
  }
  series('bytes_in', '#2563eb');
  series('bytes_out', '#16a34a');

  // x-axis labels: first / middle / last sample time.
  g.globalAlpha = 0.55;
  g.fillStyle = fg;
  function xlabel(idx, align, x) {
    var d = new Date(s[idx].t);
    var txt = ('0' + d.getHours()).slice(-2) + ':' + ('0' + d.getMinutes()).slice(-2) + ':' + ('0' + d.getSeconds()).slice(-2);
    g.textAlign = align;
    g.fillText(txt, x, h - 6);
    g.textAlign = 'left';
  }
  xlabel(0, 'left', padL);
  if (s.length > 2) xlabel((s.length / 2) | 0, 'center', xs((s.length / 2) | 0));
  xlabel(s.length - 1, 'right', padL + iw);
  g.globalAlpha = 1;
}

bwDraw(document.getElementById('bwchart'), []);
bwRefresh();
setInterval(bwRefresh, 10000);
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
