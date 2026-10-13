package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// serveAdmin exposes the dashboard and the JSON API used by `aritun status`.
func (s *Server) serveAdmin(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tunnels", s.handleAPITunnels)
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
	ID         string `json:"id"`
	Client     string `json:"client"`
	Type       string `json:"type"`
	LocalPort  int    `json:"local_port"`
	Subdomain  string `json:"subdomain,omitempty"`
	PublicURL  string `json:"public_url,omitempty"`
	PublicPort int    `json:"public_port,omitempty"`
	AgeSeconds int64  `json:"age_seconds"`
}

type dashboardView struct {
	ServerVersion string       `json:"server_version"`
	Domain        string       `json:"domain"`
	TunnelCount   int          `json:"tunnel_count"`
	Tunnels       []tunnelView `json:"tunnels"`
}

func (s *Server) snapshot() dashboardView {
	tunnels := s.reg.List()
	views := make([]tunnelView, 0, len(tunnels))
	for _, t := range tunnels {
		views = append(views, tunnelView{
			ID:         t.ID,
			Client:     t.Session.name,
			Type:       t.Type,
			LocalPort:  t.LocalPort,
			Subdomain:  t.Subdomain,
			PublicURL:  t.PublicURL,
			PublicPort: t.PublicPort,
			AgeSeconds: int64(time.Since(t.Session.createdAt).Seconds()),
		})
	}
	return dashboardView{
		ServerVersion: aritunVersion,
		Domain:        s.cfg.Domain,
		TunnelCount:   len(views),
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

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	view := s.snapshot()

	fmt.Fprint(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AriTun - dashboard</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; margin: 0; padding: 2.5rem 1.5rem; }
  main { max-width: 60rem; margin: 0 auto; }
  h1 { font-size: 1.15rem; font-weight: 600; margin: 0 0 .25rem; }
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
  .empty { color: #888; padding: 2rem 0; }
</style></head><body><main>
  <h1>AriTun</h1>
  <div class="meta">v`+view.ServerVersion+` - `+fmt.Sprint(view.TunnelCount)+` active tunnel(s)</div>`)
	if len(view.Tunnels) == 0 {
		fmt.Fprint(w, `<div class="empty">No tunnels yet. Start one with <code>aritun http 3000</code>.</div>`)
	} else {
		fmt.Fprint(w, `<table><thead><tr>
  <th>Type</th><th>Client</th><th>Local</th><th>Public</th><th>Uptime</th>
</tr></thead><tbody>`)
		for _, t := range view.Tunnels {
			public := t.PublicURL
			if t.Type == "tcp" {
				public = fmt.Sprintf("%s:%d", s.publicHost(), t.PublicPort)
			}
			local := fmt.Sprintf("%d", t.LocalPort)
			link := ""
			if t.Type == "http" && t.PublicURL != "" {
				link = fmt.Sprintf(`<a href="%s" target="_blank" rel="noreferrer">%s</a>`, t.PublicURL, t.PublicURL)
			} else {
				link = "<code>" + public + "</code>"
			}
			fmt.Fprintf(w, `<tr>
  <td><span class="tag %s">%s</span></td>
  <td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td>
</tr>`, t.Type, t.Type, htmlEscape(t.Client), local, link, humanAge(t.AgeSeconds))
		}
		fmt.Fprint(w, `</tbody></table>`)
	}
	fmt.Fprint(w, `</main></body></html>`)
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
