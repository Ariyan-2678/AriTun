package server

import (
	"context"
	"crypto/tls"
	"log"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/coder/websocket"

	"github.com/Ariyan-2678/aritun/internal/tlsutil"
)

// controlCertificate returns the TLS certificate used by the control listener.
// Explicit files win; otherwise a self-signed certificate is generated (and
// regenerated when the SAN set stops covering what clients dial).
func (s *Server) controlCertificate() (tls.Certificate, error) {
	if s.cfg.CertFile != "" && s.cfg.KeyFile != "" {
		return tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
	}

	hosts := s.controlHosts()
	cert, fp, err := tlsutil.EnsureSelfSigned(s.cfg.DataDir, hosts)
	if err != nil {
		return tls.Certificate{}, err
	}
	s.log.Info("control certificate ready", "fingerprint", fp,
		"dir", s.cfg.DataDir, "sans", len(hosts))
	return cert, nil
}

// controlHosts is the SAN set for the control certificate. Clients dial
// whatever address they can reach — a hostname, the machine's own IP, or a
// public IP behind NAT — so every one of those has to be listed or the
// handshake fails with a hostname mismatch.
func (s *Server) controlHosts() []string {
	seen := make(map[string]bool)
	var out []string
	add := func(h string) {
		h = strings.TrimSpace(h)
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}

	add("localhost")
	add("127.0.0.1")
	add("::1")

	// The bind address itself, when it names a host rather than just a port.
	if host, _, err := net.SplitHostPort(s.cfg.ControlAddr); err == nil {
		add(host)
	}

	// Addresses this machine owns, so connecting by LAN or public IP works.
	for _, ip := range tlsutil.LocalIPs() {
		add(ip)
	}

	// Anything the operator knows we cannot discover: a NAT'd public IP, an
	// alias, or a hostname.
	for _, h := range s.cfg.ControlHosts {
		add(h)
	}

	if s.cfg.Domain != "" {
		add(s.cfg.Domain)
		add("*." + s.cfg.Domain)
	}
	return out
}

// tlsListen wraps a plain listener with the control certificate.
func tlsListen(addr string, cert tls.Certificate) (net.Listener, error) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	return tls.Listen("tcp", addr, cfg)
}

// ---- websocket control upgrade ----

// ControlPath is the URL path the WebSocket control channel is served on.
const ControlPath = "/control"

// AriTun's WebSocket subprotocol for the control channel.
const controlSubprotocol = "aritun-control"

// handleControlUpgrade completes the WebSocket handshake on the public HTTP
// listener so clients can reach the control plane through Caddy on :443
// instead of opening an extra port. It reports whether the request was claimed.
func (s *Server) handleControlUpgrade(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != ControlPath || !isControlUpgrade(r) {
		return false
	}

	subprotocols := []string{controlSubprotocol}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols: subprotocols,
		// Clients authenticate with the shared token; the Origin header tells
		// us nothing useful about a CLI agent.
		InsecureSkipVerify: true,
	})
	if err != nil {
		s.log.Warn("websocket upgrade failed", "err", err, "remote", r.RemoteAddr)
		return true
	}

	// The socket outlives this request, so it must not borrow the request
	// context; lifetime is owned by the connection itself.
	conn := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	s.log.Debug("control channel upgraded", "remote", conn.RemoteAddr().String())
	go s.handleControlConn(conn)
	return true
}

// isControlUpgrade reports whether the request is asking for a WebSocket
// upgrade on the control path. Only our own agent dials this, so the checks are
// deliberately minimal: websocket.Accept performs the real validation.
func isControlUpgrade(r *http.Request) bool {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if !headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		return false
	}
	return r.Header.Get("Sec-WebSocket-Key") != ""
}

// headerContainsToken reports whether a comma-separated header value contains
// the given token, e.g. "keep-alive, Upgrade".
func headerContainsToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// slogWriter adapts net/http's *log.Logger into slog so everything lands in one
// place.
func slogWriter(l *slog.Logger) *log.Logger {
	return log.New(&slogSink{log: l}, "", 0)
}

type slogSink struct {
	log *slog.Logger
}

func (s *slogSink) Write(p []byte) (int, error) {
	s.log.Error(strings.TrimSpace(string(p)))
	return len(p), nil
}
