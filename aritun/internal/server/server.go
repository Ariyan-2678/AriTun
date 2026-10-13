// Package server implements the AriTun control plane and the public listeners.
package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// Config holds everything aritund needs to run.
type Config struct {
	// Domain is the parent domain for http tunnels, e.g. "aritun.example.com".
	// Requests arriving for "*.Domain" are routed by their first label.
	Domain string

	// Token is required in the client hello. Empty disables authentication
	// (only sensible for local development).
	Token string

	// ControlAddr is where clients dial, e.g. ":9443".
	ControlAddr string
	// ControlTLS toggles TLS on ControlAddr.
	ControlTLS bool
	// CertFile/KeyFile optionally pin the control certificate. When empty and
	// ControlTLS is on, a self-signed certificate is generated in DataDir.
	CertFile string
	KeyFile  string

	// ControlHosts are extra SANs for that generated certificate: addresses
	// clients dial that this machine cannot discover on its own, such as a
	// public IP behind NAT.
	ControlHosts []string

	// HTTPAddr is the plain HTTP listener that Caddy (or any reverse proxy)
	// forwards public http tunnels to, e.g. "127.0.0.1:9001".
	HTTPAddr string

	// AdminAddr serves the dashboard and JSON API, e.g. "127.0.0.1:9090".
	AdminAddr string

	// TCPMin/TCPMax bound the public ports handed out for tcp tunnels.
	TCPMin int
	TCPMax int

	// DataDir stores the generated control certificate.
	DataDir string

	// HandshakeTimeout bounds the hello exchange.
	HandshakeTimeout time.Duration
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.ControlAddr == "" {
		out.ControlAddr = ":9443"
	}
	if out.HTTPAddr == "" {
		out.HTTPAddr = "127.0.0.1:9001"
	}
	if out.TCPMin == 0 {
		out.TCPMin = 20000
	}
	if out.TCPMax == 0 {
		out.TCPMax = 20999
	}
	if out.DataDir == "" {
		out.DataDir = defaultDataDir()
	}
	if out.HandshakeTimeout == 0 {
		out.HandshakeTimeout = 10 * time.Second
	}
	return out
}

// Server owns the registry and every listener.
type Server struct {
	cfg   Config
	log   *slog.Logger
	reg   *Registry
	ports *portAllocator

	mu        sync.Mutex
	sessions  map[string]*Session
	listeners map[string]net.Listener // tunnel id -> tcp listener
}

// New builds a server. It does not listen yet.
func New(cfg Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	return &Server{
		cfg:       cfg,
		log:       log,
		reg:       newRegistry(),
		ports:     newPortAllocator(cfg.TCPMin, cfg.TCPMax),
		sessions:  make(map[string]*Session),
		listeners: make(map[string]net.Listener),
	}
}

// Registry exposes the tunnel table for the admin API.
func (s *Server) Registry() *Registry { return s.reg }

// Config returns the effective configuration.
func (s *Server) Config() Config { return s.cfg }

// Run starts every listener and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	errCh := make(chan error, 4)

	if s.cfg.ControlAddr != "" {
		ln, err := s.listenControl()
		if err != nil {
			return fmt.Errorf("control listener: %w", err)
		}
		s.log.Info("control plane listening", "addr", ln.Addr().String(), "tls", s.cfg.ControlTLS)
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- s.serveControl(ctx, ln)
		}()
	}

	if s.cfg.HTTPAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			return fmt.Errorf("http listener: %w", err)
		}
		s.log.Info("http router listening", "addr", ln.Addr().String())
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- s.serveHTTP(ctx, ln)
		}()
	}

	if s.cfg.AdminAddr != "" {
		ln, err := net.Listen("tcp", s.cfg.AdminAddr)
		if err != nil {
			return fmt.Errorf("admin listener: %w", err)
		}
		s.log.Info("admin dashboard listening", "addr", ln.Addr().String())
		wg.Add(1)
		go func() {
			defer wg.Done()
			errCh <- s.serveAdmin(ctx, ln)
		}()
	}

	select {
	case <-ctx.Done():
		s.shutdown()
		return nil
	case err := <-errCh:
		s.shutdown()
		return err
	}
}

func (s *Server) shutdown() {
	// Collect before closing: Session.close acquires s.mu again to clean up
	// its listeners, so closing while holding the lock would deadlock.
	s.mu.Lock()
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	for id, ln := range s.listeners {
		ln.Close()
		delete(s.listeners, id)
	}
	s.mu.Unlock()

	for _, sess := range sessions {
		sess.close()
	}
}

// ---- control plane ----

func (s *Server) listenControl() (net.Listener, error) {
	if !s.cfg.ControlTLS {
		return net.Listen("tcp", s.cfg.ControlAddr)
	}
	cert, err := s.controlCertificate()
	if err != nil {
		return nil, err
	}
	return tlsListen(s.cfg.ControlAddr, cert)
}

func (s *Server) serveControl(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go s.handleControlConn(conn)
	}
}

// handleControlConn runs the handshake and then hands the connection to yamux.
// It is shared by the TLS listener and the WebSocket upgrade path.
func (s *Server) handleControlConn(conn net.Conn) {
	remote := conn.RemoteAddr().String()
	log := s.log.With("remote", remote)

	_ = conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))
	hello, err := protocol.ReadMsg(conn)
	if err != nil {
		log.Debug("handshake failed", "err", err)
		conn.Close()
		return
	}
	if hello.Op != protocol.OpHello {
		_ = protocol.WriteMsg(conn, &protocol.Msg{Op: protocol.OpError, Error: "expected hello"})
		conn.Close()
		return
	}
	if err := s.checkToken(hello.Token); err != nil {
		log.Warn("rejected client", "err", err)
		_ = protocol.WriteMsg(conn, &protocol.Msg{Op: protocol.OpError, Error: err.Error()})
		conn.Close()
		return
	}
	_ = conn.SetDeadline(time.Time{})

	sess := newSession(s, hello.Name, hello.Version, conn)
	if err := protocol.WriteMsg(conn, &protocol.Msg{
		Op:       protocol.OpWelcome,
		ClientID: sess.id,
		Version:  protocol.Version,
	}); err != nil {
		conn.Close()
		return
	}

	log.Info("client connected", "client", sess.name, "id", sess.id, "version", hello.Version)
	sess.run()
	log.Info("client disconnected", "client", sess.name, "id", sess.id)
}

func (s *Server) checkToken(token string) error {
	if s.cfg.Token == "" {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Token)) != 1 {
		return errors.New("invalid token")
	}
	return nil
}

// ---- public http tunnels ----

func (s *Server) serveHTTP(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           http.HandlerFunc(s.handlePublicHTTP),
		ReadHeaderTimeout: 15 * time.Second,
		// Tunnelled connections are long lived (websockets, SSE, h2c upgrades).
		IdleTimeout: 0,
		ErrorLog:    slogWriter(s.log),
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutdownCtx)
	}()
	err := srv.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) || ctx.Err() != nil {
		return nil
	}
	return err
}

func (s *Server) handlePublicHTTP(w http.ResponseWriter, r *http.Request) {
	// The control channel may share this listener so that Caddy on :443 is the
	// only TLS endpoint clients need to reach.
	if s.handleControlUpgrade(w, r) {
		return
	}

	sub := s.subdomainOf(r.Host)
	if sub == "" {
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
		return
	}

	t := s.reg.BySubdomain(sub)
	if t == nil {
		s.notFound(w, sub)
		return
	}

	if t.BasicAuth != "" {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user+":"+pass), []byte(t.BasicAuth)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="AriTun"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	s.reverseProxy(t).ServeHTTP(w, r)
}

// reverseProxy builds a one-shot proxy bound to a single tunnel. Each request
// gets its own stream to the client, which keeps the routing trivial and safe.
func (s *Server) reverseProxy(t *Tunnel) *httputil.ReverseProxy {
	tunnelID := t.ID
	proxy := &httputil.ReverseProxy{
		Rewrite: func(rp *httputil.ProxyRequest) {
			rp.SetURL(&url.URL{Scheme: "http", Host: "aritun-upstream"})
			// Preserve the original Host so the app behind the tunnel can
			// build correct absolute URLs.
			rp.Out.Host = rp.In.Host
			// SetXForwarded overwrites any client-supplied headers with the
			// address we actually saw.
			rp.SetXForwarded()
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return s.openStream(tunnelID)
			},
			ForceAttemptHTTP2:     false,
			ResponseHeaderTimeout: 0,
		},
		// Flush immediately so SSE, websockets and streaming bodies work.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Debug("proxy error", "tunnel", tunnelID, "err", err)
			if errors.Is(err, yamux.ErrSessionShutdown) || strings.Contains(err.Error(), "goAway") {
				http.Error(w, "tunnel is offline", http.StatusBadGateway)
				return
			}
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return proxy
}

// openStream asks the owning client for a fresh data stream.
func (s *Server) openStream(tunnelID string) (net.Conn, error) {
	t := s.reg.ByID(tunnelID)
	if t == nil {
		return nil, fmt.Errorf("tunnel %s is not registered", tunnelID)
	}
	return t.Session.openStream(tunnelID)
}

// subdomainOf extracts the routing label from a Host header.
func (s *Server) subdomainOf(host string) string {
	h := strings.ToLower(host)
	if before, _, err := net.SplitHostPort(h); err == nil {
		h = before
	}
	h = strings.TrimSuffix(h, ".")

	if d := strings.ToLower(s.cfg.Domain); d != "" {
		if h == d {
			return ""
		}
		if strings.HasSuffix(h, "."+d) {
			return strings.TrimSuffix(h, "."+d)
		}
		// Host does not belong to our domain at all (direct IP access during
		// development): fall through and treat the first label as the name.
	}
	if i := strings.Index(h, "."); i > 0 {
		return h[:i]
	}
	return h
}

func (s *Server) notFound(w http.ResponseWriter, sub string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprintf(w, `<html><body style="font-family:system-ui;margin:4rem auto;max-width:34rem">
<h1 style="font-size:1.1rem">No tunnel at <code>%s</code></h1>
<p>That subdomain is not currently forwarded. Start a tunnel on your machine:</p>
<pre style="background:#f4f4f5;padding:1rem;border-radius:8px">aritun http 3000</pre>
</body></html>`, htmlEscape(sub))
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// ---- tcp tunnels ----

func (s *Server) startTCPListener(t *Tunnel) (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", t.PublicPort))
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listeners[t.ID] = ln
	s.mu.Unlock()

	s.log.Info("tcp tunnel published", "tunnel", t.ID, "public", t.PublicPort, "client", t.Session.name)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.pipeTCP(conn, t.ID)
		}
	}()
	return ln, nil
}

func (s *Server) pipeTCP(in net.Conn, tunnelID string) {
	defer in.Close()

	out, err := s.openStream(tunnelID)
	if err != nil {
		s.log.Debug("tcp dial failed", "tunnel", tunnelID, "err", err)
		return
	}
	defer out.Close()

	s.log.Debug("tcp connection", "tunnel", tunnelID, "peer", in.RemoteAddr().String())
	protocol.Pipe(in, out)
}
