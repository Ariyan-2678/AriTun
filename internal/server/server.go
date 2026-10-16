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
	"net/netip"
	"net/url"
	"strconv"
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

	// TokensFile points at a JSON file of named tokens with per-type
	// permissions. It complements Token, which keeps working as a root token.
	TokensFile string

	// OAuthBase is the external base URL for OAuth callbacks, e.g.
	// "https://aritun.example.com". Provider credentials come from the
	// environment (see newOAuthProviders).
	OAuthBase string

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

	insp      *inspector
	tokens    *tokenStore
	oauth     *oauthProviders
	startedAt time.Time

	// adminLim rate limits the admin HTTP surface per client IP (defense in
	// depth: the admin binds loopback by default but may be exposed).
	adminLim *adminLimiter
	// bw keeps a bounded ring of aggregate throughput samples backing the
	// dashboard chart and /api/bandwidth.
	bw *bandwidthSampler

	mu        sync.Mutex
	sessions  map[string]*Session
	listeners map[string]net.Listener   // tunnel id -> tcp listener
	udpConns  map[string]net.PacketConn // tunnel id -> udp socket
	udpFlows  map[string]*udpFlowTable  // tunnel id -> visitor flow table
}

// New builds a server. It does not listen yet.
func New(cfg Config, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	cfg = cfg.withDefaults()
	s := &Server{
		cfg:       cfg,
		log:       log,
		reg:       newRegistry(),
		ports:     newPortAllocator(cfg.TCPMin, cfg.TCPMax),
		insp:      newInspector(500),
		startedAt: time.Now(),
		adminLim:  newAdminLimiter(adminRatePerSec, adminRateBurst),
		bw:        newBandwidthSampler(bandwidthInterval, bandwidthRetention),
		sessions:  make(map[string]*Session),
		listeners: make(map[string]net.Listener),
		udpConns:  make(map[string]net.PacketConn),
		udpFlows:  make(map[string]*udpFlowTable),
	}
	if cfg.TokensFile != "" {
		s.tokens = newTokenStore(cfg.TokensFile)
		s.log.Info("named tokens loaded", "file", cfg.TokensFile, "count", len(s.tokens.List()))
	}
	if cfg.OAuthBase != "" {
		s.oauth = newOAuthProviders(cfg.OAuthBase)
	}
	s.loadPersisted()
	return s
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

	tokenInfo := s.resolveToken(hello.Token)
	sess := newSession(s, hello.Name, hello.Version, conn, tokenInfo)
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
	// No token system at all: allow everything (dev mode).
	if s.cfg.Token == "" && s.tokens == nil {
		return nil
	}
	// Legacy root token.
	if s.cfg.Token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Token)) == 1 {
		return nil
	}
	// Named tokens.
	if s.tokens != nil && s.tokens.lookup(token) != nil {
		return nil
	}
	s.audit(nil, "auth.fail", maskToken(token), "invalid token")
	return errors.New("invalid token")
}

// resolveToken maps a hello token to a TokenInfo carrying its permissions.
// The root token (Config.Token) gets every permission; named tokens get what
// was configured.
func (s *Server) resolveToken(token string) *TokenInfo {
	if s.cfg.Token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(s.cfg.Token)) == 1 {
		return &TokenInfo{Name: "root", Permissions: allPerms}
	}
	if s.tokens != nil {
		if rec := s.tokens.lookup(token); rec != nil {
			return &TokenInfo{Name: rec.Name, Permissions: rec.Permissions}
		}
	}
	// Token-less dev mode.
	if s.cfg.Token == "" && s.tokens == nil {
		return nil
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
	// OAuth callback rides the same listener so Caddy's single TLS cert covers it.
	if s.handleOAuthCallback(w, r) {
		return
	}
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

	// Paused tunnels answer 503 without disturbing the client's registration.
	if t.paused.Load() {
		http.Error(w, "tunnel paused", http.StatusServiceUnavailable)
		return
	}

	// IP allow/deny.
	ip := visitorIP(r.Header.Get("X-Forwarded-For"), r.RemoteAddr)
	if !checkACL(ip, t.allowPrefixes, t.denyPrefixes) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Rate limit.
	if t.limiter != nil && !t.limiter.allow() {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	// OAuth gate — checked before BasicAuth so the sign-in page is reachable.
	if t.OAuth != "" {
		if !s.oauthGate(w, r, t, sub) {
			return
		}
	}

	if t.BasicAuth != "" {
		user, pass, ok := r.BasicAuth()
		if !ok || subtle.ConstantTimeCompare([]byte(user+":"+pass), []byte(t.BasicAuth)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="AriTun"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
	}

	// Multi tunnel: /20128/foo -> local port 20128, path /foo
	if t.Type == protocol.TypeMulti {
		s.handleMultiHTTP(w, r, t)
		return
	}

	cw := &countingWriter{ResponseWriter: w}
	start := time.Now()
	r = CaptureBody(r)
	s.reverseProxy(t).ServeHTTP(cw, r)
	markUpgradeStatus(r, cw)
	t.counters.record(statusOf(cw), int(cw.bytes))
	s.recordRequest(t, r, cw, start)
}

// oauthGate returns true when the request may proceed; otherwise it has
// already written a redirect or an error.
func (s *Server) oauthGate(w http.ResponseWriter, r *http.Request, t *Tunnel, subdomain string) bool {
	if s.oauth == nil || !s.oauth.ready(t.OAuth) {
		// Provider not configured server-side: fail open with a clear message
		// rather than locking everyone out.
		s.log.Warn("oauth requested but provider not configured", "provider", t.OAuth, "tunnel", t.ID)
		return true
	}
	if c, err := r.Cookie(oauthCookieName(subdomain)); err == nil {
		if _, ok := s.oauth.verifyCookie(subdomain, c.Value); ok {
			return true
		}
	}
	// Not authenticated: kick off the login flow.
	if strings.HasPrefix(r.URL.Path, oauthCallbackPath) {
		// Let the callback handler (mounted on the HTTP router) run.
		return true
	}
	s.oauth.startLogin(w, r, t.OAuth, subdomain)
	return false
}

// handleOAuthCallback intercepts /-/auth/callback/<provider> before subdomain
// routing, because the callback arrives at the parent domain, not at a tunnel.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) bool {
	if s.oauth == nil || !strings.HasPrefix(r.URL.Path, oauthCallbackPath) {
		return false
	}
	provider := strings.TrimPrefix(r.URL.Path, oauthCallbackPath)
	provider = strings.TrimSuffix(provider, "/")
	if provider != "google" && provider != "github" {
		http.NotFound(w, r)
		return true
	}
	s.oauth.handleCallback(w, r, provider)
	return true
}

// handleMultiHTTP routes by the first path segment: /20128/api -> local port 20128, path /api.
func (s *Server) handleMultiHTTP(w http.ResponseWriter, r *http.Request, t *Tunnel) {
	path := r.URL.Path
	// extract port from first segment
	seg := path
	rest := "/"
	if i := strings.IndexByte(path[1:], '/'); i >= 0 {
		seg = path[1 : 1+i]
		rest = path[1+i:]
	} else {
		seg = path[1:]
	}
	port, err := strconv.Atoi(seg)
	if err != nil || port < 1 || port > 65535 {
		http.Error(w, "usage: /<port>/<path>", http.StatusBadRequest)
		return
	}

	// rewrite path (strip the port segment)
	r = CaptureBody(r)
	r2 := r.Clone(r.Context())
	r2.URL.Path = rest
	r2.URL.RawPath = ""
	r2.RequestURI = rest

	cw := &countingWriter{ResponseWriter: w}
	start := time.Now()
	s.reverseProxyMulti(t, port, r.Host).ServeHTTP(cw, r2)
	markUpgradeStatus(r2, cw)
	t.counters.record(statusOf(cw), int(cw.bytes))
	s.recordRequest(t, r2, cw, start)
}

// reverseProxyMulti builds a proxy for a multi tunnel that opens a stream
// tagged with the target local port. reqHost is the Host header the browser
// used, needed to rewrite same-host absolute URLs in responses.
func (s *Server) reverseProxyMulti(t *Tunnel, targetPort int, reqHost string) *httputil.ReverseProxy {
	tunnelID := t.ID
	prefix := "/" + strconv.Itoa(targetPort)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(rp *httputil.ProxyRequest) {
			rp.SetURL(&url.URL{Scheme: "http", Host: "aritun-upstream"})
			rp.Out.Host = rp.In.Host
			rp.SetXForwarded()
			// Let the transport negotiate (and transparently decode) gzip so
			// the response body below is plain text we can rewrite.
			rp.Out.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(resp *http.Response) error {
			rewriteMultiResponse(resp, prefix, reqHost)
			return nil
		},
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				st, err := s.openMultiStream(tunnelID, targetPort)
				if err != nil {
					return nil, err
				}
				if t.bwLimiter != nil {
					return &limitedConn{Conn: st, bw: t.bwLimiter}, nil
				}
				return st, nil
			},
			ForceAttemptHTTP2:     false,
			ResponseHeaderTimeout: 0,
		},
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log.Debug("multi proxy error", "tunnel", tunnelID, "port", targetPort, "err", err)
			if errors.Is(err, yamux.ErrSessionShutdown) || strings.Contains(err.Error(), "goAway") {
				http.Error(w, "tunnel is offline", http.StatusBadGateway)
				return
			}
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
	}
	return proxy
}

// openMultiStream asks the owning client for a fresh data stream with a target port.
func (s *Server) openMultiStream(tunnelID string, targetPort int) (net.Conn, error) {
	t := s.reg.ByID(tunnelID)
	if t == nil {
		return nil, fmt.Errorf("tunnel %s is not registered", tunnelID)
	}
	return t.Session.openMultiStream(tunnelID, targetPort)
}

// reverseProxy builds a one-shot proxy bound to a single tunnel. Each request
// gets its own stream to the client, which keeps the routing trivial and safe.
func (s *Server) reverseProxy(t *Tunnel) *httputil.ReverseProxy {
	// Build once per tunnel and reuse. A cached http.Transport keeps its
	// connection pool warm across requests, so each pooled connection (one
	// yamux stream) is reused via keep-alive instead of a fresh stream per
	// request. That removes a stream open/close round trip from every
	// subsequent request on a hot tunnel.
	t.proxyOnce.Do(func() {
		tunnelID := t.ID
		t.httpProxy = &httputil.ReverseProxy{
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
					st, err := s.openStream(tunnelID)
					if err != nil {
						return nil, err
					}
					if t.bwLimiter != nil {
						return &limitedConn{Conn: st, bw: t.bwLimiter}, nil
					}
					return st, nil
				},
				ForceAttemptHTTP2:     false,
				ResponseHeaderTimeout: 0,
				// Keep-alive pool: reuse idle streams between requests.
				MaxIdleConns:        128,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
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
	})
	return t.httpProxy
}

// markUpgradeStatus records a protocol upgrade as the 101 it was. When a
// request switches protocols, httputil.ReverseProxy hijacks the connection
// and writes the switching-protocols response straight onto the socket, so
// the counting writer never sees a status line; without this the inspector
// and the metrics would log the upgraded connection as an ordinary 200.
func markUpgradeStatus(r *http.Request, cw *countingWriter) {
	if cw.status != 0 || r == nil || r.Header.Get("Upgrade") == "" {
		return
	}
	if headerContainsToken(r.Header.Get("Connection"), "upgrade") {
		cw.status = http.StatusSwitchingProtocols
	}
}

// openStream asks the owning client for a fresh data stream.
func (s *Server) openStream(tunnelID string) (net.Conn, error) {
	t := s.reg.ByID(tunnelID)
	if t == nil {
		return nil, fmt.Errorf("tunnel %s is not registered", tunnelID)
	}
	return t.Session.openStream(tunnelID)
}

// openUDPStream asks the owning client for a udp-tunnel stream to its local
// UDP port.
func (s *Server) openUDPStream(tunnelID string, localPort int) (net.Conn, error) {
	t := s.reg.ByID(tunnelID)
	if t == nil {
		return nil, fmt.Errorf("tunnel %s is not registered", tunnelID)
	}
	return t.Session.openUDPStream(tunnelID, localPort)
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

	t := s.reg.ByID(tunnelID)
	if t == nil {
		return
	}
	if t.paused.Load() {
		return
	}
	if !checkACL(mustAddr(in.RemoteAddr().String()), t.allowPrefixes, t.denyPrefixes) {
		return
	}

	out, err := s.openStream(tunnelID)
	if err != nil {
		s.log.Debug("tcp dial failed", "tunnel", tunnelID, "err", err)
		return
	}
	defer out.Close()

	// Bandwidth limiting: wrap both ends so the shared bucket sees both
	// directions.
	if t.bwLimiter != nil {
		in = &limitedConn{Conn: in, bw: t.bwLimiter}
		out = &limitedConn{Conn: out, bw: t.bwLimiter}
	}

	s.log.Debug("tcp connection", "tunnel", tunnelID, "peer", in.RemoteAddr().String())
	protocol.Pipe(in, out)
}

// mustAddr parses a "host:port" remote address into a netip.Addr, returning
// the zero Addr on failure (which checkACL treats as "no match" for deny and
// "not in allow list" — safe default).
func mustAddr(hostPort string) netip.Addr {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	a, _ := netip.ParseAddr(host)
	return a
}
