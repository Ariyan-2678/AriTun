// Package client implements the AriTun agent that runs on your own machine.
package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/hashicorp/yamux"

	"github.com/Ariyan-2678/aritun/internal/protocol"
	"github.com/Ariyan-2678/aritun/internal/tlsutil"
)

// controlSubprotocol is the WebSocket subprotocol negotiated with the server.
const controlSubprotocol = "aritun-control"

// Config configures how the agent reaches the server.
type Config struct {
	// Server is either "host:9443" (raw) or "wss://aritun.example.com/control".
	Server string
	// Token must match the server's.
	Token string
	// Name identifies this machine in the dashboard.
	Name string
	// CAFile trusts a specific certificate (the server's self-signed one).
	CAFile string
	// Insecure skips certificate verification.
	Insecure bool
	// NoTLS disables TLS entirely. Only for talking to a local dev server.
	NoTLS bool
	// LocalHost is where proxied connections are sent. Defaults to 127.0.0.1.
	LocalHost string
	// Proxy is an optional SOCKS5 proxy, e.g. "socks5://127.0.0.1:10808".
	// Some networks let the TCP handshake through and then black-hole the
	// payload, in which case nothing works without a proxy.
	Proxy string
}

// FatalError marks a failure that reconnecting cannot fix — a rejected token,
// or a server that does not speak our protocol. Run gives up instead of
// retrying forever.
type FatalError struct{ Reason string }

func (e *FatalError) Error() string { return e.Reason }

// isCertError reports whether err came from TLS verification. A wrong CA or a
// hostname mismatch will not heal on reconnect, so the client gives up instead
// of burning the backoff loop on something the user has to fix.
func isCertError(err error) bool {
	var (
		unknownAuthority x509.UnknownAuthorityError
		invalidCert      x509.CertificateInvalidError
		hostnameMismatch x509.HostnameError
		verification     *tls.CertificateVerificationError
	)
	return errors.As(err, &unknownAuthority) ||
		errors.As(err, &invalidCert) ||
		errors.As(err, &hostnameMismatch) ||
		errors.As(err, &verification)
}

// Client keeps one multiplexed connection to the server alive and re-registers
// the requested tunnels whenever it reconnects.
type Client struct {
	cfg Config
	log *slog.Logger

	mu        sync.Mutex
	requested []protocol.Tunnel
	active    map[string]protocol.Tunnel // tunnel id -> server-assigned record
	onUpdate  func([]protocol.Tunnel)

	proxy *ProxyDialer // nil means dial directly
}

// New builds a client. requested may be replaced later with SetTunnels.
// A malformed proxy is returned as an error rather than dropped: silently
// falling back to a direct dial would look like a network outage instead of
// a typo, and on a filtered network a direct dial never works anyway.
func New(cfg Config, requested []protocol.Tunnel, log *slog.Logger) (*Client, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.LocalHost == "" {
		cfg.LocalHost = "127.0.0.1"
	}
	if cfg.Name == "" {
		host, err := os.Hostname()
		if err == nil {
			cfg.Name = host
		}
	}
	proxy, err := ParseProxyURL(cfg.Proxy)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:       cfg,
		log:       log,
		requested: requested,
		active:    make(map[string]protocol.Tunnel),
		proxy:     proxy,
	}, nil
}

// UsingProxy reports whether outbound dials go through SOCKS5.
func (c *Client) UsingProxy() bool { return c.proxy != nil }

// OnUpdate registers a callback fired whenever the set of published tunnels
// changes (first registration, reconnect, or server-side removal).
func (c *Client) OnUpdate(fn func([]protocol.Tunnel)) {
	c.mu.Lock()
	c.onUpdate = fn
	c.mu.Unlock()
}

// SetTunnels replaces the desired tunnel set and returns the tunnels that are
// currently live (empty until the first registration completes).
func (c *Client) SetTunnels(t []protocol.Tunnel) []protocol.Tunnel {
	c.mu.Lock()
	c.requested = t
	c.mu.Unlock()
	return c.Snapshot()
}

// Snapshot returns the currently published tunnels.
func (c *Client) Snapshot() []protocol.Tunnel {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]protocol.Tunnel, 0, len(c.active))
	for _, t := range c.active {
		out = append(out, t)
	}
	return out
}

// Run maintains the connection until ctx is cancelled. It reconnects forever,
// backing off between attempts.
func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var fatal *FatalError
		if errors.As(err, &fatal) {
			return fatal
		}
		if isCertError(err) {
			return &FatalError{Reason: fmt.Sprintf(
				"TLS verification failed: %v\n"+
					"  If the server uses a self-signed certificate, pass --ca <path to control-cert.pem>.\n"+
					"  --insecure skips verification; use it only for local testing.", err)}
		}
		if err != nil {
			c.log.Warn("connection lost, retrying", "err", err, "in", backoff)
		} else {
			// The session was healthy until it dropped: start the next wait
			// from the short end of the curve instead of a stale 30s.
			backoff = time.Second
		}
		c.clearActive()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *Client) clearActive() {
	c.mu.Lock()
	c.active = make(map[string]protocol.Tunnel)
	fn := c.onUpdate
	c.mu.Unlock()
	if fn != nil {
		fn(nil)
	}
}

func (c *Client) runOnce(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := protocol.WriteMsg(conn, &protocol.Msg{
		Op:      protocol.OpHello,
		Token:   c.cfg.Token,
		Name:    c.cfg.Name,
		Version: protocol.Version,
	}); err != nil {
		return err
	}
	welcome, err := protocol.ReadMsg(conn)
	if err != nil {
		return err
	}
	if welcome.Op == protocol.OpError {
		return &FatalError{Reason: "server rejected us: " + welcome.Error}
	}
	if welcome.Op != protocol.OpWelcome {
		return fmt.Errorf("unexpected reply %q", welcome.Op)
	}
	_ = conn.SetDeadline(time.Time{})
	c.log.Info("session established", "server", c.cfg.Server, "client_id", welcome.ClientID)

	// Start from DefaultConfig: yamux does not fill in defaults for a hand
	// built Config, and rejects one with an empty AcceptBacklog. DefaultConfig
	// also sets LogOutput, which must be cleared before a Logger is supplied.
	msessCfg := yamux.DefaultConfig()
	msessCfg.LogOutput = nil
	msessCfg.Logger = protocol.YamuxLogger(c.log, "component", "yamux")
	// A shorter keepalive than the default catches dropped NAT mappings
	// (laptop sleeping, phone hotspot switching) before requests hang.
	msessCfg.KeepAliveInterval = 15 * time.Second
	sess, err := yamux.Client(conn, msessCfg)
	if err != nil {
		return err
	}
	defer sess.Close()

	ctrl, err := sess.Open()
	if err != nil {
		return err
	}
	defer ctrl.Close()
	if err := protocol.WriteStreamHeader(ctrl, protocol.StreamControl, "control"); err != nil {
		return err
	}

	sendMu := &sync.Mutex{}
	send := func(m *protocol.Msg) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return protocol.WriteMsg(ctrl, m)
	}

	c.mu.Lock()
	desired := append([]protocol.Tunnel(nil), c.requested...)
	c.mu.Unlock()
	if len(desired) == 0 {
		return errors.New("no tunnels requested")
	}
	if err := send(&protocol.Msg{Op: protocol.OpRegister, Tunnels: desired}); err != nil {
		return err
	}

	// The session is healthy as long as both loops are running.
	errCh := make(chan error, 3)

	go func() {
		for {
			st, err := sess.Accept()
			if err != nil {
				errCh <- err
				return
			}
			go c.handleData(st)
		}
	}()

	go func() {
		for {
			msg, err := protocol.ReadMsg(ctrl)
			if err != nil {
				errCh <- err
				return
			}
			switch msg.Op {
			case protocol.OpRegistered:
				c.applyRegistered(msg.Tunnels)
			case protocol.OpUnregistered:
				c.forget(msg.IDs)
			case protocol.OpError:
				c.log.Error("server error", "err", msg.Error)
			}
		}
	}()

	// Keep the session warm; yamux also has its own keepalive, this just makes
	// the liveness obvious in packet captures and logs.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case <-t.C:
				if err := send(&protocol.Msg{Op: protocol.OpPing}); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

func (c *Client) applyRegistered(tunnels []protocol.Tunnel) {
	c.mu.Lock()
	for _, t := range tunnels {
		if t.Error != "" {
			c.log.Error("tunnel rejected", "type", t.Type, "local", t.LocalPort, "reason", t.Error)
			continue
		}
		c.active[t.ID] = t
	}
	out := make([]protocol.Tunnel, 0, len(c.active))
	for _, t := range c.active {
		out = append(out, t)
	}
	fn := c.onUpdate
	c.mu.Unlock()
	if fn != nil {
		fn(out)
	}
}

func (c *Client) forget(ids []string) {
	c.mu.Lock()
	for _, id := range ids {
		delete(c.active, id)
	}
	out := make([]protocol.Tunnel, 0, len(c.active))
	for _, t := range c.active {
		out = append(out, t)
	}
	fn := c.onUpdate
	c.mu.Unlock()
	if fn != nil {
		fn(out)
	}
}

func (c *Client) localPortFor(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	if t, ok := c.active[id]; ok {
		return t.LocalPort
	}
	return 0
}

// handleData accepts one proxied connection from the server and forwards it to
// the local service.
func (c *Client) handleData(st net.Conn) {
	defer st.Close()

	// Peek the first byte to distinguish StreamData from StreamMulti.
	var kindBuf [1]byte
	if _, err := io.ReadFull(st, kindBuf[:]); err != nil {
		return
	}

	if kindBuf[0] == protocol.StreamMulti {
		// Read the rest of the multi header: [2-byte id len][id][2-byte port]
		c.handleMultiData(st)
		return
	}

	// StreamData: read [2-byte id len][id] and dispatch.
	// We already consumed the kind byte; reconstruct the header manually.
	rest, err := readStreamID(st)
	if err != nil {
		return
	}
	port := c.localPortFor(rest)
	if port == 0 {
		c.log.Debug("stream for unknown tunnel", "id", rest)
		return
	}
	c.dialLocalAndPipe(st, port)
}

// handleMultiData reads a StreamMulti header and pipes to the target port.
func (c *Client) handleMultiData(st net.Conn) {
	// [2-byte id len][id][2-byte port]
	var lenBuf [2]byte
	if _, err := io.ReadFull(st, lenBuf[:]); err != nil {
		return
	}
	idLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if idLen == 0 || idLen > 1<<16-1 {
		return
	}
	id := make([]byte, idLen)
	if _, err := io.ReadFull(st, id); err != nil {
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(st, portBuf[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	if port < 1 || port > 65535 {
		return
	}
	c.dialLocalAndPipe(st, port)
}

// dialLocalAndPipe connects to localhost:port and pipes both ways.
func (c *Client) dialLocalAndPipe(st net.Conn, port int) {
	local, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", c.cfg.LocalHost, port), 5*time.Second)
	if err != nil {
		c.log.Warn("cannot reach local service", "port", port, "err", err)
		return
	}
	defer local.Close()
	protocol.Pipe(st, local)
}

// readStreamID reads [2-byte id len][id] from the stream (kind already consumed).
func readStreamID(r io.Reader) (string, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return "", err
	}
	n := int(binary.BigEndian.Uint16(lenBuf[:]))
	if n == 0 || n > 1<<16-1 {
		return "", errors.New("bad stream id length")
	}
	id := make([]byte, n)
	if _, err := io.ReadFull(r, id); err != nil {
		return "", err
	}
	return string(id), nil
}

// ---- dialing ----

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	switch {
	case strings.HasPrefix(c.cfg.Server, "wss://"), strings.HasPrefix(c.cfg.Server, "ws://"):
		return c.dialWebSocket(ctx)
	default:
		return c.dialRaw(ctx)
	}
}

func (c *Client) dialWebSocket(ctx context.Context) (net.Conn, error) {
	u, err := url.Parse(c.cfg.Server)
	if err != nil {
		return nil, err
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = "/control"
	}

	tlsCfg, err := c.tlsConfig(u.Hostname())
	if err != nil {
		return nil, err
	}

	// coder/websocket dials over HTTP/1.1; the custom transport carries our TLS
	// settings and, when configured, routes the underlying TCP through SOCKS.
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return c.dialTCP(ctx, addr)
	}
	httpc := &http.Client{Transport: tr}

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	ws, resp, err := websocket.Dial(dialCtx, u.String(), &websocket.DialOptions{
		HTTPClient:   httpc,
		Subprotocols: []string{controlSubprotocol},
	})
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			return nil, fmt.Errorf("server replied %s", resp.Status)
		}
		return nil, err
	}
	// The handshake context is cancelled on return, but the socket now owns
	// its own lifetime.
	return websocket.NetConn(context.Background(), ws, websocket.MessageBinary), nil
}

// dialTCP opens a plain TCP connection to addr, through the SOCKS proxy when
// one is configured. Everything that talks to the server goes through here.
func (c *Client) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	if c.proxy != nil {
		return c.proxy.DialContext(ctx, "tcp", addr)
	}
	d := &net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

func (c *Client) dialRaw(ctx context.Context) (net.Conn, error) {
	addr := c.cfg.Server
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}

	raw, err := c.dialTCP(ctx, addr)
	if err != nil {
		return nil, err
	}
	if c.cfg.NoTLS {
		return raw, nil
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		raw.Close()
		return nil, fmt.Errorf("server must be host:port, got %q", addr)
	}
	tlsCfg, err := c.tlsConfig(host)
	if err != nil {
		raw.Close()
		return nil, err
	}

	// The handshake gets its own deadline so a black-holed connection surfaces
	// as a dial failure instead of hanging Run() forever.
	conn := tls.Client(raw, tlsCfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *Client) tlsConfig(serverName string) (*tls.Config, error) {
	cfg := &tls.Config{
		ServerName:         serverName,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.cfg.Insecure,
		NextProtos:         []string{"http/1.1"},
	}
	if c.cfg.CAFile != "" {
		pool, err := tlsutil.LoadPool(c.cfg.CAFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}
