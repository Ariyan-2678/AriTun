package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// Session is one connected client. A session owns a yamux multiplexor; every
// proxied connection is a stream on that session.
type Session struct {
	id        string
	name      string
	version   string
	createdAt time.Time
	tokenInfo *TokenInfo // nil = token-less dev mode (full access)

	srv  *Server
	conn net.Conn
	sess *yamux.Session
	ctrl net.Conn

	sendMu sync.Mutex
	once   sync.Once
	done   chan struct{}
}

func newSession(s *Server, name, version string, conn net.Conn, tokenInfo *TokenInfo) *Session {
	if name == "" {
		name = conn.RemoteAddr().String()
	}
	return &Session{
		id:        "c_" + randomID(6),
		name:      name,
		version:   version,
		createdAt: time.Now(),
		tokenInfo: tokenInfo,
		srv:       s,
		conn:      conn,
		done:      make(chan struct{}),
	}
}

// run multiplexes the connection and serves the control channel until the peer
// goes away.
func (s *Session) run() {
	s.srv.mu.Lock()
	s.srv.sessions[s.id] = s
	s.srv.mu.Unlock()

	defer func() {
		s.close()
		s.srv.mu.Lock()
		delete(s.srv.sessions, s.id)
		s.srv.mu.Unlock()
	}()

	// Start from DefaultConfig: yamux does not fill in defaults for a hand
	// built Config, and rejects one with an empty AcceptBacklog. DefaultConfig
	// also sets LogOutput, which must be cleared before a Logger is supplied.
	msessCfg := yamux.DefaultConfig()
	msessCfg.LogOutput = nil
	msessCfg.Logger = protocol.YamuxLogger(s.srv.log, "component", "yamux", "client", s.id)
	msess, err := yamux.Server(s.conn, msessCfg)
	if err != nil {
		s.srv.log.Error("yamux server", "err", err)
		return
	}
	s.sess = msess

	ctrl, err := msess.Accept()
	if err != nil {
		s.srv.log.Debug("control stream", "err", err)
		return
	}
	kind, _, err := protocol.ReadStreamHeader(ctrl)
	if err != nil || kind != protocol.StreamControl {
		s.srv.log.Warn("bad control stream", "kind", kind, "err", err)
		ctrl.Close()
		return
	}
	s.ctrl = ctrl

	enc := &controlWriter{sess: s}

	for {
		msg, err := protocol.ReadMsg(ctrl)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				s.srv.log.Debug("control read", "client", s.name, "err", err)
			}
			return
		}
		if err := s.dispatch(msg, enc); err != nil {
			s.srv.log.Warn("control dispatch", "client", s.name, "op", msg.Op, "err", err)
			enc.send(&protocol.Msg{Op: protocol.OpError, Error: err.Error()})
		}
	}
}

func (s *Session) dispatch(msg *protocol.Msg, enc *controlWriter) error {
	switch msg.Op {
	case protocol.OpRegister:
		return s.register(msg.Tunnels, enc)
	case protocol.OpUnregister:
		s.unregister(msg.IDs)
		enc.send(&protocol.Msg{Op: protocol.OpUnregistered, IDs: msg.IDs})
		return nil
	case protocol.OpPing:
		enc.send(&protocol.Msg{Op: protocol.OpPong})
		return nil
	default:
		return fmt.Errorf("unknown op %q", msg.Op)
	}
}

// register publishes the requested tunnels. Per-tunnel failures are reported
// inline rather than failing the whole batch, so one busy port does not stop
// the rest of `aritun all` from coming up.
func (s *Session) register(tunnels []protocol.Tunnel, enc *controlWriter) error {
	resolved := make([]protocol.Tunnel, 0, len(tunnels))

	for _, req := range tunnels {
		out := req
		out.ID = "t_" + randomID(6)
		out.Error = ""

		// Permission check: does this token's grant cover the tunnel type?
		if !s.tokenInfo.Has(req.Type) {
			out.Error = fmt.Sprintf("token %q is not allowed to publish %s tunnels", s.tokenInfo.Name, req.Type)
			resolved = append(resolved, out)
			continue
		}

		t := &Tunnel{Tunnel: out, Session: s, counters: &tunnelCounters{}}

		// Compile the CIDR policy once, rejecting bad entries at register time
		// so a typo surfaces in the client's terminal, not as a silent open
		// tunnel.
		if len(req.Allow) > 0 || len(req.Deny) > 0 {
			allow, err := parseCIDRs(req.Allow)
			if err != nil {
				out.Error = "bad --allow: " + err.Error()
				resolved = append(resolved, out)
				continue
			}
			deny, err := parseCIDRs(req.Deny)
			if err != nil {
				out.Error = "bad --deny: " + err.Error()
				resolved = append(resolved, out)
				continue
			}
			t.allowPrefixes = allow
			t.denyPrefixes = deny
		}
		t.limiter = newRateLimiter(req.RateLimit)
		t.bwLimiter = newBandwidthLimiter(req.BandwidthLimit)

		switch req.Type {
		case protocol.TypeHTTP, protocol.TypeMulti:
			if req.Subdomain == "" {
				out.Error = "subdomain required"
				break
			}
			// Fold case before building the public URL so the advertised
			// link matches what the Host-header router will look up.
			sub := strings.ToLower(req.Subdomain)
			t.Subdomain = sub
			t.PublicURL = s.publicURL(sub)
			out = t.Tunnel

		case protocol.TypeTCP:
			port, err := s.srv.ports.alloc()
			if err != nil {
				out.Error = err.Error()
				break
			}
			t.PublicPort = port
			out = t.Tunnel

		default:
			out.Error = fmt.Sprintf("unknown tunnel type %q", req.Type)
		}

		if out.Error != "" {
			resolved = append(resolved, out)
			continue
		}

		if err := s.srv.reg.Add(t); err != nil {
			out.Error = err.Error()
			resolved = append(resolved, out)
			continue
		}

		if t.Type == protocol.TypeTCP {
			if _, err := s.srv.startTCPListener(t); err != nil {
				s.srv.reg.Remove(t.ID)
				out.Error = err.Error()
			}
		}

		out = t.Tunnel
		s.srv.log.Info("tunnel published",
			"client", s.name, "tunnel", t.ID, "type", t.Type,
			"local", t.LocalPort, "url", t.PublicURL, "public_port", t.PublicPort)
		resolved = append(resolved, out)
	}

	return enc.send(&protocol.Msg{Op: protocol.OpRegistered, Tunnels: resolved})
}

func (s *Session) unregister(ids []string) {
	for _, id := range ids {
		t, ok := s.srv.reg.Remove(id)
		if !ok {
			continue
		}
		s.srv.mu.Lock()
		if ln, ok := s.srv.listeners[id]; ok {
			ln.Close()
			delete(s.srv.listeners, id)
		}
		s.srv.mu.Unlock()
		s.srv.log.Info("tunnel removed", "client", s.name, "tunnel", t.ID, "type", t.Type)
	}
}

// openStream opens a data stream tagged with tunnelID.
func (s *Session) openStream(tunnelID string) (net.Conn, error) {
	select {
	case <-s.done:
		return nil, errors.New("client session is closed")
	default:
	}
	if s.sess == nil || s.sess.IsClosed() {
		return nil, errors.New("client session is closed")
	}
	st, err := s.sess.Open()
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteStreamHeader(st, protocol.StreamData, tunnelID); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// openMultiStream opens a data stream tagged with tunnelID and a target local port.
func (s *Session) openMultiStream(tunnelID string, targetPort int) (net.Conn, error) {
	select {
	case <-s.done:
		return nil, errors.New("client session is closed")
	default:
	}
	if s.sess == nil || s.sess.IsClosed() {
		return nil, errors.New("client session is closed")
	}
	st, err := s.sess.Open()
	if err != nil {
		return nil, err
	}
	if err := protocol.WriteMultiStreamHeader(st, tunnelID, targetPort); err != nil {
		st.Close()
		return nil, err
	}
	return st, nil
}

// close tears down the session and every tunnel it owned.
func (s *Session) close() {
	s.once.Do(func() {
		close(s.done)

		removed := s.srv.reg.RemoveSession(s)
		if len(removed) > 0 {
			s.srv.mu.Lock()
			for _, id := range removed {
				if ln, ok := s.srv.listeners[id]; ok {
					ln.Close()
					delete(s.srv.listeners, id)
				}
			}
			s.srv.mu.Unlock()
		}

		if s.sess != nil {
			s.sess.Close()
		}
		s.conn.Close()
	})
}

// controlWriter serialises writes to the control stream.
type controlWriter struct {
	sess *Session
}

func (w *controlWriter) send(m *protocol.Msg) error {
	w.sess.sendMu.Lock()
	defer w.sess.sendMu.Unlock()
	if w.sess.ctrl == nil {
		return errors.New("control stream not ready")
	}
	return protocol.WriteMsg(w.sess.ctrl, m)
}

func (s *Session) publicURL(subdomain string) string {
	d := s.srv.cfg.Domain
	if d == "" {
		// Development mode: no parent domain configured, so the http router is
		// reached directly and the subdomain is just the Host prefix.
		return "http://" + subdomain + "." + s.srv.cfg.HTTPAddr
	}
	return "https://" + subdomain + "." + d
}

func randomID(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
