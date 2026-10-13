package client

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// ProxyDialer opens TCP connections through a SOCKS5 proxy.
//
// Network filtering in some regions lets the TCP handshake through but then
// black-holes the payload, so the AriTun agent has to be able to reach its
// server through a local proxy. The hostname is passed to the proxy to resolve
// (RFC 1928 ATYP DOMAINNAME) rather than resolved locally, which both avoids
// leaking lookups and lets the proxy apply its own routing.
type ProxyDialer struct {
	// network is "tcp" for now; SOCKS5 supports udp but we do not need it.
	network string
	// proxyAddr is where the SOCKS5 server listens.
	proxyAddr string
	// user/pass are optional RFC 1929 username/password credentials.
	user, pass string
	forward    net.Dialer
}

// ParseProxyURL understands:
//
//	socks5://host:port
//	socks5://user:pass@host:port
//	socks5h://host:port     (same behaviour; remote DNS is always used)
//
// Anything else is rejected rather than silently ignored — a typo in --proxy
// must not make the agent fall back to a direct connection.
func ParseProxyURL(raw string) (*ProxyDialer, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	if !strings.Contains(raw, "://") {
		// Bare "host:port" is common enough to accept.
		raw = "socks5://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "socks":
	case "http", "https", "http-connect":
		return nil, fmt.Errorf("proxy: scheme %q is not supported; use socks5://host:port", u.Scheme)
	default:
		return nil, fmt.Errorf("proxy: unsupported scheme %q", u.Scheme)
	}
	if u.Hostname() == "" {
		return nil, errors.New("proxy: missing host")
	}
	port := u.Port()
	if port == "" {
		port = "1080"
	}

	d := &ProxyDialer{
		network:   "tcp",
		proxyAddr: net.JoinHostPort(u.Hostname(), port),
	}
	if u.User != nil {
		d.user = u.User.Username()
		d.pass, _ = u.User.Password()
	}
	return d, nil
}

// DialContext connects to addr ("host:port") through the proxy.
func (p *ProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: bad target address %q: %w", addr, err)
	}
	port, err := net.LookupPort(network, portStr)
	if err != nil {
		return nil, fmt.Errorf("proxy: bad target port %q: %w", portStr, err)
	}
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("proxy: target port out of range: %d", port)
	}

	dialer := p.forward
	if deadline, ok := ctx.Deadline(); ok {
		dialer.Deadline = deadline
	} else {
		dialer.Timeout = 30 * time.Second
	}

	conn, err := dialer.DialContext(ctx, p.network, p.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy: connect to %s: %w", p.proxyAddr, err)
	}

	if err := p.handshake(conn, host, uint16(port)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// handshake performs RFC 1928 negotiation (and RFC 1929 auth if credentials
// were supplied), then issues CONNECT.
func (p *ProxyDialer) handshake(conn net.Conn, host string, port uint16) error {
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	// Method selection.
	if p.user != "" {
		if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
			return fmt.Errorf("proxy: write methods: %w", err)
		}
	} else {
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			return fmt.Errorf("proxy: write methods: %w", err)
		}
	}

	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return fmt.Errorf("proxy: read method: %w", err)
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("proxy: unexpected version %d", hdr[0])
	}
	switch hdr[1] {
	case 0x00: // no authentication
	case 0x02: // username/password (RFC 1929)
		if err := p.authenticate(conn); err != nil {
			return err
		}
	case 0xFF:
		return errors.New("proxy: no acceptable authentication method")
	default:
		return fmt.Errorf("proxy: refused auth method 0x%02x", hdr[1])
	}

	// CONNECT request. Hostname is sent as-is so the proxy resolves it.
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			v6 := ip.To16()
			req = append(req, 0x04)
			req = append(req, v6...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("proxy: hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)

	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("proxy: write connect: %w", err)
	}
	return readConnectReply(conn)
}

func (p *ProxyDialer) authenticate(conn net.Conn) error {
	if p.user == "" {
		return errors.New("proxy: server requires credentials but none were given")
	}
	// [0x01][ulen][user][plen][pass]
	req := []byte{0x01, byte(len(p.user))}
	req = append(req, p.user...)
	req = append(req, byte(len(p.pass)))
	req = append(req, p.pass...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("proxy: write auth: %w", err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		return fmt.Errorf("proxy: read auth: %w", err)
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("proxy: auth rejected (status %d)", resp[1])
	}
	return nil
}

// readConnectReply parses the variable-length SOCKS5 reply.
func readConnectReply(conn net.Conn) error {
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("proxy: read reply: %w", err)
	}
	if head[0] != 0x05 {
		return fmt.Errorf("proxy: bad reply version %d", head[0])
	}
	if head[1] != 0x00 {
		return fmt.Errorf("proxy: CONNECT failed: %s", socks5Error(head[1]))
	}

	// Skip BND.ADDR (length depends on ATYP) and BND.PORT.
	var skip int
	switch head[3] {
	case 0x01:
		skip = 4
	case 0x04:
		skip = 16
	case 0x03:
		var l [1]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return err
		}
		skip = int(l[0])
	default:
		return fmt.Errorf("proxy: unknown address type 0x%02x", head[3])
	}
	if _, err := io.CopyN(io.Discard, conn, int64(skip+2)); err != nil {
		return fmt.Errorf("proxy: read bind address: %w", err)
	}
	return nil
}

func socks5Error(code byte) string {
	switch code {
	case 0x01:
		return "general server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused by destination"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("error code %d", code)
	}
}
