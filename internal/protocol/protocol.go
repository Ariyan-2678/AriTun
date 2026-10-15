// Package protocol defines the wire format shared by the AriTun server and client.
//
// A control connection carries two things:
//
//  1. A short length-prefixed JSON handshake (hello/welcome) that happens on the
//     raw connection before any multiplexing starts.
//  2. A yamux session on top of that same connection. The very first stream is
//     the long-lived control channel; every other stream is one proxied
//     connection, tagged with the tunnel it belongs to.
package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const Version = "0.5.0"

// Stream kinds written as the first byte of every yamux stream.
const (
	StreamControl byte = 0x01 // JSON messages, both directions
	StreamData    byte = 0x02 // one proxied TCP connection
	// StreamMulti is a proxied HTTP connection for a multi tunnel; the target
	// local port follows the id as a 2-byte big-endian integer.
	StreamMulti byte = 0x03
	// StreamUDP is one proxied UDP datagram flow for a udp tunnel; the target
	// local port follows the id as a 2-byte big-endian integer. Each UDP
	// datagram is framed on the stream as [2-byte len][bytes].
	StreamUDP byte = 0x04
)

// Operations exchanged on the control channel.
const (
	OpHello        = "hello"
	OpWelcome      = "welcome"
	OpRegister     = "register"
	OpUnregister   = "unregister"
	OpRegistered   = "registered"
	OpUnregistered = "unregistered"
	OpPing         = "ping"
	OpPong         = "pong"
	// OpHealth carries client -> server reports of whether each tunnel's local
	// service is reachable. Uses Msg.Tunnels with only ID and Healthy set.
	OpHealth = "health"
	OpError  = "error"
)

// Tunnel types.
const (
	TypeHTTP = "http"
	TypeTCP  = "tcp"
	// TypeMulti is an HTTP tunnel that routes by the first path segment:
	// /20128/foo -> the client's port 20128, path /foo.
	TypeMulti = "multi"
	// TypeUDP forwards UDP datagrams to a local UDP port.
	TypeUDP = "udp"
)

// maxMessageSize bounds a single control message so a hostile peer cannot make
// us allocate unbounded memory.
const maxMessageSize = 1 << 20 // 1 MiB

// ErrClosed is returned when the peer hung up cleanly.
var ErrClosed = io.EOF

// Msg is the single JSON envelope used for the handshake and for the control
// channel. Exactly one of the payload fields is meaningful per Op.
type Msg struct {
	Op       string `json:"op"`
	Token    string `json:"token,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	Error    string `json:"error,omitempty"`
	ClientID string `json:"client_id,omitempty"`

	// Tunnels is used by register/registered.
	Tunnels []Tunnel `json:"tunnels,omitempty"`

	// IDs is used by unregister.
	IDs []string `json:"ids,omitempty"`
}

// Tunnel describes one published endpoint. Only the fields relevant to Type are
// set.
type Tunnel struct {
	ID        string `json:"id"`
	Type      string `json:"type"` // http | tcp | multi
	LocalPort int    `json:"local_port"`
	Subdomain string `json:"subdomain,omitempty"`

	// BasicAuth is "user:pass" required to reach an http tunnel.
	BasicAuth string `json:"basic_auth,omitempty"`

	// OAuth gates an http tunnel behind Google or GitHub sign-in. Empty means
	// disabled. Set by the client, honored by the server.
	OAuth string `json:"oauth,omitempty"`

	// Allow and Deny are CIDR lists evaluated against the visitor's IP.
	// Deny wins over Allow; an empty Allow means "everyone".
	Allow []string `json:"allow,omitempty"`
	Deny  []string `json:"deny,omitempty"`

	// RateLimit is requests per second for http/multi tunnels (0 = unlimited).
	RateLimit int `json:"rate_limit,omitempty"`

	// BandwidthLimit is bytes per second across the whole tunnel (0 = unlimited).
	BandwidthLimit int64 `json:"bandwidth_limit,omitempty"`

	// Paused is set by the server (via the admin API) to temporarily refuse
	// traffic without unregistering the tunnel. Clients see it in registered.
	Paused bool `json:"paused,omitempty"`

	// Healthy is reported by the client on OpHealth: true when the tunnel's
	// local service was reachable at the last probe. The server reflects it in
	// the dashboard and /metrics.
	Healthy bool `json:"healthy,omitempty"`

	// Filled in by the server.
	PublicPort int    `json:"public_port,omitempty"`
	PublicURL  string `json:"public_url,omitempty"`
	Error      string `json:"error,omitempty"`
}

// WriteMsg frames and writes a control message as [4-byte big-endian length][json].
func WriteMsg(w io.Writer, m *Msg) error {
	body, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(body) > maxMessageSize {
		return fmt.Errorf("protocol: message too large (%d bytes)", len(body))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// ReadMsg reads one framed control message.
func ReadMsg(r io.Reader) (*Msg, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > maxMessageSize {
		return nil, fmt.Errorf("protocol: bad message length %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	var m Msg
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("protocol: bad message: %w", err)
	}
	return &m, nil
}

// WriteStreamHeader tags a newly opened yamux stream: [1-byte kind][2-byte id length][id].
func WriteStreamHeader(w io.Writer, kind byte, id string) error {
	if len(id) > 1<<16-1 {
		return errors.New("protocol: id too long")
	}
	buf := make([]byte, 3+len(id))
	buf[0] = kind
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(id)))
	copy(buf[3:], id)
	_, err := w.Write(buf)
	return err
}

// ReadStreamHeader reads and strips a stream header.
func ReadStreamHeader(r io.Reader) (byte, string, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, "", err
	}
	n := binary.BigEndian.Uint16(hdr[1:3])
	if n == 0 {
		return 0, "", errors.New("protocol: empty stream id")
	}
	id := make([]byte, n)
	if _, err := io.ReadFull(r, id); err != nil {
		return 0, "", err
	}
	return hdr[0], string(id), nil
}

// WriteMultiStreamHeader tags a multi-tunnel data stream: [1-byte kind=0x03]
// [2-byte id length][id][2-byte target port].
func WriteMultiStreamHeader(w io.Writer, id string, targetPort int) error {
	if len(id) > 1<<16-1 {
		return errors.New("protocol: id too long")
	}
	buf := make([]byte, 5+len(id))
	buf[0] = StreamMulti
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(id)))
	copy(buf[3:], id)
	binary.BigEndian.PutUint16(buf[3+len(id):], uint16(targetPort))
	_, err := w.Write(buf)
	return err
}

// ReadMultiStreamHeader reads a multi stream header and returns the tunnel id
// and target local port.
func ReadMultiStreamHeader(r io.Reader) (string, int, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", 0, err
	}
	if hdr[0] != StreamMulti {
		return "", 0, fmt.Errorf("protocol: expected multi stream, got kind %d", hdr[0])
	}
	n := binary.BigEndian.Uint16(hdr[1:3])
	if n == 0 {
		return "", 0, errors.New("protocol: empty stream id")
	}
	id := make([]byte, n)
	if _, err := io.ReadFull(r, id); err != nil {
		return "", 0, err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	return string(id), port, nil
}

// maxDatagram bounds a single UDP payload so a hostile peer cannot make us
// allocate unbounded memory. This is the practical max UDP payload size.
const maxDatagram = 65535

// WriteUDPStreamHeader tags a udp-tunnel data stream: [1-byte kind=0x04]
// [2-byte id length][id][2-byte target port]. Same layout as multi.
func WriteUDPStreamHeader(w io.Writer, id string, targetPort int) error {
	if len(id) > 1<<16-1 {
		return errors.New("protocol: id too long")
	}
	buf := make([]byte, 5+len(id))
	buf[0] = StreamUDP
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(id)))
	copy(buf[3:], id)
	binary.BigEndian.PutUint16(buf[3+len(id):], uint16(targetPort))
	_, err := w.Write(buf)
	return err
}

// ReadUDPStreamHeader reads a udp stream header and returns the tunnel id and
// target local UDP port.
func ReadUDPStreamHeader(r io.Reader) (string, int, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", 0, err
	}
	if hdr[0] != StreamUDP {
		return "", 0, fmt.Errorf("protocol: expected udp stream, got kind %d", hdr[0])
	}
	n := binary.BigEndian.Uint16(hdr[1:3])
	if n == 0 {
		return "", 0, errors.New("protocol: empty stream id")
	}
	id := make([]byte, n)
	if _, err := io.ReadFull(r, id); err != nil {
		return "", 0, err
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return "", 0, err
	}
	port := int(binary.BigEndian.Uint16(portBuf[:]))
	return string(id), port, nil
}

// WriteDatagram frames one UDP payload on a stream as [2-byte len][bytes].
func WriteDatagram(w io.Writer, payload []byte) error {
	if len(payload) > maxDatagram {
		return errors.New("protocol: datagram too large")
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadDatagram reads one framed UDP payload from a stream.
func ReadDatagram(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
