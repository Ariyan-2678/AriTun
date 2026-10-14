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

const Version = "0.3.1"

// Stream kinds written as the first byte of every yamux stream.
const (
	StreamControl byte = 0x01 // JSON messages, both directions
	StreamData    byte = 0x02 // one proxied TCP connection
	// StreamMulti is a proxied HTTP connection for a multi tunnel; the target
	// local port follows the id as a 2-byte big-endian integer.
	StreamMulti byte = 0x03
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
	OpError        = "error"
)

// Tunnel types.
const (
	TypeHTTP = "http"
	TypeTCP  = "tcp"
	// TypeMulti is an HTTP tunnel that routes by the first path segment:
	// /20128/foo -> the client's port 20128, path /foo.
	TypeMulti = "multi"
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
	Type      string `json:"type"` // http | tcp
	LocalPort int    `json:"local_port"`
	Subdomain string `json:"subdomain,omitempty"`

	// BasicAuth is "user:pass" required to reach an http tunnel.
	BasicAuth string `json:"basic_auth,omitempty"`

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
