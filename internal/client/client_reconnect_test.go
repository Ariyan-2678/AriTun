package client

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

func quietLog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeControlServer speaks just enough of the control protocol to complete
// handshakes and capture register messages, one session per TCP connection.
type fakeControlServer struct {
	ln        net.Listener
	registers chan []protocol.Tunnel
	sessions  chan net.Conn
}

func newFakeControlServer(t *testing.T) *fakeControlServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &fakeControlServer{
		ln:        ln,
		registers: make(chan []protocol.Tunnel, 8),
		sessions:  make(chan net.Conn, 8),
	}
	go s.acceptLoop()
	return s
}

func (s *fakeControlServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.serve(conn)
	}
}

func (s *fakeControlServer) serve(conn net.Conn) {
	if _, err := protocol.ReadMsg(conn); err != nil { // hello
		conn.Close()
		return
	}
	if err := protocol.WriteMsg(conn, &protocol.Msg{Op: protocol.OpWelcome, ClientID: "client-1"}); err != nil {
		conn.Close()
		return
	}
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = nil
	cfg.Logger = protocol.YamuxLogger(quietLog())
	sess, err := yamux.Server(conn, cfg)
	if err != nil {
		conn.Close()
		return
	}
	defer sess.Close()
	st, err := sess.Accept()
	if err != nil {
		conn.Close()
		return
	}
	defer st.Close()
	if _, _, err := protocol.ReadStreamHeader(st); err != nil {
		return
	}
	msg, err := protocol.ReadMsg(st)
	if err != nil {
		return
	}
	if msg.Op != protocol.OpRegister {
		return
	}
	s.registers <- msg.Tunnels
	registered := make([]protocol.Tunnel, len(msg.Tunnels))
	for i, tu := range msg.Tunnels {
		tu.ID = fmt.Sprintf("tun-%d", i)
		tu.PublicURL = "https://" + tu.ID + ".example.test"
		registered[i] = tu
	}
	if err := protocol.WriteMsg(st, &protocol.Msg{Op: protocol.OpRegistered, Tunnels: registered}); err != nil {
		return
	}
	s.sessions <- conn
	// Hold the session open until the peer hangs up or the test drops it.
	var buf [1]byte
	_, _ = st.Read(buf[:])
}

func recvTunnels(t *testing.T, ch chan []protocol.Tunnel) []protocol.Tunnel {
	t.Helper()
	select {
	case ts := <-ch:
		return ts
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for register")
		return nil
	}
}

func recvConn(t *testing.T, ch chan net.Conn) net.Conn {
	t.Helper()
	select {
	case c := <-ch:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for session")
		return nil
	}
}

func TestRequestedTunnelsSurviveReconnect(t *testing.T) {
	srv := newFakeControlServer(t)
	defer srv.ln.Close()

	requested := []protocol.Tunnel{
		{Type: protocol.TypeHTTP, LocalPort: 8080, Subdomain: "app"},
		{Type: protocol.TypeTCP, LocalPort: 2222},
	}
	c, err := New(Config{Server: srv.ln.Addr().String(), NoTLS: true, Token: "test"}, requested, quietLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() { runErr <- c.Run(ctx) }()

	first := recvTunnels(t, srv.registers)
	if !reflect.DeepEqual(first, requested) {
		t.Fatalf("first register = %+v, want %+v", first, requested)
	}

	// Drop the first session; the client must reconnect and re-register the
	// same requested tunnels.
	sess := recvConn(t, srv.sessions)
	sess.Close()

	second := recvTunnels(t, srv.registers)
	if !reflect.DeepEqual(second, requested) {
		t.Fatalf("register after reconnect = %+v, want %+v", second, requested)
	}

	// The published set was cleared during the drop and repopulated from the
	// second register (the fake server assigns tun-0 / tun-1).
	deadline := time.Now().Add(5 * time.Second)
	for len(c.Snapshot()) != len(requested) {
		if time.Now().After(deadline) {
			t.Fatalf("snapshot after reconnect has %d tunnels, want %d", len(c.Snapshot()), len(requested))
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	if err := <-runErr; err != context.Canceled {
		t.Errorf("Run returned %v, want context.Canceled", err)
	}
}

func TestClearActiveKeepsRequested(t *testing.T) {
	requested := []protocol.Tunnel{{Type: protocol.TypeHTTP, LocalPort: 8080}}
	c, err := New(Config{Server: "127.0.0.1:1", NoTLS: true}, requested, quietLog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.applyRegistered([]protocol.Tunnel{{
		ID: "a", Type: protocol.TypeHTTP, LocalPort: 8080, PublicURL: "https://a.test",
	}})
	if got := len(c.Snapshot()); got != 1 {
		t.Fatalf("snapshot has %d tunnels, want 1", got)
	}
	c.clearActive()
	if got := len(c.Snapshot()); got != 0 {
		t.Fatalf("snapshot after clear has %d tunnels, want 0", got)
	}
	c.mu.Lock()
	got := append([]protocol.Tunnel(nil), c.requested...)
	c.mu.Unlock()
	if !reflect.DeepEqual(got, requested) {
		t.Fatalf("requested tunnels changed across a drop: got %+v, want %+v", got, requested)
	}
}
