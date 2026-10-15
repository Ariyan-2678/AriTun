package server

import (
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// registerTunnels drives Session.register directly against an in-memory
// control stream, returning the session and the resolved tunnels exactly as
// the client would see them. The session is closed at test cleanup so any
// tcp/udp listener it started does not outlive the test.
func registerTunnels(t *testing.T, s *Server, name string, reqs ...protocol.Tunnel) (*Session, []protocol.Tunnel) {
	t.Helper()

	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })

	sess := newSession(s, name, "test", c1, nil) // nil token info = dev mode
	sess.ctrl = c1
	t.Cleanup(sess.close)

	done := make(chan error, 1)
	go func() {
		done <- sess.register(reqs, &controlWriter{sess: sess})
	}()

	msg, err := protocol.ReadMsg(c2)
	if err != nil {
		t.Fatalf("read registered reply: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("register: %v", err)
	}
	if msg.Op != protocol.OpRegistered {
		t.Fatalf("op = %q, want %q", msg.Op, protocol.OpRegistered)
	}
	return sess, msg.Tunnels
}

func newPersistServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	if cfg.DataDir == "" {
		t.Fatal("persist tests must set DataDir")
	}
	return New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

// firstTunnel returns the single resolved tunnel, failing on per-tunnel errors.
func firstTunnel(t *testing.T, tuns []protocol.Tunnel) protocol.Tunnel {
	t.Helper()
	if len(tuns) != 1 {
		t.Fatalf("got %d resolved tunnels, want 1: %+v", len(tuns), tuns)
	}
	if tuns[0].Error != "" {
		t.Fatalf("tunnel error: %s", tuns[0].Error)
	}
	return tuns[0]
}

func TestPersistSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, TCPMin: 24100, TCPMax: 24199}

	s1 := newPersistServer(t, cfg)
	s1.loadPersisted()

	sess1, tuns := registerTunnels(t, s1, "alice",
		protocol.Tunnel{Type: protocol.TypeHTTP, LocalPort: 3000, Subdomain: "Web"},
		protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: 4000},
	)
	httpTun := firstTunnel(t, tuns[:1])
	tcpTun := firstTunnel(t, tuns[1:])
	if httpTun.Subdomain != "web" {
		t.Fatalf("subdomain = %q, want web (lowercased)", httpTun.Subdomain)
	}

	// The reservations must be on disk.
	b, err := os.ReadFile(filepath.Join(dir, persistFileName))
	if err != nil {
		t.Fatalf("read %s: %v", persistFileName, err)
	}
	var f persistFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatalf("unmarshal %s: %v", persistFileName, err)
	}
	if len(f.Tunnels) != 2 {
		t.Fatalf("file holds %d tunnels, want 2: %+v", len(f.Tunnels), f.Tunnels)
	}
	byKey := map[string]persistedTunnel{}
	for _, res := range f.Tunnels {
		byKey[res.key()] = res
	}
	httpRes, ok := byKey["sub:alice:web"]
	if !ok {
		t.Fatalf("no http reservation for alice/web in %+v", f.Tunnels)
	}
	if httpRes.Type != protocol.TypeHTTP || httpRes.LocalPort != 3000 {
		t.Errorf("http reservation = %+v, want type http local port 3000", httpRes)
	}
	tcpRes, ok := byKey["tcp:4000"]
	if !ok {
		t.Fatalf("no tcp reservation for local port 4000 in %+v", f.Tunnels)
	}
	if tcpRes.PublicPort != tcpTun.PublicPort || tcpRes.ClientName != "alice" {
		t.Errorf("tcp reservation = %+v, want public port %d client alice", tcpRes, tcpTun.PublicPort)
	}

	// Simulate a restart: the client is gone (taking its live listener with
	// it, as a real disconnect does) and a fresh server reads the file.
	sess1.close()

	s2 := newPersistServer(t, cfg)
	s2.loadPersisted()

	p := s2.reg.persisted()
	if p == nil {
		t.Fatal("persisted() = nil after loadPersisted")
	}
	got := p.list()
	if len(got) != 2 {
		t.Fatalf("loaded %d reservations, want 2: %+v", len(got), got)
	}
	if !s2.ports.isReserved(tcpTun.PublicPort) {
		t.Errorf("port %d not reserved in the allocator after load", tcpTun.PublicPort)
	}
}

func TestPersistReawardsPortOnReconnect(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, TCPMin: 24200, TCPMax: 24299}

	s1 := newPersistServer(t, cfg)
	s1.loadPersisted()
	sess1, tuns1 := registerTunnels(t, s1, "alice",
		protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: 4444})
	port1 := firstTunnel(t, tuns1).PublicPort
	if port1 == 0 {
		t.Fatal("no public port awarded")
	}
	sess1.close() // client disconnect — not an unregister, the reservation stays

	s2 := newPersistServer(t, cfg)
	s2.loadPersisted()
	_, tuns2 := registerTunnels(t, s2, "alice",
		protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: 4444})
	if got := firstTunnel(t, tuns2).PublicPort; got != port1 {
		t.Fatalf("re-awarded port = %d, want the persisted %d", got, port1)
	}
}

func TestPersistReawardsUDPPortOnReconnect(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, TCPMin: 24400, TCPMax: 24499}

	s1 := newPersistServer(t, cfg)
	s1.loadPersisted()
	sess1, tuns1 := registerTunnels(t, s1, "alice",
		protocol.Tunnel{Type: protocol.TypeUDP, LocalPort: 5555})
	port1 := firstTunnel(t, tuns1).PublicPort
	if port1 == 0 {
		t.Fatal("no public port awarded")
	}
	sess1.close()

	s2 := newPersistServer(t, cfg)
	s2.loadPersisted()
	_, tuns2 := registerTunnels(t, s2, "alice",
		protocol.Tunnel{Type: protocol.TypeUDP, LocalPort: 5555})
	if got := firstTunnel(t, tuns2).PublicPort; got != port1 {
		t.Fatalf("re-awarded udp port = %d, want the persisted %d", got, port1)
	}
}

func TestPersistReawardsSubdomainOnReconnect(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, Domain: "aritun.test"}

	s1 := newPersistServer(t, cfg)
	s1.loadPersisted()
	sess1, tuns1 := registerTunnels(t, s1, "alice",
		protocol.Tunnel{Type: protocol.TypeHTTP, LocalPort: 3000, Subdomain: "web"})
	firstTunnel(t, tuns1)
	sess1.close()

	s2 := newPersistServer(t, cfg)
	s2.loadPersisted()

	// While the owner is away, nobody else may take the reserved subdomain.
	_, tunsOther := registerTunnels(t, s2, "bob",
		protocol.Tunnel{Type: protocol.TypeHTTP, LocalPort: 3001, Subdomain: "web"})
	if err := tunsOther[0].Error; err == "" {
		t.Fatal("bob was allowed to take alice's reserved subdomain")
	}

	// The owning client reconnecting keeps the URL.
	_, tuns2 := registerTunnels(t, s2, "alice",
		protocol.Tunnel{Type: protocol.TypeHTTP, LocalPort: 3000, Subdomain: "web"})
	got := firstTunnel(t, tuns2)
	if got.Subdomain != "web" {
		t.Fatalf("subdomain = %q, want web", got.Subdomain)
	}
	if want := "https://web.aritun.test"; got.PublicURL != want {
		t.Fatalf("public URL = %q, want %q", got.PublicURL, want)
	}
}

func TestPersistedPortNotIssuedToOtherTunnels(t *testing.T) {
	dir := t.TempDir()
	// Tiny range so the reserved port is easy to reason about.
	cfg := Config{DataDir: dir, TCPMin: 24500, TCPMax: 24509}

	s1 := newPersistServer(t, cfg)
	s1.loadPersisted()
	sess1, tuns1 := registerTunnels(t, s1, "alice",
		protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: 5555})
	reserved := firstTunnel(t, tuns1).PublicPort
	sess1.close()

	s2 := newPersistServer(t, cfg)
	s2.loadPersisted()

	// A different tunnel (other client, other local port) must never be
	// handed alice's reserved port, even though nothing is listening on it.
	_, tuns2 := registerTunnels(t, s2, "bob",
		protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: 6666})
	bob := firstTunnel(t, tuns2)
	if bob.PublicPort == reserved {
		t.Fatalf("bob was handed alice's reserved port %d", reserved)
	}

	// And alice still gets it back when she reconnects.
	_, tuns3 := registerTunnels(t, s2, "alice",
		protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: 5555})
	if got := firstTunnel(t, tuns3).PublicPort; got != reserved {
		t.Fatalf("alice's re-awarded port = %d, want the reserved %d", got, reserved)
	}
}

func TestPersistUnregisterReleasesReservation(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir, Domain: "aritun.test"}

	s := newPersistServer(t, cfg)
	s.loadPersisted()
	sess, tuns := registerTunnels(t, s, "alice",
		protocol.Tunnel{Type: protocol.TypeHTTP, LocalPort: 3000, Subdomain: "web"})
	tun := firstTunnel(t, tuns)

	// Explicit unregister releases the subdomain for good.
	sess.unregister([]string{tun.ID})

	_, tunsOther := registerTunnels(t, s, "bob",
		protocol.Tunnel{Type: protocol.TypeHTTP, LocalPort: 3001, Subdomain: "web"})
	if err := tunsOther[0].Error; err != "" {
		t.Fatalf("bob could not take web after alice unregistered: %s", err)
	}

	// The released reservation is gone from disk too — only bob's new one
	// remains under that subdomain.
	p := s.reg.persisted()
	for _, res := range p.list() {
		if res.Type == protocol.TypeHTTP && res.Subdomain == "web" && res.ClientName == "alice" {
			t.Fatalf("alice's web reservation still on record after unregister: %+v", res)
		}
	}
	if got := p.list(); len(got) != 1 || got[0].ClientName != "bob" {
		t.Fatalf("reservations after unregister = %+v, want only bob's web", got)
	}
}

func TestPersistLoadMissingAndCorrupt(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{DataDir: dir}

	// First run: no file, no reservations, no error.
	s := newPersistServer(t, cfg)
	s.loadPersisted()
	if p := s.reg.persisted(); p == nil || len(p.list()) != 0 {
		t.Fatalf("missing file: persisted() = %v, want an empty store", p)
	}

	// A corrupt file is discarded, not fatal.
	if err := os.WriteFile(filepath.Join(dir, persistFileName), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newPersistServer(t, cfg)
	s2.loadPersisted()
	if p := s2.reg.persisted(); p == nil || len(p.list()) != 0 {
		t.Fatalf("corrupt file: persisted() = %v, want an empty store", p)
	}
}
