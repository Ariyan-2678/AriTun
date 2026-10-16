package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// persistFileName is the reservations file inside Config.DataDir.
const persistFileName = "tunnels.json"

// persistFileVersion is written into the file so a future format change can
// detect and migrate old data.
const persistFileVersion = 1

// persistedTunnel is one tunnel reservation: enough to re-award the same
// subdomain or public port when the owning client reconnects after a restart.
type persistedTunnel struct {
	ClientName string `json:"client_name,omitempty"`
	Type       string `json:"type"`
	Subdomain  string `json:"subdomain,omitempty"`
	PublicPort int    `json:"public_port,omitempty"`
	LocalPort  int    `json:"local_port,omitempty"`
}

// key identifies the reservation. tcp/udp reservations belong to the local
// port — a reconnecting client may have changed its --name but the service
// behind the tunnel is the same — while http/multi reservations belong to the
// client name plus the subdomain the public URL is built from.
func (res persistedTunnel) key() string {
	switch res.Type {
	case protocol.TypeTCP, protocol.TypeUDP:
		return res.Type + ":" + strconv.Itoa(res.LocalPort)
	default:
		return "sub:" + res.ClientName + ":" + res.Subdomain
	}
}

// persistFile is the on-disk envelope for the reservation set.
type persistFile struct {
	Version int               `json:"version"`
	Tunnels []persistedTunnel `json:"tunnels"`
}

// persistStore keeps the live reservation set and mirrors it to a JSON file.
// All methods are safe for concurrent use.
type persistStore struct {
	mu      sync.Mutex
	path    string
	tunnels map[string]persistedTunnel
}

func newPersistStore(path string) *persistStore {
	return &persistStore{path: path, tunnels: make(map[string]persistedTunnel)}
}

// load reads the reservations file into the store. A missing file (first run)
// is fine; a corrupt or unreadable one is discarded so the server still boots.
func (p *persistStore) load(log *slog.Logger) {
	b, err := os.ReadFile(p.path)
	if err != nil {
		if !os.IsNotExist(err) && log != nil {
			log.Warn("read persisted tunnels", "file", p.path, "err", err)
		}
		return
	}
	var f persistFile
	if err := json.Unmarshal(b, &f); err != nil {
		if log != nil {
			log.Warn("discard corrupt persisted tunnels", "file", p.path, "err", err)
		}
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, res := range f.Tunnels {
		switch res.Type {
		case protocol.TypeHTTP, protocol.TypeMulti, protocol.TypeTCP, protocol.TypeUDP:
			p.tunnels[res.key()] = res
		}
	}
}

// list returns a snapshot of the reservation set, sorted by key.
func (p *persistStore) list() []persistedTunnel {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]persistedTunnel, 0, len(p.tunnels))
	for _, res := range p.tunnels {
		out = append(out, res)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out
}

// upsert records (or refreshes) one reservation and saves the set.
func (p *persistStore) upsert(res persistedTunnel) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tunnels[res.key()] = res
	return p.saveLocked()
}

// remove drops the reservation matching res's key and saves the set.
func (p *persistStore) remove(res persistedTunnel) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tunnels, res.key())
	return p.saveLocked()
}

// claim returns the reservation for typ+localPort, if one holds a usable
// public port. The reservation stays on record — a later restart re-awards it
// again — but only when the port is still actually claimable.
func (p *persistStore) claim(typ string, localPort int) (persistedTunnel, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	res, ok := p.tunnels[persistedTunnel{Type: typ, LocalPort: localPort}.key()]
	if !ok || res.PublicPort == 0 {
		return persistedTunnel{}, false
	}
	return res, true
}

// peek returns a copy of the reservation stored under res's key, without
// touching anything. rollBack uses it to snapshot the record that a Registry
// removal is about to erase.
func (p *persistStore) peek(res persistedTunnel) (persistedTunnel, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	got, ok := p.tunnels[res.key()]
	return got, ok
}

// portAvailableFor probes whether the port can actually be bound for typ.
// TCP wants a listen socket, UDP a packet socket: probing a UDP reservation
// with a TCP probe could drop a perfectly usable reservation (or keep one a
// future udp bind could never honour).
func portAvailableFor(typ string, port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	if typ == protocol.TypeUDP {
		pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
		if err != nil {
			return false
		}
		pc.Close()
		return true
	}
	return portFree(port)
}

// subdomainReservedFor reports whether an http/multi subdomain is held by a
// reservation belonging to a different client name.
func (p *persistStore) subdomainReservedFor(clientName, sub string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, res := range p.tunnels {
		if res.Type != protocol.TypeHTTP && res.Type != protocol.TypeMulti {
			continue
		}
		if res.Subdomain == sub && res.ClientName != clientName {
			return true
		}
	}
	return false
}

// save mirrors the set to disk.
func (p *persistStore) save() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.saveLocked()
}

// saveLocked mirrors the set to disk. p.mu must be held.
func (p *persistStore) saveLocked() error {
	list := make([]persistedTunnel, 0, len(p.tunnels))
	for _, res := range p.tunnels {
		list = append(list, res)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].key() < list[j].key() })
	b, err := json.MarshalIndent(persistFile{Version: persistFileVersion, Tunnels: list}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p.path, b, 0o600)
}

// loadPersisted reads the tunnel reservations saved under Config.DataDir and
// reserves their public ports so the port allocator cannot hand them to a
// different tunnel before the owning client reconnects. Call it once at
// startup, from New or Run, before any client is served. A missing file (first
// run) is not an error.
func (s *Server) loadPersisted() {
	path := filepath.Join(s.cfg.DataDir, persistFileName)
	p := newPersistStore(path)
	p.load(s.log)

	pruned := 0
	for _, res := range p.list() {
		if res.PublicPort == 0 {
			continue
		}
		switch {
		case res.PublicPort < s.cfg.TCPMin || res.PublicPort > s.cfg.TCPMax:
			// Outside the configured range: we could never re-bind it.
			_ = p.remove(res)
			pruned++
		case s.reg.ByPublicPort(res.PublicPort) != nil, s.ports.isReserved(res.PublicPort):
			// Already held by a live tunnel or an earlier load pass.
		case !portAvailableFor(res.Type, res.PublicPort):
			// Occupied by something outside this server; the reservation can
			// never be honoured, so drop it rather than block the port.
			_ = p.remove(res)
			pruned++
		default:
			s.ports.reserve(res.PublicPort)
		}
	}
	s.reg.setPersist(p)

	count := len(p.list())
	if pruned > 0 {
		_ = p.save()
	}
	if count > 0 || pruned > 0 {
		s.log.Info("tunnel reservations loaded", "file", path, "count", count, "pruned", pruned)
	}
}

// persistTunnel records a successful registration so the same subdomain or
// public port can be re-awarded after a restart. Failures are logged, never
// fatal: losing a reservation must not break a live tunnel.
func (s *Server) persistTunnel(t *Tunnel) {
	p := s.reg.persisted()
	if p == nil {
		return
	}
	res := persistedTunnel{
		Type:       t.Type,
		Subdomain:  t.Subdomain,
		PublicPort: t.PublicPort,
		LocalPort:  t.LocalPort,
	}
	if t.Session != nil {
		res.ClientName = t.Session.name
	}
	if err := p.upsert(res); err != nil {
		s.log.Warn("persist tunnel", "tunnel", t.ID, "err", err)
	}
}

// claimPersistedPort re-awards the public port reserved for typ+localPort, if
// any, so a reconnecting tcp/udp client keeps the same port. The reservation
// stays on record but leaves the allocator's reserved set: the port is now
// owned by a live tunnel.
func (s *Server) claimPersistedPort(typ string, localPort int) (int, bool) {
	p := s.reg.persisted()
	if p == nil || localPort < 1 {
		return 0, false
	}
	res, ok := p.claim(typ, localPort)
	if !ok {
		return 0, false
	}
	if res.PublicPort < s.cfg.TCPMin || res.PublicPort > s.cfg.TCPMax || !portAvailableFor(typ, res.PublicPort) {
		return 0, false
	}
	s.ports.unreserve(res.PublicPort)
	return res.PublicPort, true
}

// rollBack removes a tunnel whose listener failed to start. Registry.Remove
// also erases the tunnel's persisted reservation — which may be a record this
// identity re-claimed from before a restart — so the record is snapshotted
// before the removal and written back afterwards. A transient bind failure
// must not permanently delete someone's stable URL or port.
func (s *Server) rollBack(t *Tunnel) {
	p := s.reg.persisted()
	var prior persistedTunnel
	var had bool
	if p != nil && t.Session != nil {
		prior, had = p.peek(persistedTunnel{
			ClientName: t.Session.name,
			Type:       t.Type,
			Subdomain:  t.Subdomain,
			LocalPort:  t.LocalPort,
		})
	}

	s.reg.Remove(t.ID)

	if !had || prior.PublicPort == 0 {
		return
	}
	// claimPersistedPort already unreserved the port before the listener
	// failed; put it back under reservation so another client cannot grab it
	// while the owner retries.
	if (prior.Type == protocol.TypeTCP || prior.Type == protocol.TypeUDP) &&
		!s.ports.isReserved(prior.PublicPort) && portAvailableFor(prior.Type, prior.PublicPort) {
		s.ports.reserve(prior.PublicPort)
	}
	if err := p.upsert(prior); err != nil {
		s.log.Warn("restore reservation after rollback", "tunnel", t.ID, "err", err)
	}
}

// subdomainReservedFor reports whether sub is held by a persisted reservation
// belonging to a different client — the owning client has not reconnected yet
// after a restart, so no one else may take the URL.
func (s *Server) subdomainReservedFor(clientName, sub string) bool {
	p := s.reg.persisted()
	if p == nil {
		return false
	}
	return p.subdomainReservedFor(clientName, sub)
}
