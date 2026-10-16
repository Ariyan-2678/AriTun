package server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// udpFlowIdle closes a visitor's UDP flow after this much silence, so a
// visitor that sent one datagram and vanished releases its yamux stream.
const udpFlowIdle = 60 * time.Second

// udpSweepInterval is how often stale flows are swept.
const udpSweepInterval = 15 * time.Second

// udpFlow is one visitor address bound to the local service over a single
// yamux stream. UDP has no connections, so we key flows by the visitor's
// source address and give each its own stream.
type udpFlow struct {
	addr   string
	stream net.Conn
	out    chan []byte // datagrams waiting to go back to the visitor
	dead   chan struct{}
	once   sync.Once
	onDead func()
}

// close tears the flow down and runs its eviction hook exactly once, from
// whichever goroutine triggered the close (idle sweep, writer error or
// stream end). Without the eviction a dead flow stays in the table and its
// address falls silent forever.
func (f *udpFlow) close() {
	f.once.Do(func() {
		close(f.dead)
		close(f.out)
		f.stream.Close()
		if f.onDead != nil {
			f.onDead()
		}
	})
}

// udpFlowTable tracks a tunnel's visitor flows and their last-active times.
// serveUDP's reader creates and touches entries while the sweeper and the
// evict-on-death hooks remove them, so the maps are mutex-guarded.
type udpFlowTable struct {
	mu    sync.Mutex
	flows map[string]*udpFlow
	seen  map[string]time.Time
	done  chan struct{}
	once  sync.Once
}

func newUDPFlowTable() *udpFlowTable {
	return &udpFlowTable{
		flows: make(map[string]*udpFlow),
		seen:  make(map[string]time.Time),
		done:  make(chan struct{}),
	}
}

func (ft *udpFlowTable) touch(key string) {
	ft.mu.Lock()
	ft.seen[key] = time.Now()
	ft.mu.Unlock()
}

func (ft *udpFlowTable) get(key string) *udpFlow {
	ft.mu.Lock()
	f := ft.flows[key]
	ft.mu.Unlock()
	if f != nil {
		ft.touch(key)
	}
	return f
}

func (ft *udpFlowTable) put(key string, f *udpFlow) {
	ft.mu.Lock()
	ft.flows[key] = f
	ft.seen[key] = time.Now()
	ft.mu.Unlock()
}

// evict removes one flow's bookkeeping. Runs under the flow's once, so a
// flow closed by any path is also dropped from the maps.
func (ft *udpFlowTable) evict(key string) {
	ft.mu.Lock()
	delete(ft.flows, key)
	delete(ft.seen, key)
	ft.mu.Unlock()
}

// shutdown stops the sweeper and closes every live flow. Idempotent: both
// closeUDP and serveUDP's exit path can call it.
func (ft *udpFlowTable) shutdown() {
	ft.once.Do(func() {
		close(ft.done)
		ft.mu.Lock()
		flows := ft.flows
		ft.flows = make(map[string]*udpFlow)
		ft.seen = make(map[string]time.Time)
		ft.mu.Unlock()
		for _, f := range flows {
			f.close() // onDead re-enters evict on the emptied map, harmless
		}
	})
}

// startUDPListener allocates a public port and begins relaying UDP datagrams
// for this tunnel to the client's local UDP service.
func (s *Server) startUDPListener(t *Tunnel) error {
	port, err := s.ports.alloc()
	if err != nil {
		return err
	}
	return s.startUDPOnPort(t, port)
}

// startUDPListenerPort is startUDPListener for a re-awarded public port: the
// port came from a persisted reservation, so it must be bound as-is instead
// of going through the allocator.
func (s *Server) startUDPListenerPort(t *Tunnel, port int) error {
	return s.startUDPOnPort(t, port)
}

func (s *Server) startUDPOnPort(t *Tunnel, port int) error {
	t.PublicPort = port
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	table := newUDPFlowTable()

	s.mu.Lock()
	s.udpConns[t.ID] = conn
	s.udpFlows[t.ID] = table
	s.mu.Unlock()

	s.log.Info("udp tunnel published", "tunnel", t.ID, "public", port, "client", t.Session.name)

	go s.serveUDP(conn, t, table)
	go s.sweepUDPFlows(t, table)
	return nil
}

// serveUDP reads visitor datagrams and forwards them over per-address streams.
func (s *Server) serveUDP(conn net.PacketConn, t *Tunnel, table *udpFlowTable) {
	defer table.shutdown() // socket closed: drop flows, stop the sweeper

	getFlow := func(addr net.Addr) *udpFlow {
		key := addr.String()
		if f := table.get(key); f != nil {
			return f
		}

		// Open a fresh stream to the client for this visitor address.
		st, err := s.openUDPStream(t.ID, t.LocalPort)
		if err != nil {
			s.log.Debug("udp stream open failed", "tunnel", t.ID, "err", err)
			return nil
		}
		if t.bwLimiter != nil {
			st = &limitedConn{Conn: st, bw: t.bwLimiter}
		}
		f := &udpFlow{addr: key, stream: st, out: make(chan []byte, 64), dead: make(chan struct{})}
		f.onDead = func() { table.evict(key) }
		// serveUDP's reader is the only creator and the sweeper only closes
		// registered flows, which this one isn't yet, so no insertion race.
		table.put(key, f)

		go func() {
			// stream -> visitor
			for {
				dg, err := protocol.ReadDatagram(st)
				if err != nil {
					break
				}
				if _, err := conn.WriteTo(dg, addr); err != nil {
					break
				}
			}
			f.close()
		}()
		go func() {
			// flow.out -> stream
			for {
				select {
				case <-f.dead:
					return
				case dg, ok := <-f.out:
					if !ok {
						return
					}
					if err := protocol.WriteDatagram(st, dg); err != nil {
						f.close()
						return
					}
				}
			}
		}()
		return f
	}

	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return // socket closed
		}
		if t.paused.Load() {
			continue
		}
		if !checkACL(mustAddr(addr.String()), t.allowPrefixes, t.denyPrefixes) {
			continue
		}
		if t.counters != nil {
			// Inbound only: a datagram is not a request, so the request/bytesOut
			// counters must not move.
			t.counters.addIn(int64(n))
		}
		f := getFlow(addr)
		if f == nil {
			continue
		}
		// Non-blocking send: drop rather than stall if the visitor is faster
		// than the client.
		select {
		case <-f.dead:
		case f.out <- append([]byte(nil), buf[:n]...):
		default:
		}
	}
}

// sweepUDPFlows closes flows idle longer than udpFlowIdle. The loop ends when
// the flow table shuts down (UDP socket closed or tunnel removed).
func (s *Server) sweepUDPFlows(t *Tunnel, table *udpFlowTable) {
	ticker := time.NewTicker(udpSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-table.done:
			return
		case <-ticker.C:
		}

		cutoff := time.Now().Add(-udpFlowIdle)
		var stale []*udpFlow
		table.mu.Lock()
		for key, f := range table.flows {
			if last, ok := table.seen[key]; ok && last.Before(cutoff) {
				stale = append(stale, f)
			}
		}
		table.mu.Unlock()
		for _, f := range stale {
			s.log.Debug("udp flow idle, closed", "tunnel", t.ID, "addr", f.addr)
			f.close() // once-guarded; also evicts from the table
		}
	}
}

// closeUDP shuts down the tunnel's UDP socket, drops it from the maps and
// stops the flow table that hangs off it.
func (s *Server) closeUDP(tunnelID string) {
	s.mu.Lock()
	conn, okC := s.udpConns[tunnelID]
	table, okF := s.udpFlows[tunnelID]
	delete(s.udpConns, tunnelID)
	delete(s.udpFlows, tunnelID)
	s.mu.Unlock()
	if okF {
		table.shutdown()
	}
	if okC {
		conn.Close()
	}
}
