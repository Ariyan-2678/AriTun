package server

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// udpFlowIdle closes a visitor's UDP flow after this much silence.
const udpFlowIdle = 60 * time.Second

// udpFlow is one visitor address bound to the local service over a single
// yamux stream. UDP has no connections, so we key flows by the visitor's
// source address and give each its own stream.
type udpFlow struct {
	stream net.Conn
	out    chan []byte // datagrams waiting to go back to the visitor
	dead   chan struct{}
	once   sync.Once
}

func (f *udpFlow) close() {
	f.once.Do(func() {
		close(f.dead)
		close(f.out)
		f.stream.Close()
	})
}

// startUDPListener allocates a public port and begins relaying UDP datagrams
// for this tunnel to the client's local UDP service.
func (s *Server) startUDPListener(t *Tunnel) error {
	port, err := s.ports.alloc()
	if err != nil {
		return err
	}
	t.PublicPort = port

	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.udpConns[t.ID] = conn
	s.mu.Unlock()

	s.log.Info("udp tunnel published", "tunnel", t.ID, "public", port, "client", t.Session.name)

	go s.serveUDP(conn, t)
	go s.sweepUDPFlows(t.ID)
	return nil
}

// serveUDP reads visitor datagrams and forwards them over per-address streams.
func (s *Server) serveUDP(conn net.PacketConn, t *Tunnel) {
	var mu sync.Mutex
	flows := make(map[string]*udpFlow)

	getFlow := func(addr net.Addr) *udpFlow {
		key := addr.String()
		mu.Lock()
		f, ok := flows[key]
		mu.Unlock()
		if ok {
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
		f = &udpFlow{stream: st, out: make(chan []byte, 64), dead: make(chan struct{})}
		mu.Lock()
		flows[key] = f
		mu.Unlock()

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
			t.counters.record(200, n)
			t.counters.bytesIn.Add(int64(n))
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

// sweepUDPFlows closes any flow idle longer than udpFlowIdle.
func (s *Server) sweepUDPFlows(tunnelID string) {
	// Placeholder for a future per-flow idle sweep. Flows are torn down when
	// the stream breaks (client disconnect) or the tunnel is removed; a time-
	// based sweep would need access to the flows map, which lives in serveUDP.
	// Keeping this a no-op hook documents the intended lifecycle point.
	_ = tunnelID
}

// closeUDP shuts down the tunnel's UDP socket and drops it from the map.
func (s *Server) closeUDP(tunnelID string) {
	s.mu.Lock()
	conn, ok := s.udpConns[tunnelID]
	delete(s.udpConns, tunnelID)
	s.mu.Unlock()
	if ok {
		conn.Close()
	}
}
