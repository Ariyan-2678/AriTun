package server

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// rateLimiter is a simple token-bucket limiter. Each tunnel gets its own.
// Zero or negative rate means unlimited.
type rateLimiter struct {
	mu     sync.Mutex
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newRateLimiter(perSec int) *rateLimiter {
	if perSec <= 0 {
		return nil // unlimited
	}
	burst := float64(perSec)
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		rate:   float64(perSec),
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
	}
}

// allow takes one token, refilling based on elapsed time. It returns false
// when the caller should be rejected (429).
func (r *rateLimiter) allow() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(r.last).Seconds()
	r.last = now
	r.tokens += elapsed * r.rate
	if r.tokens > r.burst {
		r.tokens = r.burst
	}
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// bandwidthLimiter meters bytes across a tunnel with a token bucket the size
// of one second of budget. Zero or negative limit means unlimited.
type bandwidthLimiter struct {
	mu     sync.Mutex
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
}

func newBandwidthLimiter(bytesPerSec int64) *bandwidthLimiter {
	if bytesPerSec <= 0 {
		return nil
	}
	burst := float64(bytesPerSec)
	return &bandwidthLimiter{
		rate:   burst,
		burst:  burst,
		tokens: burst,
		last:   time.Now(),
	}
}

// wait blocks until n bytes of budget are available (or ctx is done).
// It returns ctx.Err() if the context expires first.
func (b *bandwidthLimiter) wait(ctx context.Context, n int) error {
	if b == nil || n <= 0 {
		return nil
	}
	for {
		b.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		b.last = now
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		if b.tokens >= float64(n) {
			b.tokens -= float64(n)
			b.mu.Unlock()
			return nil
		}
		// Not enough budget yet — compute how long to sleep.
		need := float64(n) - b.tokens
		sleep := time.Duration(need / b.rate * float64(time.Second))
		if sleep < time.Millisecond {
			sleep = time.Millisecond
		}
		b.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

// limitedConn wraps a net.Conn and throttles both directions.
type limitedConn struct {
	// embed io.ReadWriteCloser via net.Conn so the reverse proxy and pipe
	// keep working; we only intercept Read/Write.
	net.Conn
	bw *bandwidthLimiter
}

func (c *limitedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 && c.bw != nil {
		_ = c.bw.wait(context.Background(), n)
	}
	return n, err
}

func (c *limitedConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		// Chunk so a single huge Write cannot starve the bucket check.
		chunk := p
		if len(chunk) > 32*1024 {
			chunk = p[:32*1024]
		}
		if c.bw != nil {
			if err := c.bw.wait(context.Background(), len(chunk)); err != nil {
				return written, err
			}
		}
		n, err := c.Conn.Write(chunk)
		written += n
		if err != nil {
			return written, err
		}
		p = p[n:]
	}
	return written, nil
}

// ---- admin API limiter ----

// Defaults for the admin HTTP surface. The admin binds loopback by default,
// but it may be exposed (behind Caddy or directly), so every admin route is
// also rate limited per client IP as defense in depth. The numbers are named
// constants so tests can tighten them.
const (
	// adminRatePerSec is the sustained request rate allowed per client IP.
	// A few hundred requests per minute is far more than a single operator
	// (or the dashboard's own refresh polls) will ever need.
	adminRatePerSec = 10 // ~600 requests/minute
	// adminRateBurst is the immediate burst allowed per client IP, so a
	// page load or a status script can fire a handful of calls at once.
	adminRateBurst = 120
	// adminMaxClients bounds the per-IP table; past this many tracked
	// addresses the least-recently-seen ones are evicted.
	adminMaxClients = 4096
	// adminClientTTL forgets an idle client IP. Its bucket would have
	// refilled to full long before, so nothing is gained by keeping it.
	adminClientTTL = 5 * time.Minute
	// adminGCInterval is the minimum spacing between table sweeps.
	adminGCInterval = 30 * time.Second
	// adminGCTrigger forces a sweep once the table grows this large.
	adminGCTrigger = 512
)

// adminBucket is one client IP's token bucket inside an adminLimiter.
type adminBucket struct {
	tokens float64
	last   time.Time
}

// adminLimiter is a per-client-IP token bucket for the admin surface. A nil
// *adminLimiter allows everything, and setLimit lets tests tighten the rate
// and burst at runtime.
type adminLimiter struct {
	mu      sync.Mutex
	rate    float64 // tokens (requests) per second
	burst   float64
	clients map[string]*adminBucket
	lastGC  time.Time
}

// newAdminLimiter builds a limiter allowing perSec requests/second (burst)
// per client IP. A non-positive perSec means unlimited (nil).
func newAdminLimiter(perSec, burst int) *adminLimiter {
	if perSec <= 0 {
		return nil // unlimited
	}
	if burst < 1 {
		burst = 1
	}
	return &adminLimiter{
		rate:    float64(perSec),
		burst:   float64(burst),
		clients: make(map[string]*adminBucket),
	}
}

// setLimit replaces the rate and burst at runtime. All future allow decisions
// — for existing and new buckets alike — use the new numbers.
func (l *adminLimiter) setLimit(perSec, burst int) {
	if l == nil || perSec <= 0 {
		return
	}
	if burst < 1 {
		burst = 1
	}
	l.mu.Lock()
	l.rate, l.burst = float64(perSec), float64(burst)
	l.mu.Unlock()
}

// allow takes one request token for ip, refilling its bucket from the elapsed
// time. It returns false when the caller should answer 429.
func (l *adminLimiter) allow(ip string) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	l.gc(now)
	b, ok := l.clients[ip]
	if !ok {
		b = &adminBucket{tokens: l.burst, last: now}
		l.clients[ip] = b
	} else {
		b.tokens += now.Sub(b.last).Seconds() * l.rate
		b.last = now
	}
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// gc drops idle buckets and, past adminMaxClients, evicts the
// least-recently-seen addresses so the table stays memory-bounded no matter
// how many source addresses are thrown at it.
func (l *adminLimiter) gc(now time.Time) {
	if len(l.clients) < adminGCTrigger && now.Sub(l.lastGC) < adminGCInterval {
		return
	}
	l.lastGC = now
	for ip, b := range l.clients {
		if now.Sub(b.last) > adminClientTTL {
			delete(l.clients, ip)
		}
	}
	if len(l.clients) <= adminMaxClients {
		return
	}
	type seen struct {
		ip   string
		last time.Time
	}
	seenList := make([]seen, 0, len(l.clients))
	for ip, b := range l.clients {
		seenList = append(seenList, seen{ip, b.last})
	}
	sort.Slice(seenList, func(i, j int) bool { return seenList[i].last.Before(seenList[j].last) })
	for _, s := range seenList[:len(l.clients)-adminMaxClients] {
		delete(l.clients, s.ip)
	}
}
