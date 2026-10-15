package server

import (
	"context"
	"net"
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
