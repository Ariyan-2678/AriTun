package client

import (
	"math/rand/v2"
	"time"
)

// Reconnect curve: ~500ms base, doubling per consecutive failure up to ~30s,
// plus jitter so a fleet of agents hit by the same outage does not reconnect
// in lockstep.
const (
	backoffBase = 500 * time.Millisecond
	backoffCap  = 30 * time.Second
)

// backoff computes reconnect delays. It is deterministic when randFloat is
// injected (tests pass a constant), so the curve can be asserted without
// sleeping or depending on the global RNG.
type backoff struct {
	base time.Duration
	cap  time.Duration
	// attempt is the number of failures since the last reset.
	attempt int
	// randFloat returns a value in [0, 1]. Never nil after newBackoff.
	randFloat func() float64
}

func newBackoff() *backoff {
	return &backoff{
		base:      backoffBase,
		cap:       backoffCap,
		randFloat: rand.Float64,
	}
}

// next returns the delay to wait before the following attempt and advances
// the curve. The raw delay is base * 2^attempt capped at cap, then jittered
// into [d/2, d] (equal jitter): consecutive retries still spread out even at
// the cap, but a client never waits less than half the curve intends.
func (b *backoff) next() time.Duration {
	d := b.base
	for i := 0; i < b.attempt; i++ {
		if d >= b.cap/2 {
			d = b.cap
			break
		}
		d *= 2
	}
	b.attempt++
	if d > b.cap {
		d = b.cap
	}
	half := d / 2
	return half + time.Duration(b.randFloat()*float64(half))
}

// reset returns the curve to its base. Run calls it after a session that
// reached welcome/register: the server is reachable again, so the next drop
// deserves a short wait instead of a stale cap.
func (b *backoff) reset() { b.attempt = 0 }
