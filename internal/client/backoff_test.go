package client

import (
	"testing"
	"time"
)

// maxJitter pins randFloat to the top of the jitter band so the raw curve is
// observable exactly.
func maxJitter() *backoff {
	b := newBackoff()
	b.randFloat = func() float64 { return 1 }
	return b
}

// minJitter pins randFloat to the bottom of the jitter band.
func minJitter() *backoff {
	b := newBackoff()
	b.randFloat = func() float64 { return 0 }
	return b
}

func TestBackoffSequence(t *testing.T) {
	want := []time.Duration{
		500 * time.Millisecond,
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		backoffCap,
		backoffCap,
		backoffCap,
	}
	b := maxJitter()
	var prev time.Duration
	for i, w := range want {
		got := b.next()
		if got != w {
			t.Errorf("attempt %d: got %v, want %v", i, got, w)
		}
		if got < prev {
			t.Errorf("attempt %d: delay %v went backwards from %v", i, got, prev)
		}
		prev = got
	}
}

func TestBackoffCapped(t *testing.T) {
	b := maxJitter()
	var last time.Duration
	for i := 0; i < 100; i++ {
		last = b.next()
		if last > backoffCap {
			t.Fatalf("attempt %d: delay %v exceeds cap %v", i, last, backoffCap)
		}
	}
	if last != backoffCap {
		t.Errorf("after many failures got %v, want the cap %v", last, backoffCap)
	}
}

func TestBackoffJitterStaysInBand(t *testing.T) {
	// Cycle through the band so each delay must land in [raw/2, raw].
	vals := []float64{0, 0.25, 0.5, 0.75, 1}
	b := newBackoff()
	for i := 0; i < 20; i++ {
		b.randFloat = func() float64 { return vals[i%len(vals)] }
		raw := maxJitterAt(b.attempt)
		got := b.next()
		if got < raw/2 || got > raw {
			t.Errorf("attempt %d: jittered delay %v outside [%v, %v]", i, got, raw/2, raw)
		}
	}
}

// maxJitterAt computes the raw (unjittered) curve value for a given attempt
// counter without advancing any state.
func maxJitterAt(attempt int) time.Duration {
	b := maxJitter()
	b.attempt = attempt
	return b.next()
}

func TestBackoffReset(t *testing.T) {
	b := maxJitter()
	for i := 0; i < 5; i++ {
		b.next()
	}
	if got := b.next(); got != 16*time.Second {
		t.Fatalf("before reset: got %v, want 16s", got)
	}
	b.reset()
	if got := b.next(); got != 500*time.Millisecond {
		t.Fatalf("after reset: got %v, want 500ms", got)
	}
}
