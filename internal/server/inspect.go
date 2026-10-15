package server

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// RequestLog is one proxied request, kept for the inspector and the dashboard.
type RequestLog struct {
	Time      time.Time `json:"time"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Status    int       `json:"status"`
	Duration  int64     `json:"duration_ms"`
	Bytes     int64     `json:"bytes"`
	RemoteIP  string    `json:"remote_ip"`
	TunnelID  string    `json:"tunnel_id"`
	Subdomain string    `json:"subdomain,omitempty"`
	Client    string    `json:"client"`
}

// tunnelCounters accumulates per-tunnel lifetime totals for the dashboard and
// Prometheus.
type tunnelCounters struct {
	requests  atomic.Int64
	bytesIn   atomic.Int64
	bytesOut  atomic.Int64
	lastCode  atomic.Int32
	lastSeen  atomic.Int64 // unix nano
}

func (c *tunnelCounters) record(status, bytes int) {
	c.requests.Add(1)
	c.bytesOut.Add(int64(bytes))
	c.lastCode.Store(int32(status))
	c.lastSeen.Store(time.Now().UnixNano())
}

func (c *tunnelCounters) addIn(n int64) { c.bytesIn.Add(n) }

// inspector keeps a bounded ring of recent requests plus global counters.
type inspector struct {
	mu      sync.RWMutex
	ring    []RequestLog
	next    int
	size    int
	total   atomic.Int64
	sessions atomic.Int64
}

func newInspector(size int) *inspector {
	if size <= 0 {
		size = 500
	}
	return &inspector{
		ring: make([]RequestLog, size),
		size: size,
	}
}

func (in *inspector) record(rl RequestLog) {
	in.mu.Lock()
	in.ring[in.next] = rl
	in.next = (in.next + 1) % in.size
	in.mu.Unlock()
	in.total.Add(1)
}

// Recent returns up to n of the newest entries, oldest first.
func (in *inspector) Recent(n int) []RequestLog {
	in.mu.RLock()
	defer in.mu.RUnlock()
	if n <= 0 || n > in.size {
		n = in.size
	}
	// Collect the last `n` filled slots in chronological order.
	out := make([]RequestLog, 0, n)
	// next points at the slot that will be written next, so the newest is
	// at next-1.
	for i := n - 1; i >= 0; i-- {
		idx := (in.next - 1 - i + in.size*2) % in.size
		e := in.ring[idx]
		if e.Time.IsZero() {
			continue // empty slot
		}
		out = append(out, e)
	}
	return out
}

// countingWriter captures the status code and byte count of a proxied
// response so the inspector can log it.
type countingWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *countingWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p)
	w.bytes += int64(n)
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return n, err
}

// Flush forwards to the underlying writer so SSE and websockets keep working.
func (w *countingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func statusOf(w *countingWriter) int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// formatMethodURL gives a compact "GET /path" for the inspector line.
func formatMethodURL(r *http.Request) string {
	p := r.URL.Path
	if p == "" {
		p = "/"
	}
	if len(p) > 120 {
		p = p[:120] + "…"
	}
	return r.Method + " " + p
}
