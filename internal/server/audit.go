package server

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// auditRingSize bounds how many administrative actions are kept in memory.
const auditRingSize = 1000

// auditDetailCap bounds the free-text parts of an entry so a hostile or buggy
// caller cannot bloat the ring or the file sink.
const auditDetailCap = 256

// AuditEntry is one administrative action, e.g. pausing a tunnel or minting a
// token. Secrets never reach an entry: call sites pass masked values
// (maskToken) for anything token-shaped.
type AuditEntry struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	Actor  string    `json:"actor"`
	Target string    `json:"target,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// AuditLog keeps a bounded ring of recent administrative actions in memory
// and, when a sink is configured, appends every entry to a file as JSON lines.
// It is safe for concurrent use.
type AuditLog struct {
	mu   sync.Mutex
	ring []AuditEntry
	next int
	size int
	file *os.File
}

// newAuditLog builds a ring-only audit log of the given capacity; size <= 0
// selects auditRingSize.
func newAuditLog(size int) *AuditLog {
	if size <= 0 {
		size = auditRingSize
	}
	return &AuditLog{ring: make([]AuditEntry, size), size: size}
}

// setSink starts appending entries to path as JSON lines, replacing any
// previous sink. An empty path removes the sink and leaves the ring intact.
func (a *AuditLog) setSink(path string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		a.file.Close()
		a.file = nil
	}
	if path == "" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("audit log dir: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("audit log %s: %w", path, err)
	}
	a.file = f
	return nil
}

// Add stores an entry in the ring and, when a file sink is configured, appends
// it as one JSON line. A sink error is returned but the entry is still kept in
// memory, so auditing degrades instead of failing the action that was logged.
func (a *AuditLog) Add(e AuditEntry) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Target = truncateAudit(e.Target)
	e.Detail = truncateAudit(e.Detail)

	a.mu.Lock()
	defer a.mu.Unlock()
	a.ring[a.next] = e
	a.next = (a.next + 1) % a.size
	if a.file == nil {
		return nil
	}
	b, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	if _, err := a.file.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	return nil
}

// Recent returns up to n of the newest entries, oldest first. n <= 0 returns
// the whole ring.
func (a *AuditLog) Recent(n int) []AuditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n <= 0 || n > a.size {
		n = a.size
	}
	out := make([]AuditEntry, 0, n)
	for i := n - 1; i >= 0; i-- {
		idx := (a.next - 1 - i + a.size*2) % a.size
		e := a.ring[idx]
		if e.Time.IsZero() {
			continue // empty slot
		}
		out = append(out, e)
	}
	return out
}

// Close releases the file sink. The ring stays usable.
func (a *AuditLog) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file == nil {
		return nil
	}
	err := a.file.Close()
	a.file = nil
	if err != nil {
		return fmt.Errorf("close audit log: %w", err)
	}
	return nil
}

func truncateAudit(s string) string {
	if len(s) > auditDetailCap {
		// ToValidUTF8 keeps the cut from leaving half a rune behind.
		return strings.ToValidUTF8(s[:auditDetailCap], "") + "…"
	}
	return s
}

var (
	auditMu        sync.Mutex
	auditSingleton *AuditLog
)

// globalAudit returns the package-wide audit log, creating it on first use so
// the admin handlers work even when InitAudit was never called.
func globalAudit() *AuditLog {
	auditMu.Lock()
	defer auditMu.Unlock()
	if auditSingleton == nil {
		auditSingleton = newAuditLog(auditRingSize)
	}
	return auditSingleton
}

// InitAudit points the package-wide audit log at path, replacing any previous
// file sink; an empty path keeps the in-memory ring only. aritund calls it
// from --audit-log before the server starts.
func InitAudit(path string) error {
	return globalAudit().setSink(path)
}

// audit records an administrative action against the package-wide audit log.
// r identifies the caller and may be nil for actions that do not ride an HTTP
// request. Callers must pass masked secrets (maskToken), never raw tokens.
// Defined here so the handlers in admin.go — and later any hook wired into
// server.go — share one entry point.
func (s *Server) audit(r *http.Request, action, target, detail string) {
	e := AuditEntry{
		Time:   time.Now(),
		Action: action,
		Actor:  actorOf(r),
		Target: target,
		Detail: detail,
	}
	if err := globalAudit().Add(e); err != nil && s != nil && s.log != nil {
		s.log.Warn("audit entry not persisted", "action", action, "err", err)
	}
}

// actorOf best-effort identifies who performed an action: the forwarded client
// address, the peer address, or "admin" when there is no request at all.
func actorOf(r *http.Request) string {
	if r == nil {
		return "admin"
	}
	if ip := visitorIP(r.Header.Get("X-Forwarded-For"), r.RemoteAddr); ip.IsValid() {
		return ip.String()
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || host == "" {
		return "admin"
	}
	return host
}
