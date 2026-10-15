package server

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// Tunnel is a server-side view of a published endpoint plus the session that
// owns it.
type Tunnel struct {
	protocol.Tunnel
	Session *Session

	// compiled policy — built once at register time
	allowPrefixes []netip.Prefix
	denyPrefixes  []netip.Prefix

	// live enforcement state
	paused    bool
	limiter   *rateLimiter
	bwLimiter *bandwidthLimiter
	counters  *tunnelCounters
}

// Registry tracks every live tunnel and answers the routing lookups the public
// listeners need.
type Registry struct {
	mu sync.RWMutex

	byID         map[string]*Tunnel
	bySubdomain  map[string]*Tunnel
	byPublicPort map[int]*Tunnel
}

func newRegistry() *Registry {
	return &Registry{
		byID:         make(map[string]*Tunnel),
		bySubdomain:  make(map[string]*Tunnel),
		byPublicPort: make(map[int]*Tunnel),
	}
}

// Add indexes a tunnel, rejecting duplicate subdomains and public ports.
// HTTP subdomains are lowercased so routing (which folds Host to lower) always
// matches what was registered.
func (r *Registry) Add(t *Tunnel) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, dup := r.byID[t.ID]; dup {
		return fmt.Errorf("tunnel %s already registered", t.ID)
	}
	if t.Type == protocol.TypeHTTP || t.Type == protocol.TypeMulti {
		t.Subdomain = strings.ToLower(t.Subdomain)
		if err := ValidSubdomain(t.Subdomain); err != nil {
			return err
		}
		if _, dup := r.bySubdomain[t.Subdomain]; dup {
			return fmt.Errorf("subdomain %q is already in use", t.Subdomain)
		}
	}
	if t.Type == protocol.TypeTCP {
		if t.PublicPort == 0 {
			return fmt.Errorf("tcp tunnel %s has no public port", t.ID)
		}
		if _, dup := r.byPublicPort[t.PublicPort]; dup {
			return fmt.Errorf("public port %d is already in use", t.PublicPort)
		}
	}

	r.byID[t.ID] = t
	if t.Type == protocol.TypeHTTP || t.Type == protocol.TypeMulti {
		r.bySubdomain[t.Subdomain] = t
	}
	if t.Type == protocol.TypeTCP {
		r.byPublicPort[t.PublicPort] = t
	}
	return nil
}

// Remove deletes a tunnel and reports it.
func (r *Registry) Remove(id string) (*Tunnel, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	t, ok := r.byID[id]
	if !ok {
		return nil, false
	}
	delete(r.byID, id)
	if t.Subdomain != "" {
		delete(r.bySubdomain, t.Subdomain)
	}
	if t.PublicPort != 0 {
		delete(r.byPublicPort, t.PublicPort)
	}
	return t, true
}

// RemoveSession drops every tunnel owned by a session.
func (r *Registry) RemoveSession(s *Session) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	var removed []string
	for id, t := range r.byID {
		if t.Session != s {
			continue
		}
		delete(r.byID, id)
		if t.Subdomain != "" {
			delete(r.bySubdomain, t.Subdomain)
		}
		if t.PublicPort != 0 {
			delete(r.byPublicPort, t.PublicPort)
		}
		removed = append(removed, id)
	}
	return removed
}

// ByID looks up a tunnel by its id.
func (r *Registry) ByID(id string) *Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byID[id]
}

// BySubdomain looks up an http tunnel.
func (r *Registry) BySubdomain(sub string) *Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.bySubdomain[sub]
}

// ByPublicPort looks up a tcp tunnel.
func (r *Registry) ByPublicPort(port int) *Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byPublicPort[port]
}

// List returns the tunnels sorted by creation order proxy (id).
func (r *Registry) List() []*Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]*Tunnel, 0, len(r.byID))
	for _, t := range r.byID {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].Session.createdAt, out[j].Session.createdAt; !a.Equal(b) {
			return a.Before(b)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Count returns the number of live tunnels.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.byID)
}

// portAllocator hands out public ports for tcp tunnels inside a configured
// range, skipping anything already bound on this host.
type portAllocator struct {
	mu   sync.Mutex
	next int
	min  int
	max  int
}

func newPortAllocator(min, max int) *portAllocator {
	return &portAllocator{next: min, min: min, max: max}
}

// alloc reserves the next free port, verifying nothing is listening on it yet.
func (a *portAllocator) alloc() (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for i := 0; i <= a.max-a.min; i++ {
		port := a.next
		a.next++
		if a.next > a.max {
			a.next = a.min
		}
		if portFree(port) {
			return port, nil
		}
	}
	return 0, fmt.Errorf("no free ports left in range %d-%d", a.min, a.max)
}

func portFree(port int) bool {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// ValidSubdomain reports whether s is safe to embed in a public hostname and
// in the dashboard HTML. Only DNS labels of [a-z0-9-] are allowed (optionally
// separated by dots for multi-label names). Anything else — spaces, quotes,
// slashes, unicode — is rejected rather than escaped, so a hostile client
// cannot smuggle markup into the dashboard or a malformed Host into Caddy.
func ValidSubdomain(s string) error {
	if s == "" {
		return fmt.Errorf("subdomain required")
	}
	if len(s) > 253 {
		return fmt.Errorf("subdomain too long")
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid subdomain %q", s)
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid subdomain %q", s)
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("invalid subdomain %q: only a-z, 0-9 and '-' are allowed", s)
			}
		}
	}
	return nil
}
