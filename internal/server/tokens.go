package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Permission levels a token can carry.
const (
	PermHTTP  = "http"
	PermTCP   = "tcp"
	PermMulti = "multi"
	PermUDP   = "udp"
)

// allPerms is what the legacy single --token grants.
var allPerms = []string{PermHTTP, PermTCP, PermMulti, PermUDP}

// TokenInfo is what checkToken hands back for a matched token.
type TokenInfo struct {
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
}

// Has reports whether the token may register a tunnel of the given type.
func (t *TokenInfo) Has(perm string) bool {
	if t == nil {
		return true // no token system in play — allow everything
	}
	for _, p := range t.Permissions {
		if p == perm || p == "*" {
			return true
		}
	}
	return false
}

// TokenRecord is one entry persisted in tokens.json.
type TokenRecord struct {
	Name        string    `json:"name"`
	Token       string    `json:"token"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	// ExpiresAt is when the token stops working. Nil means it never expires.
	// Expired records stay in tokens.json (visible to List) but lookup
	// rejects them, so checkToken/resolveToken need no expiry logic.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// expired reports whether the token's TTL has elapsed.
func (r *TokenRecord) expired() bool {
	return r.ExpiresAt != nil && !time.Now().Before(*r.ExpiresAt)
}

// defaultTokenTTL is the lifetime newTokenStore stamps onto freshly created
// (and rotated) tokens. Set with SetDefaultTokenTTL before server.New.
var (
	defaultTTLMu    sync.RWMutex
	defaultTokenTTL time.Duration
)

// SetDefaultTokenTTL sets the lifetime applied to newly created named
// tokens; zero means tokens never expire. Call it before server.New so the
// token store picks it up at construction.
func SetDefaultTokenTTL(d time.Duration) {
	defaultTTLMu.Lock()
	defaultTokenTTL = d
	defaultTTLMu.Unlock()
}

// tokenStore is a file-backed list of named tokens with per-type permissions.
// It complements (does not replace) the single Config.Token, which keeps
// working as a root token with every permission, so existing setups do not
// break.
type tokenStore struct {
	mu      sync.RWMutex
	path    string
	records map[string]*TokenRecord // keyed by token value
	// defaultTTL is applied by Add (and rotate) when > 0; zero means
	// tokens never expire.
	defaultTTL time.Duration
}

func newTokenStore(path string) *tokenStore {
	ts := &tokenStore{path: path, records: make(map[string]*TokenRecord)}
	defaultTTLMu.RLock()
	ts.defaultTTL = defaultTokenTTL
	defaultTTLMu.RUnlock()
	ts.load()
	return ts
}

func (ts *tokenStore) load() {
	if ts.path == "" {
		return
	}
	b, err := os.ReadFile(ts.path)
	if err != nil {
		return
	}
	var list []TokenRecord
	if err := json.Unmarshal(b, &list); err != nil {
		return
	}
	for i := range list {
		rec := list[i]
		if rec.Token == "" {
			continue
		}
		ts.records[rec.Token] = &rec
	}
}

func (ts *tokenStore) save() error {
	if ts.path == "" {
		return nil
	}
	list := make([]TokenRecord, 0, len(ts.records))
	for _, r := range ts.records {
		list = append(list, *r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ts.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(ts.path, b, 0o600)
}

// Add persists a new token and returns the generated secret. When the
// store's defaultTTL is positive the token expires that long after
// creation.
func (ts *tokenStore) Add(name string, perms []string) (string, error) {
	if name == "" {
		return "", errors.New("token name required")
	}
	if err := validatePerms(perms); err != nil {
		return "", err
	}
	secret, err := randomToken()
	if err != nil {
		return "", err
	}
	now := time.Now()
	rec := &TokenRecord{
		Name:        name,
		Token:       secret,
		Permissions: perms,
		CreatedAt:   now,
	}
	if ttl := ts.defaultTTL; ttl > 0 {
		exp := now.Add(ttl)
		rec.ExpiresAt = &exp
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.records[secret] = rec
	return secret, ts.save()
}

// Remove revokes a token by its secret value.
func (ts *tokenStore) Remove(secret string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if _, ok := ts.records[secret]; !ok {
		return false
	}
	delete(ts.records, secret)
	ts.save()
	return true
}

// RemoveByName revokes every token registered under a name.
func (ts *tokenStore) RemoveByName(name string) int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	n := 0
	for k, r := range ts.records {
		if r.Name == name {
			delete(ts.records, k)
			n++
		}
	}
	if n > 0 {
		ts.save()
	}
	return n
}

// List returns all records sorted by creation time.
func (ts *tokenStore) List() []TokenRecord {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	out := make([]TokenRecord, 0, len(ts.records))
	for _, r := range ts.records {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// rotate issues a fresh secret for every token registered under name and
// revokes the old secret(s). Permissions and CreatedAt are preserved. When
// the store's defaultTTL is positive the new secret gets a fresh expiry
// (so rotate doubles as "renew"); otherwise the previous expiry, if any,
// is kept. The change is persisted like every other mutation.
func (ts *tokenStore) rotate(name string) (string, error) {
	if name == "" {
		return "", errors.New("token name required")
	}
	ts.mu.Lock()
	defer ts.mu.Unlock()
	var proto *TokenRecord
	for _, r := range ts.records {
		if r.Name == name {
			// Keep the newest record's permissions/expiry as the template.
			if proto == nil || r.CreatedAt.After(proto.CreatedAt) {
				proto = r
			}
		}
	}
	if proto == nil {
		return "", fmt.Errorf("token %q not found", name)
	}
	secret, err := randomToken()
	if err != nil {
		return "", err
	}
	for k, r := range ts.records {
		if r.Name == name {
			delete(ts.records, k)
		}
	}
	var exp *time.Time
	if ttl := ts.defaultTTL; ttl > 0 {
		now := time.Now()
		e := now.Add(ttl)
		exp = &e
	} else {
		exp = proto.ExpiresAt
	}
	ts.records[secret] = &TokenRecord{
		Name:        name,
		Token:       secret,
		Permissions: append([]string(nil), proto.Permissions...),
		CreatedAt:   proto.CreatedAt,
		ExpiresAt:   exp,
	}
	return secret, ts.save()
}

// lookup finds the record for a secret in constant time. Expired tokens
// are treated as absent, so callers (checkToken, resolveToken) reject them
// without any expiry logic of their own.
func (ts *tokenStore) lookup(secret string) *TokenRecord {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	// Constant-time scan over every record so a timing side channel cannot
	// reveal which token (if any) matched.
	var found *TokenRecord
	for tok, rec := range ts.records {
		if subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1 {
			found = rec
		}
	}
	if found != nil && found.expired() {
		return nil
	}
	return found
}

func validatePerms(perms []string) error {
	if len(perms) == 0 {
		return fmt.Errorf("at least one permission required (%s, %s, %s, %s, or *)", PermHTTP, PermTCP, PermMulti, PermUDP)
	}
	for _, p := range perms {
		switch p {
		case PermHTTP, PermTCP, PermMulti, PermUDP, "*":
		default:
			return fmt.Errorf("unknown permission %q", p)
		}
	}
	return nil
}

func randomToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// maskToken redacts the middle of a token so the dashboard can show a hint
// without leaking the secret.
func maskToken(t string) string {
	if len(t) <= 8 {
		return "****"
	}
	return t[:4] + "…" + t[len(t)-4:]
}
