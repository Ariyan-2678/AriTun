package server

import (
	"path/filepath"
	"testing"
	"time"
)

// Regression: named tokens must be able to carry the udp permission. It was
// missing from validatePerms, so POST /api/tokens with permissions ["udp"]
// was rejected even though PermUDP exists and the root token grants it.
func TestValidatePermsAcceptsUDP(t *testing.T) {
	for _, perms := range [][]string{
		{PermUDP},
		{PermHTTP, PermTCP, PermMulti, PermUDP},
		{"*"},
	} {
		if err := validatePerms(perms); err != nil {
			t.Errorf("validatePerms(%v) = %v, want nil", perms, err)
		}
	}
	if err := validatePerms([]string{"bogus"}); err == nil {
		t.Error("validatePerms([bogus]) = nil, want error")
	}
	if err := validatePerms(nil); err == nil {
		t.Error("validatePerms(nil) = nil, want error")
	}
}

// Add stamps the store's default TTL as an expiry, and an expired token is
// treated as absent by lookup (so checkToken rejects it with no changes there).
func TestTokenTTLExpiryAndLookup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tokens.json")
	ts := newTokenStore(path)
	ts.defaultTTL = time.Hour

	secret, err := ts.Add("web", []string{PermHTTP, PermUDP})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	rec := ts.lookup(secret)
	if rec == nil {
		t.Fatal("lookup after Add = nil, want the record")
	}
	if rec.ExpiresAt == nil {
		t.Fatal("Add with positive TTL did not stamp ExpiresAt")
	}
	if rec.expired() {
		t.Error("fresh token reported expired")
	}

	// Force the expiry into the past: lookup must now reject it.
	past := time.Now().Add(-time.Minute)
	ts.mu.Lock()
	ts.records[secret].ExpiresAt = &past
	ts.mu.Unlock()
	if got := ts.lookup(secret); got != nil {
		t.Errorf("lookup of expired token = %v, want nil", got)
	}
}

// rotate issues a fresh secret, keeps the name/permissions, and revokes the old
// secret.
func TestTokenRotate(t *testing.T) {
	ts := newTokenStore(filepath.Join(t.TempDir(), "tokens.json"))
	orig, err := ts.Add("ci", []string{PermTCP})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	rotated, err := ts.rotate("ci")
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rotated == orig {
		t.Error("rotate returned the same secret")
	}
	if ts.lookup(orig) != nil {
		t.Error("old secret still resolves after rotate")
	}
	rec := ts.lookup(rotated)
	if rec == nil {
		t.Fatal("rotated secret does not resolve")
	}
	if rec.Name != "ci" {
		t.Errorf("rotated name = %q, want ci", rec.Name)
	}
	if len(rec.Permissions) != 1 || rec.Permissions[0] != PermTCP {
		t.Errorf("rotated permissions = %v, want [tcp]", rec.Permissions)
	}
	if _, err := ts.rotate("nope"); err == nil {
		t.Error("rotate of unknown name = nil error, want error")
	}
}
