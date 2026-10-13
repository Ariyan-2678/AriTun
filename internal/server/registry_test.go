package server

import (
	"strings"
	"testing"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

func TestValidSubdomain(t *testing.T) {
	good := []string{"demo", "swift-fox-42", "a", "p3000", "my.app", "0", "x-y-z"}
	for _, s := range good {
		if err := ValidSubdomain(s); err != nil {
			t.Errorf("ValidSubdomain(%q) = %v, want nil", s, err)
		}
	}

	bad := []string{
		"", "Demo", "demo app", "demo.app!", "demo_app",
		"-demo", "demo-", "demo..app", ".", "a.b.",
		strings.Repeat("a", 64), strings.Repeat("a.", 130) + "a",
		`"><script>`, "demo/app", "demo:80",
	}
	for _, s := range bad {
		if err := ValidSubdomain(s); err == nil {
			t.Errorf("ValidSubdomain(%q) = nil, want error", s)
		}
	}
}

// Host routing folds the request Host to lowercase, so registration must too
// or "Demo" would never match a request for "demo.example.com".
func TestRegistryLowercasesSubdomain(t *testing.T) {
	r := newRegistry()
	tun := &Tunnel{Tunnel: protocol.Tunnel{
		ID:        "t_1",
		Type:      protocol.TypeHTTP,
		LocalPort: 3000,
		Subdomain: "Demo",
	}}
	if err := r.Add(tun); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if tun.Subdomain != "demo" {
		t.Fatalf("Subdomain = %q, want demo", tun.Subdomain)
	}
	if r.BySubdomain("demo") == nil {
		t.Fatal("BySubdomain(demo) = nil after registering Demo")
	}
}

func TestRegistryRejectsBadSubdomain(t *testing.T) {
	r := newRegistry()
	tun := &Tunnel{Tunnel: protocol.Tunnel{
		ID:        "t_1",
		Type:      protocol.TypeHTTP,
		LocalPort: 3000,
		Subdomain: `evil"><img src=x onerror=alert(1)>`,
	}}
	if err := r.Add(tun); err == nil {
		t.Fatal("Add accepted a subdomain with markup")
	}
	if r.BySubdomain(`evil"><img src=x onerror=alert(1)>`) != nil {
		t.Fatal("bad subdomain was indexed")
	}
}

func TestRegistryDuplicateSubdomainAfterLowercase(t *testing.T) {
	r := newRegistry()
	a := &Tunnel{Tunnel: protocol.Tunnel{ID: "t_1", Type: protocol.TypeHTTP, LocalPort: 1, Subdomain: "Demo"}}
	b := &Tunnel{Tunnel: protocol.Tunnel{ID: "t_2", Type: protocol.TypeHTTP, LocalPort: 2, Subdomain: "demo"}}
	if err := r.Add(a); err != nil {
		t.Fatalf("Add(a): %v", err)
	}
	if err := r.Add(b); err == nil {
		t.Fatal("Add(demo) succeeded after Demo was registered")
	}
}
