package main

import (
	"strings"
	"testing"
)

// The infrastructure ports --server and --proxy point at must never end up in
// the published set, no matter how they were reached (env var or flag).
func TestInfrastructurePortsAreExcluded(t *testing.T) {
	cases := []struct {
		name   string
		server string
		proxy  string
		want   []int
	}{
		{"raw server", "1.2.3.4:9000", "", []int{9000}},
		{"raw server + proxy", "1.2.3.4:9000", "socks5://127.0.0.1:10808", []int{9000, 10808}},
		{"bare host:port proxy", "1.2.3.4:9000", "127.0.0.1:10808", []int{9000, 10808}},
		{"ipv6 server", "[::1]:9443", "", []int{9443}},
		{"websocket server keeps only host part", "wss://t.example.com/control", "", nil},
		{"unparseable is ignored", "not-a-host-port", "", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := globals{server: tc.server, proxy: tc.proxy}
			opts := discoveryOptions(g, map[int]bool{})

			for _, port := range tc.want {
				if !opts.Exclude[port] {
					t.Errorf("port %d should be excluded (server=%q proxy=%q)",
						port, tc.server, tc.proxy)
				}
			}
		})
	}
}

func TestDiscoveryOptionsNeverNilsExclude(t *testing.T) {
	// A caller passing nil must still get a usable map, otherwise the
	// assignment below would panic.
	opts := discoveryOptions(globals{server: "1.2.3.4:9000"}, nil)
	if opts.Exclude == nil {
		t.Fatal("Exclude must not be nil")
	}
	if !opts.Exclude[9000] {
		t.Error("control port missing from Exclude")
	}
}

func TestUserExcludeIsPreserved(t *testing.T) {
	opts := discoveryOptions(globals{server: "1.2.3.4:9000"}, map[int]bool{445: true})
	if !opts.Exclude[445] {
		t.Error("--exclude must survive alongside the automatic exclusions")
	}
	if !opts.Exclude[9000] {
		t.Error("control port missing")
	}
}

// normalizeArgs must keep `--proxy socks5://host:port` intact, since the value
// contains "://" and a colon.
func TestNormalizeArgsKeepsProxyValue(t *testing.T) {
	got := normalizeArgs([]string{"all", "--ports", "3000", "--proxy", "socks5://127.0.0.1:10808"})
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "socks5://127.0.0.1:10808") {
		t.Fatalf("proxy value was split: %q", joined)
	}
	if !strings.HasSuffix(joined, "all") && !strings.HasPrefix(joined, "--ports") {
		t.Fatalf("positional arg not preserved: %q", joined)
	}
}

// --include-ephemeral is a boolean; if normalizeArgs treats it as taking a
// value it would swallow the next token.
func TestNormalizeArgsTreatsIncludeEphemeralAsBool(t *testing.T) {
	got := normalizeArgs([]string{"all", "--include-ephemeral", "--ports", "3000"})
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "--include-ephemeral --ports 3000") &&
		!strings.Contains(joined, "--include-ephemeral  --ports 3000") {
		// After normalize, flags come first in original relative order.
		if strings.Contains(joined, "3000 --include-ephemeral") {
			t.Fatalf("--include-ephemeral swallowed a value: %q", joined)
		}
	}
	if !boolFlags["include-ephemeral"] {
		t.Fatal("include-ephemeral missing from boolFlags")
	}
}
