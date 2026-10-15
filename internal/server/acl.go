package server

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// parseCIDRs compiles a list of CIDR strings (or bare IPs) into prefixes.
// Empty strings are skipped so trailing commas in flags do not fail.
func parseCIDRs(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		p, err := parseOneCIDR(e)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// parseOneCIDR accepts both "10.0.0.0/8" and a bare "10.0.0.1" (treated as
// a /32 or /128 host route), which is what people naturally type in --allow.
func parseOneCIDR(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// checkACL evaluates a visitor IP against compiled allow/deny lists.
// The rules, in order:
//  1. If the IP matches any deny entry, reject.
//  2. If the allow list is non-empty and the IP matches none of it, reject.
//  3. Otherwise allow.
//
// An empty allow list means "everyone not explicitly denied".
func checkACL(ip netip.Addr, allow, deny []netip.Prefix) bool {
	for _, p := range deny {
		if p.Contains(ip) {
			return false
		}
	}
	if len(allow) == 0 {
		return true
	}
	for _, p := range allow {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// visitorIP extracts the client address from a request, preferring
// X-Forwarded-For's first hop (what Caddy sets) and falling back to the
// remote address. Unparseable values yield the zero Addr.
func visitorIP(xff, remoteAddr string) netip.Addr {
	if xff != "" {
		// X-Forwarded-For may be a list: "client, proxy1, proxy2". The first
		// entry is the original client.
		first := xff
		if i := strings.IndexByte(xff, ','); i >= 0 {
			first = xff[:i]
		}
		if a, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil {
			return a
		}
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return a
	}
	return netip.Addr{}
}
