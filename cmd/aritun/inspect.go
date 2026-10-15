package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// cmdInspect implements `aritun inspect`: it polls the admin API's
// /api/requests endpoint and prints a live feed of proxied requests. --follow
// keeps the stream open; otherwise it prints one snapshot and exits.
func cmdInspect(args []string) error {
	var g globals
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	admin := fs.String("admin", envOr("ARITUN_ADMIN", ""),
		"admin base URL; default: derived from --server (port 9090)")
	tunnel := fs.String("tunnel", "", "only show requests for this tunnel id")
	follow := fs.Bool("follow", false, "keep polling and print new requests as they arrive")
	interval := fs.Duration("interval", time.Second, "poll interval when --follow is set")
	raw := fs.Bool("json", false, "print raw JSON")
	g.register(fs)
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return err
	}
	if err := g.loadConfig(); err != nil {
		return err
	}

	base := *admin
	if base == "" {
		derived, err := adminURLFromServer(g.server)
		if err != nil {
			return fmt.Errorf("cannot derive the admin URL: %w (pass --admin explicitly)", err)
		}
		base = derived
	}
	base = strings.TrimRight(base, "/")

	seen := make(map[string]bool)
	httpc := &http.Client{Timeout: 10 * time.Second}

	fetch := func() ([]requestLog, int64, error) {
		url := base + "/api/requests"
		if *tunnel != "" {
			url += "?tunnel=" + *tunnel
		}
		resp, err := httpc.Get(url)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, 0, fmt.Errorf("server replied %s", resp.Status)
		}
		var payload struct {
			Total    int64        `json:"total"`
			Requests []requestLog `json:"requests"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return nil, 0, err
		}
		return payload.Requests, payload.Total, nil
	}

	if !*follow {
		logs, total, err := fetch()
		if err != nil {
			return err
		}
		if *raw {
			b, _ := json.MarshalIndent(map[string]any{"total": total, "requests": logs}, "", "  ")
			fmt.Println(string(b))
			return nil
		}
		fmt.Printf("%d request(s) total, %d shown:\n\n", total, len(logs))
		for _, l := range logs {
			printRequestLine(l)
		}
		return nil
	}

	// Follow mode: print anything new each poll.
	for _, l := range mustFetchAll(fetch) {
		seen[key(l)] = true
		printRequestLine(l)
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for range ticker.C {
		logs, _, err := fetch()
		if err != nil {
			fmt.Fprintln(os.Stderr, "inspect:", err)
			continue
		}
		for _, l := range logs {
			k := key(l)
			if !seen[k] {
				seen[k] = true
				printRequestLine(l)
			}
		}
	}
	return nil
}

type requestLog struct {
	Time      time.Time `json:"time"`
	Method    string    `json:"method"`
	URL       string    `json:"url"`
	Status    int       `json:"status"`
	Duration  int64     `json:"duration_ms"`
	Bytes     int64     `json:"bytes"`
	RemoteIP  string    `json:"remote_ip"`
	TunnelID  string    `json:"tunnel_id"`
	Subdomain string    `json:"subdomain"`
	Client    string    `json:"client"`
}

func key(l requestLog) string {
	return fmt.Sprintf("%d|%s|%s|%s", l.Time.UnixNano(), l.Method, l.URL, l.TunnelID)
}

func printRequestLine(l requestLog) {
	fmt.Printf("%s  %3d  %-6s %-40s %6s  %4dms  %-15s %s\n",
		l.Time.Format("15:04:05"), l.Status, l.Method, truncate(l.URL, 40),
		humanBytesInspect(l.Bytes), l.Duration, l.RemoteIP, l.Client)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func humanBytesInspect(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%dB", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func mustFetchAll(fetch func() ([]requestLog, int64, error)) []requestLog {
	logs, _, err := fetch()
	if err != nil {
		return nil
	}
	return logs
}
