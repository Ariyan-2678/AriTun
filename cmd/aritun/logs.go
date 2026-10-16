// aritun logs tails the server's request log: `aritun inspect` in tail -f
// clothing — one compact line per request, oldest first, following by default.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func cmdLogs(args []string) error {
	var g globals
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	admin := fs.String("admin", envOr("ARITUN_ADMIN", ""),
		"admin base URL; default: derived from --server (port 9090)")
	tunnel := fs.String("tunnel", "", "only show requests for this tunnel id")
	follow := true
	fs.BoolVar(&follow, "f", true, "keep polling and print new requests (use -f=false for one snapshot)")
	fs.BoolVar(&follow, "follow", true, "alias for -f")
	n := fs.Int("n", 20, "print the last N requests before following")
	interval := fs.Duration("interval", time.Second, "poll interval while following")
	g.register(fs)
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return err
	}
	if err := g.loadConfig(); err != nil {
		return err
	}
	if *n < 0 {
		return fmt.Errorf("--n must be >= 0")
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

	httpc := &http.Client{Timeout: 10 * time.Second}
	fetch := func() ([]requestLog, error) {
		target := base + "/api/requests"
		if *tunnel != "" {
			target += "?tunnel=" + url.QueryEscape(*tunnel)
		}
		resp, err := httpc.Get(target)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("server replied %s", resp.Status)
		}
		var payload struct {
			Requests []requestLog `json:"requests"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return nil, err
		}
		return payload.Requests, nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logs, err := fetch()
	if err != nil {
		return err
	}
	// tail -f semantics: start from the last --n lines, then stream. The
	// initial seen set must cover the whole ring, not just the printed tail —
	// otherwise the first tick re-prints every older buffered entry as new.
	seen := make(map[string]bool, len(logs))
	for _, l := range logs {
		seen[key(l)] = true
	}
	for _, l := range tailN(logs, *n) {
		printLogLine(l)
	}
	if !follow {
		return nil
	}

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			logs, err := fetch()
			if err != nil {
				fmt.Fprintln(os.Stderr, "logs:", err)
				continue
			}
			// The server hands back its bounded ring each poll, so swapping
			// the seen set for the current batch keeps a long-running tail's
			// memory flat; ring entries are chronological and never revive.
			next := make(map[string]bool, len(logs))
			for _, l := range logs {
				k := key(l)
				next[k] = true
				if !seen[k] {
					printLogLine(l)
				}
			}
			seen = next
		}
	}
}

// tailN keeps the last n entries, or everything when n covers the list.
func tailN(logs []requestLog, n int) []requestLog {
	if n < 0 || len(logs) <= n {
		return logs
	}
	return logs[len(logs)-n:]
}

// formatLogLine renders one request as a compact line:
//
//	15:04:05  200  GET  /api/users  t_ab12cd  demo  12ms
func formatLogLine(l requestLog) string {
	sub := l.Subdomain
	if sub == "" {
		sub = "-"
	}
	return fmt.Sprintf("%s  %3d  %-6s %-44s %-10s %-16s %dms",
		l.Time.Format("15:04:05"), l.Status, l.Method,
		truncate(logPath(l.URL), 44), truncate(l.TunnelID, 10),
		truncate(sub, 16), l.Duration)
}

func printLogLine(l requestLog) {
	fmt.Println(formatLogLine(l))
}

// logPath reduces a URL to its path and query so the line stays compact even
// if the server ever logs absolute URLs.
func logPath(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	p := u.Path
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	if p == "" {
		return raw
	}
	return p
}
