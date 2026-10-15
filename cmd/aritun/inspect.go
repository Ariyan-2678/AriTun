package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// cmdInspect implements `aritun inspect`: it polls the admin API's
// /api/requests endpoint and prints a live feed of proxied requests. --follow
// keeps the stream open; otherwise it prints one snapshot and exits. --headers
// adds the captured request/response headers, the body preview and a
// copy-as-curl command per request; --curl prints only the curl commands.
func cmdInspect(args []string) error {
	var g globals
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	admin := fs.String("admin", envOr("ARITUN_ADMIN", ""),
		"admin base URL; default: derived from --server (port 9090)")
	tunnel := fs.String("tunnel", "", "only show requests for this tunnel id")
	follow := fs.Bool("follow", false, "keep polling and print new requests as they arrive")
	interval := fs.Duration("interval", time.Second, "poll interval when --follow is set")
	raw := fs.Bool("json", false, "print raw JSON")
	headers := fs.Bool("headers", false,
		"also print the captured request/response headers, body preview and copy-as-curl")
	curlOnly := fs.Bool("curl", false, "print only the copy-as-curl commands")
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

	printer := newRequestPrinter(*curlOnly, *headers)
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
			printer.print(l)
		}
		return nil
	}

	// Follow mode: print anything new each poll.
	for _, l := range mustFetchAll(fetch) {
		seen[key(l)] = true
		printer.print(l)
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
				printer.print(l)
			}
		}
	}
	return nil
}

type requestLog struct {
	Time        time.Time         `json:"time"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Status      int               `json:"status"`
	Duration    int64             `json:"duration_ms"`
	Bytes       int64             `json:"bytes"`
	RemoteIP    string            `json:"remote_ip"`
	TunnelID    string            `json:"tunnel_id"`
	Subdomain   string            `json:"subdomain"`
	Client      string            `json:"client"`
	ReqHeaders  map[string]string `json:"req_headers"`
	RespHeaders map[string]string `json:"resp_headers"`
	BodyPreview string            `json:"body_preview"`
	Curl        string            `json:"curl"`
}

func key(l requestLog) string {
	return fmt.Sprintf("%d|%s|%s|%s", l.Time.UnixNano(), l.Method, l.URL, l.TunnelID)
}

// requestPrinter renders one request in the shape the selected flags ask for.
type requestPrinter struct {
	curlOnly bool
	headers  bool
}

func newRequestPrinter(curlOnly, headers bool) *requestPrinter {
	// --curl wins over --headers: it promises curl commands and nothing else.
	return &requestPrinter{curlOnly: curlOnly, headers: headers && !curlOnly}
}

func (p *requestPrinter) print(l requestLog) {
	if p.curlOnly {
		if l.Curl != "" {
			fmt.Println(l.Curl)
		}
		return
	}
	printRequestLine(l)
	if p.headers {
		printRequestDetail(l)
	}
}

func printRequestLine(l requestLog) {
	fmt.Printf("%s  %3d  %-6s %-40s %6s  %4dms  %-15s %s\n",
		l.Time.Format("15:04:05"), l.Status, l.Method, truncate(l.URL, 40),
		humanBytesInspect(l.Bytes), l.Duration, l.RemoteIP, l.Client)
}

// printRequestDetail adds the captured headers, the body preview and the
// copy-as-curl line underneath a request line.
func printRequestDetail(l requestLog) {
	printHeaders := func(label string, h map[string]string) {
		if len(h) == 0 {
			return
		}
		fmt.Printf("    %s headers:\n", label)
		keys := make([]string, 0, len(h))
		for k := range h {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("      %s: %s\n", k, oneLine(h[k], 200))
		}
	}
	printHeaders("request", l.ReqHeaders)
	printHeaders("response", l.RespHeaders)
	if l.BodyPreview != "" {
		fmt.Printf("    body: %s\n", oneLine(l.BodyPreview, 200))
	}
	if l.Curl != "" {
		fmt.Printf("    curl: %s\n", l.Curl)
	}
	fmt.Println()
}

// oneLine flattens a multi-line preview onto a single, bounded line.
func oneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", `\n`)
	return truncate(s, max)
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
