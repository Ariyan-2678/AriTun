// Command aritun is the client agent: it exposes local ports through the
// AriTun server, in the shape of `aritun http 3000`.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Ariyan-2678/aritun/internal/client"
	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// version is stamped by build.sh via -X main.version. Empty means "use
// protocol.Version".
var version string

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "aritun: "+err.Error())
		os.Exit(1)
	}
}

type globals struct {
	server   string
	token    string
	ca       string
	insecure bool
	noTLS    bool
	name     string
	proxy    string
	verbose  bool
}

func (g *globals) register(fs *flag.FlagSet) {
	fs.StringVar(&g.server, "server", envOr("ARITUN_SERVER", ""),
		"AriTun server, either host:port or wss://aritun.example.com/control")
	fs.StringVar(&g.token, "token", envOr("ARITUN_TOKEN", ""),
		"access token (must match the server)")
	fs.StringVar(&g.ca, "ca", envOr("ARITUN_CA", ""),
		"PEM file with the server's certificate, e.g. control-cert.pem")
	fs.StringVar(&g.proxy, "proxy", envOr("ARITUN_PROXY", ""),
		"SOCKS5 proxy, e.g. socks5://127.0.0.1:10808 (env ARITUN_PROXY)")
	fs.BoolVar(&g.insecure, "insecure", false, "skip TLS verification")
	fs.BoolVar(&g.noTLS, "no-tls", false, "plain TCP (local development only)")
	fs.StringVar(&g.name, "name", "", "name shown in the dashboard (default: hostname)")
	fs.BoolVar(&g.verbose, "v", false, "verbose logging")
}

func (g *globals) clientConfig() client.Config {
	return client.Config{
		Server:   g.server,
		Token:    g.token,
		Name:     g.name,
		CAFile:   g.ca,
		Proxy:    g.proxy,
		Insecure: g.insecure,
		NoTLS:    g.noTLS,
	}
}

func (g *globals) logger() *slog.Logger {
	level := slog.LevelInfo
	if g.verbose {
		level = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return fmt.Errorf("a command is required")
	}

	switch args[0] {
	case "http":
		return cmdHTTP(args[1:])
	case "tcp":
		return cmdTCP(args[1:])
	case "all":
		return cmdAll(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "version", "-version", "--version":
		fmt.Println("AriTun", buildVersion(), runtime.GOOS+"/"+runtime.GOARCH)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func buildVersion() string {
	if version != "" {
		return version
	}
	return protocol.Version
}

func usage() {
	fmt.Print(`AriTun - expose local ports through your own server

Usage:
  aritun http <port> [--subdomain NAME] [--auth user:pass]
  aritun tcp  <port>
  aritun all  [--ports 3000,8080] [--exclude 445,135] [--http-only|--tcp-only]
  aritun status [--admin http://host:9090]
  aritun version

Set --server once with ARITUN_SERVER and stop repeating it.

Global flags:
  --server  host:9443 | wss://aritun.example.com/control   (env ARITUN_SERVER)
  --token   shared secret                              (env ARITUN_TOKEN)
  --ca      PEM with the server certificate            (env ARITUN_CA)
  --proxy   SOCKS5 proxy, e.g. socks5://127.0.0.1:10808 (env ARITUN_PROXY)
  --insecure   skip TLS verification
  --no-tls     plain TCP, local development only
  --name    label shown in the dashboard
  -v        verbose logging

Examples:
  aritun http 3000
  aritun http 8080 --subdomain demo --auth admin:s3cret
  aritun tcp 3389
  aritun all
  aritun status        # derives the admin URL from --server
`)
}

// boolFlags are the flags that never take a value. Knowing them lets
// normalizeArgs tell `--server x` (two tokens) from `--verbose` (one).
var boolFlags = map[string]bool{
	"insecure": true, "no-tls": true, "v": true, "verbose": true,
	"help": true, "h": true, "version": true,
	"http-only": true, "tcp-only": true, "json": true,
	"include-ephemeral": true,
}

// normalizeArgs moves positional arguments to the end so the flag package can
// parse `aritun http 3000 --subdomain demo`, the way ngrok users expect.
// Go's flag.Parse stops at the first non-flag token, which would otherwise
// leave everything after the port unparsed.
func normalizeArgs(args []string) []string {
	var flags, positionals []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positionals = append(positionals, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			positionals = append(positionals, a)
			continue
		}
		flags = append(flags, a)

		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") || boolFlags[name] {
			continue // --flag=value, or a boolean flag
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			i++
			flags = append(flags, args[i])
		}
	}
	return append(flags, positionals...)
}

func cmdHTTP(args []string) error {
	var g globals
	fs := flag.NewFlagSet("http", flag.ContinueOnError)
	subdomain := fs.String("subdomain", "", "custom subdomain (default: random)")
	auth := fs.String("auth", "", "require user:pass to reach the tunnel")
	g.register(fs)
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: aritun http <port>")
	}
	port, err := strconv.Atoi(fs.Arg(0))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q", fs.Arg(0))
	}

	sub := *subdomain
	if sub == "" {
		sub = client.RandomSubdomain()
	}

	tunnels := []protocol.Tunnel{{
		Type:      protocol.TypeHTTP,
		LocalPort: port,
		Subdomain: sub,
		BasicAuth: *auth,
	}}
	return serve(&g, tunnels)
}

func cmdTCP(args []string) error {
	var g globals
	fs := flag.NewFlagSet("tcp", flag.ContinueOnError)
	g.register(fs)
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: aritun tcp <port>")
	}
	port, err := strconv.Atoi(fs.Arg(0))
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q", fs.Arg(0))
	}

	tunnels := []protocol.Tunnel{{
		Type:      protocol.TypeTCP,
		LocalPort: port,
	}}
	return serve(&g, tunnels)
}

// discoveryOptions builds the discovery settings for `aritun all`, excluding
// both the ports we publish explicitly and the ports of the infrastructure we
// are dialling through.
//
// Republishing --server would, on a machine where both ends run, tunnel the
// server into itself. Republishing --proxy would expose a local VPN or proxy
// to the entire internet, which is the kind of mistake that is only noticed
// after the fact. Neither is ever worth publishing, so neither can be
// overridden by --ports.
func discoveryOptions(g globals, userExclude map[int]bool) client.DiscoverOptions {
	exclude := make(map[int]bool, len(userExclude)+2)
	for port, skip := range userExclude {
		if skip {
			exclude[port] = true
		}
	}

	add := func(addr string) {
		// Accept both "host:port" and "scheme://host:port/path".
		if i := strings.Index(addr, "://"); i >= 0 {
			if u, err := url.Parse(addr); err == nil {
				addr = u.Host
			} else {
				return
			}
		}
		_, portStr, err := net.SplitHostPort(addr)
		if err != nil {
			return
		}
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			exclude[p] = true
		}
	}

	add(g.server)
	add(g.proxy)

	return client.DiscoverOptions{
		Exclude:       exclude,
		ExcludeSystem: true,
	}
}

func cmdAll(args []string) error {
	var g globals
	fs := flag.NewFlagSet("all", flag.ContinueOnError)
	portsFlag := fs.String("ports", "", "comma separated ports; skips discovery")
	excludeFlag := fs.String("exclude", "", "comma separated ports to skip")
	httpOnly := fs.Bool("http-only", false, "only publish web ports as https URLs")
	tcpOnly := fs.Bool("tcp-only", false, "only publish raw tcp ports")
	httpPortsFlag := fs.String("http-ports", "", "extra ports to treat as web services")
	includeEphemeral := fs.Bool("include-ephemeral", false,
		"also publish high-numbered dynamic ports (usually a mistake)")
	g.register(fs)
	if err := fs.Parse(normalizeArgs(args)); err != nil {
		return err
	}
	if *httpOnly && *tcpOnly {
		return fmt.Errorf("--http-only and --tcp-only are mutually exclusive")
	}

	opts := discoveryOptions(g, parseIntSet(*excludeFlag))
	opts.ExcludeEphemeral = !*includeEphemeral
	if *portsFlag != "" {
		ports, err := parseIntList(*portsFlag)
		if err != nil {
			return err
		}
		opts.Ports = ports
	}

	extraWeb := parseIntSet(*httpPortsFlag)

	fmt.Fprintln(os.Stderr, "scanning local listeners...")
	found, err := client.DiscoverLocalPorts(opts)
	if err != nil {
		return fmt.Errorf("port discovery: %w", err)
	}
	if len(found) == 0 {
		return fmt.Errorf("no listening TCP ports found on this machine")
	}

	var tunnels []protocol.Tunnel
	for _, p := range found {
		isWeb := client.LooksLikeWeb(p, extraWeb)
		switch {
		case *tcpOnly:
			tunnels = append(tunnels, protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: p})
		case *httpOnly:
			if isWeb {
				tunnels = append(tunnels, protocol.Tunnel{
					Type: protocol.TypeHTTP, LocalPort: p, Subdomain: fmt.Sprintf("p%d", p),
				})
			}
		default:
			if isWeb {
				tunnels = append(tunnels, protocol.Tunnel{
					Type: protocol.TypeHTTP, LocalPort: p, Subdomain: fmt.Sprintf("p%d", p),
				})
			} else {
				tunnels = append(tunnels, protocol.Tunnel{Type: protocol.TypeTCP, LocalPort: p})
			}
		}
	}
	if len(tunnels) == 0 {
		return fmt.Errorf("nothing to publish (%d ports found)", len(found))
	}
	return serve(&g, tunnels)
}

// serve wires up a client, prints the ngrok-style banner, and blocks until the
// user interrupts.
func serve(g *globals, tunnels []protocol.Tunnel) error {
	if g.server == "" {
		return fmt.Errorf("--server is required (or set ARITUN_SERVER)")
	}

	log := g.logger()
	c, err := client.New(g.clientConfig(), tunnels, log)
	if err != nil {
		return err
	}
	if c.UsingProxy() {
		fmt.Fprintf(os.Stderr, "proxy: %s\n", g.proxy)
	}

	printed := false
	c.OnUpdate(func(active []protocol.Tunnel) {
		printBanner(active, printed)
		printed = true
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "AriTun v%s - connecting to %s\n\n", buildVersion(), g.server)

	if err := c.Run(ctx); err != nil && ctx.Err() == nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "\ntunnel closed")
	return nil
}

func printBanner(tunnels []protocol.Tunnel, reconnect bool) {
	if reconnect {
		fmt.Fprintf(os.Stderr, "\n-- reconnected --\n")
	}
	if len(tunnels) == 0 {
		fmt.Fprintln(os.Stderr, "no tunnels published")
		return
	}

	sorted := append([]protocol.Tunnel(nil), tunnels...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Type != sorted[j].Type {
			return sorted[i].Type < sorted[j].Type
		}
		return sorted[i].LocalPort < sorted[j].LocalPort
	})

	width := 0
	for _, t := range sorted {
		if n := len(describe(t)); n > width {
			width = n
		}
	}

	for _, t := range sorted {
		local := fmt.Sprintf("http://localhost:%d", t.LocalPort)
		if t.Type == protocol.TypeTCP {
			local = fmt.Sprintf("tcp://localhost:%d", t.LocalPort)
		}
		label := t.PublicURL
		if t.Type == protocol.TypeTCP {
			label = fmt.Sprintf("tcp port %d", t.PublicPort)
		}
		fmt.Printf("  %-*s  ->  %s\n", width, label, local)
	}
	fmt.Printf("\n%d AriTun forwarding rule(s) live. Press Ctrl+C to stop.\n", len(sorted))
}

func describe(t protocol.Tunnel) string {
	if t.Type == protocol.TypeTCP {
		return fmt.Sprintf("tcp port %d", t.PublicPort)
	}
	return t.PublicURL
}

// adminURLFromServer turns whatever --server holds into the dashboard's base
// URL, so `aritun status` works without a second flag. The admin port is the
// one aritund was started with; 9090 is the default.
//
//	127.0.0.1:9443                 -> http://127.0.0.1:9090
//	wss://aritun.example.com/control -> http://aritun.example.com:9090
func adminURLFromServer(server string) (string, error) {
	if server == "" {
		return "", fmt.Errorf("no --server given (or set ARITUN_SERVER)")
	}
	u := strings.TrimSpace(server)

	if strings.Contains(u, "://") {
		parsed, err := url.Parse(u)
		if err != nil {
			return "", err
		}
		host := parsed.Hostname()
		if host == "" {
			return "", fmt.Errorf("cannot parse host from %q", server)
		}
		return "http://" + net.JoinHostPort(host, adminPort), nil
	}

	host, _, err := net.SplitHostPort(u)
	if err != nil {
		return "", fmt.Errorf("cannot parse host from %q", server)
	}
	return "http://" + net.JoinHostPort(host, adminPort), nil
}

// adminPort is the dashboard port; overridable so the guess can be pointed at
// a custom deployment.
var adminPort = envOr("ARITUN_ADMIN_PORT", "9090")

func cmdStatus(args []string) error {
	var g globals
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	admin := fs.String("admin", envOr("ARITUN_ADMIN", ""),
		"admin base URL; default: derived from --server (port 9090)")
	raw := fs.Bool("json", false, "print raw JSON")
	g.register(fs)
	if err := fs.Parse(normalizeArgs(args)); err != nil {
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

	httpc := &http.Client{Timeout: 10 * time.Second}
	resp, err := httpc.Get(strings.TrimRight(base, "/") + "/api/tunnels")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server replied %s", resp.Status)
	}

	if *raw {
		_, err := io.Copy(os.Stdout, resp.Body)
		return err
	}

	var view struct {
		ServerVersion string `json:"server_version"`
		Domain        string `json:"domain"`
		TunnelCount   int    `json:"tunnel_count"`
		Tunnels       []struct {
			Client     string `json:"client"`
			Type       string `json:"type"`
			LocalPort  int    `json:"local_port"`
			PublicURL  string `json:"public_url"`
			PublicPort int    `json:"public_port"`
			AgeSeconds int64  `json:"age_seconds"`
		} `json:"tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&view); err != nil {
		return err
	}

	fmt.Printf("AriTun server v%s · %d AriTun forwarding rule(s) active\n\n", view.ServerVersion, view.TunnelCount)
	for _, t := range view.Tunnels {
		public := t.PublicURL
		if t.Type == protocol.TypeTCP {
			public = fmt.Sprintf("tcp port %d", t.PublicPort)
		}
		fmt.Printf("  %-6s %-16s :%-6d -> %-44s up %s\n",
			t.Type, t.Client, t.LocalPort, public, humanDuration(t.AgeSeconds))
	}
	return nil
}

func humanDuration(sec int64) string {
	d := time.Duration(sec) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func parseIntList(s string) ([]int, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil
	}
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", part)
		}
		out = append(out, n)
	}
	return out, nil
}

func parseIntSet(s string) map[int]bool {
	list, _ := parseIntList(s)
	set := make(map[int]bool, len(list))
	for _, n := range list {
		set[n] = true
	}
	return set
}
