// Command aritund is the AriTun server: it authenticates clients, publishes
// their tunnels, and routes public traffic back to them.
package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/Ariyan-2678/aritun/internal/protocol"
	"github.com/Ariyan-2678/aritun/internal/server"
)

// version is stamped by build.sh via -X main.version. Empty means "use
// protocol.Version".
var version string

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "aritund: "+err.Error())
		os.Exit(1)
	}
}

func buildVersion() string {
	if version != "" {
		return version
	}
	return protocol.Version
}

func run(args []string) error {
	fs := flag.NewFlagSet("aritund", flag.ContinueOnError)
	var (
		domain       = fs.String("domain", "", "parent domain for http tunnels, e.g. aritun.yourdomain.com")
		token        = fs.String("token", envOr("ARITUN_TOKEN", ""), "client access token (generated on first run if empty)")
		tokenFile    = fs.String("token-file", "", "read the token from this file instead")
		controlAddr  = fs.String("control-addr", ":9443", "address clients dial (empty to disable)")
		controlTLS   = fs.Bool("control-tls", true, "serve TLS on the control listener")
		controlCert  = fs.String("control-cert", "", "control TLS certificate (default: self-signed in --data-dir)")
		controlKey   = fs.String("control-key", "", "control TLS private key")
		controlHosts = fs.String("control-hosts", "",
			"comma-separated extra SANs for the generated certificate, e.g. 203.0.113.5,aritun.yourdomain.com")
		httpAddr   = fs.String("http-addr", "127.0.0.1:9001", "plain HTTP listener for Caddy to forward to")
		adminAddr  = fs.String("admin-addr", "127.0.0.1:9090", "dashboard and JSON API (empty to disable)")
		tcpRange   = fs.String("tcp-range", "20000-20999", "public ports available to tcp tunnels")
		dataDir    = fs.String("data-dir", "", "AriTun data directory (default: platform-specific)")
		genToken   = fs.Bool("gen-token", false, "print a fresh random token and exit")
		tokensFile = fs.String("tokens-file", "", "JSON file of named tokens with per-type permissions")
		auditLog   = fs.String("audit-log", "",
			"append the admin audit log to this file (empty: keep it in memory only)")
		oauthBase = fs.String("oauth-base", "", "external base URL for OAuth callbacks, e.g. https://aritun.example.com")
		verbose   = fs.Bool("v", false, "verbose logging")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	if *genToken {
		fmt.Println(newToken())
		return nil
	}

	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		*token = strings.TrimSpace(string(b))
	}
	if *token == "" {
		if t, err := loadOrCreateToken(*dataDir); err == nil {
			*token = t
			log.Warn("generated an access token; clients need --token with this value",
				"token", t, "file", *dataDir+"/token")
		} else {
			return fmt.Errorf("no --token given and none could be generated: %w", err)
		}
	}

	min, max, err := parseRange(*tcpRange)
	if err != nil {
		return err
	}

	// The control listener must not collide with the AriTun TCP-forwarding range.
	if *controlAddr != "" && overlapsTCPRange(*controlAddr, min, max) {
		return fmt.Errorf("control address %s overlaps the tcp tunnel range %d-%d", *controlAddr, min, max)
	}

	if err := server.InitAudit(*auditLog); err != nil {
		return err
	}

	srv := server.New(server.Config{
		Domain:       *domain,
		Token:        *token,
		ControlAddr:  *controlAddr,
		ControlTLS:   *controlTLS,
		CertFile:     *controlCert,
		KeyFile:      *controlKey,
		ControlHosts: splitCSV(*controlHosts),
		HTTPAddr:     *httpAddr,
		AdminAddr:    *adminAddr,
		TCPMin:       min,
		TCPMax:       max,
		DataDir:      *dataDir,
		TokensFile:   *tokensFile,
		OAuthBase:    *oauthBase,
	}, log)

	log.Info("AriTun server starting",
		"version", buildVersion(),
		"domain", orNone(*domain),
		"control", orNone(*controlAddr),
		"tls", *controlTLS,
		"http_router", orNone(*httpAddr),
		"tcp_range", fmt.Sprintf("%d-%d", min, max))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := srv.Run(ctx); err != nil {
		return err
	}
	log.Info("AriTun server stopped")
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func orNone(s string) string {
	if s == "" {
		return "disabled"
	}
	return s
}

// splitCSV turns "a, b" into ["a", "b"], dropping blanks.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseRange(s string) (int, int, error) {
	parts := strings.SplitN(s, "-", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("--tcp-range must look like 20000-20999, got %q", s)
	}
	min, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil {
		return 0, 0, fmt.Errorf("--tcp-range: %w", err)
	}
	max, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return 0, 0, fmt.Errorf("--tcp-range: %w", err)
	}
	if min < 1024 || max > 65535 || min > max {
		return 0, 0, fmt.Errorf("--tcp-range %d-%d is out of bounds", min, max)
	}
	return min, max, nil
}

func overlapsTCPRange(addr string, min, max int) bool {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil || host != "" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	return port >= min && port <= max
}

func newToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// loadOrCreateToken persists a generated token so restarts do not invalidate
// every client at once.
func loadOrCreateToken(dir string) (string, error) {
	path := dir + "/token"
	if b, err := os.ReadFile(path); err == nil {
		if t := strings.TrimSpace(string(b)); t != "" {
			return t, nil
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	t := newToken()
	if err := os.WriteFile(path, []byte(t+"\n"), 0o600); err != nil {
		return "", err
	}
	return t, nil
}
