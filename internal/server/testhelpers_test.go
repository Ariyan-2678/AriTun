package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Ariyan-2678/aritun/internal/client"
	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// Scaffolding for TestE2E: a real in-process Server on ephemeral loopback
// listeners, a real client.Client driving the control protocol, and small
// request helpers. Everything is torn down through t.Cleanup.

const (
	// e2eDomain is the parent domain test tunnels publish under, so a request
	// for Host "web.aritun.test" routes to the tunnel "web".
	e2eDomain = "aritun.test"
	// e2eRootToken becomes Config.Token unless a test supplies its own.
	e2eRootToken = "e2e-root-token"
	// e2eWait bounds every wait: tests fail with a clear message instead of
	// hanging or sleeping blindly.
	e2eWait = 2 * time.Second
)

// logBuffer collects slog output from the in-process server and client so a
// failing test can dump it. Writes are mutex-guarded because both sides log
// concurrently.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// e2eEnv is one running server plus the addresses its three listeners were
// bound to.
type e2eEnv struct {
	t         *testing.T
	srv       *Server
	logs      *logBuffer
	web       *http.Client
	ctrlAddr  string // control listener, clients dial this
	httpAddr  string // public HTTP router
	adminAddr string // admin dashboard/API

	cancel  context.CancelFunc
	stopped chan error
}

// startE2E boots a real Server in-process. Instead of Server.Run (which binds
// the configured fixed addresses), it serves the control, public-http and
// admin listeners on test-reserved 127.0.0.1:0 ports, so nothing is hard
// coded and nothing can collide with a real aritund.
func startE2E(t *testing.T, cfg Config) *e2eEnv {
	t.Helper()

	logs := &logBuffer{}
	cfg.Domain = e2eDomain
	if cfg.Token == "" {
		cfg.Token = e2eRootToken
	}
	cfg.ControlTLS = false
	srv := New(cfg, slog.New(slog.NewTextHandler(logs, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	ctrlLn := e2eListen(t, "control")
	httpLn := e2eListen(t, "public http")
	adminLn := e2eListen(t, "admin")

	stopped := make(chan error, 3)
	go func() { stopped <- srv.serveControl(ctx, ctrlLn) }()
	go func() { stopped <- srv.serveHTTP(ctx, httpLn) }()
	go func() { stopped <- srv.serveAdmin(ctx, adminLn) }()

	env := &e2eEnv{
		t:         t,
		srv:       srv,
		logs:      logs,
		web:       &http.Client{Timeout: 10 * time.Second},
		ctrlAddr:  ctrlLn.Addr().String(),
		httpAddr:  httpLn.Addr().String(),
		adminAddr: adminLn.Addr().String(),
		cancel:    cancel,
		stopped:   stopped,
	}
	t.Cleanup(env.shutdown)
	return env
}

func e2eListen(t *testing.T, what string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for %s: %v", what, err)
	}
	return ln
}

// shutdown cancels the server context and waits (bounded) for all three
// serve goroutines so no listener outlives the test.
func (e *e2eEnv) shutdown() {
	defer func() {
		if e.t.Failed() && e.logs.String() != "" {
			e.t.Logf("server log:\n%s", e.logs.String())
		}
	}()
	e.cancel()
	e.web.CloseIdleConnections()

	deadline := time.After(3 * time.Second)
	for stopped := 0; stopped < 3; stopped++ {
		select {
		case <-e.stopped:
		case <-deadline:
			e.t.Errorf("only %d/3 server listeners stopped within 3s", stopped)
			return
		}
	}
}

// e2eResponse is a fully read HTTP response.
type e2eResponse struct {
	status int
	body   string
	header http.Header
}

// publicGet sends a request through the public HTTP router as if Caddy had
// forwarded it for sub+"."+e2eDomain (sub "" keeps the loopback Host).
// mutate runs before the request is sent, e.g. to set auth or X-Forwarded-For.
func (e *e2eEnv) publicGet(sub, path string, mutate ...func(*http.Request)) e2eResponse {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+e.httpAddr+path, nil)
	if err != nil {
		e.t.Fatalf("build request for %q: %v", path, err)
	}
	if sub != "" {
		req.Host = sub + "." + e2eDomain
	}
	for _, m := range mutate {
		m(req)
	}
	return e.do(req)
}

func (e *e2eEnv) adminGet(path string) e2eResponse {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://"+e.adminAddr+path, nil)
	if err != nil {
		e.t.Fatalf("build request for %q: %v", path, err)
	}
	return e.do(req)
}

func (e *e2eEnv) adminPost(path string) e2eResponse {
	e.t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://"+e.adminAddr+path, nil)
	if err != nil {
		e.t.Fatalf("build request for %q: %v", path, err)
	}
	return e.do(req)
}

func (e *e2eEnv) do(req *http.Request) e2eResponse {
	e.t.Helper()
	resp, err := e.web.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("%s %s: read body: %v", req.Method, req.URL, err)
	}
	return e2eResponse{status: resp.StatusCode, body: string(body), header: resp.Header}
}

// e2eClient is a real client.Client running against an env's control
// listener, with the latest registration state surfaced for waiting.
type e2eClient struct {
	t      *testing.T
	client *client.Client
	logs   *logBuffer

	signal chan struct{} // buffered(1): wake up after every registration update
}

// startClient launches client.Run in the background. Registration state
// arrives through OnUpdate; waitForTunnel blocks on it.
func (e *e2eEnv) startClient(token string, tunnels ...protocol.Tunnel) *e2eClient {
	e.t.Helper()

	logs := &logBuffer{}
	c, err := client.New(client.Config{
		Server:    e.ctrlAddr,
		Token:     token,
		Name:      "e2e-client",
		NoTLS:     true,
		LocalHost: "127.0.0.1",
	}, tunnels, slog.New(slog.NewTextHandler(logs, nil)))
	if err != nil {
		e.t.Fatalf("client.New: %v", err)
	}

	ec := &e2eClient{
		t:      e.t,
		client: c,
		logs:   logs,
		signal: make(chan struct{}, 1),
	}
	c.OnUpdate(func([]protocol.Tunnel) {
		select {
		case ec.signal <- struct{}{}:
		default:
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = c.Run(ctx) }()
	e.t.Cleanup(func() {
		cancel()
		if e.t.Failed() && logs.String() != "" {
			e.t.Logf("client log:\n%s", logs.String())
		}
	})
	return ec
}

func (c *e2eClient) snapshot() []protocol.Tunnel { return c.client.Snapshot() }

// waitForTunnel blocks until the client reports a live tunnel for sub,
// failing the test after e2eWait. The scan-then-wait order plus the buffered
// signal means no update can be missed.
func (c *e2eClient) waitForTunnel(sub string) protocol.Tunnel {
	c.t.Helper()
	deadline := time.After(e2eWait)
	for {
		for _, tn := range c.snapshot() {
			if tn.Subdomain == sub && tn.Error == "" {
				return tn
			}
		}
		select {
		case <-c.signal:
		case <-deadline:
			c.t.Fatalf("timed out after %v waiting for tunnel %q; client state: %+v",
				e2eWait, sub, c.snapshot())
		}
	}
}

// newLocalService starts a real HTTP server on an ephemeral loopback port —
// the "local" app behind a tunnel. It echoes the request path and host in
// headers so tests can prove traffic really crossed the tunnel.
func newLocalService(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Served-By", "aritun-e2e-local")
		w.Header().Set("X-Echo-Path", r.URL.Path)
		w.Header().Set("X-Echo-Host", r.Host)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// localPort extracts the loopback port of a httptest server.
func localPort(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse local service URL %q: %v", srv.URL, err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("local service port in %q: %v", srv.URL, err)
	}
	return p
}

// pollUntil calls fn every few milliseconds until it holds, failing the test
// if that does not happen within e2eWait. Prefer it over sleeps whenever a
// result is recorded asynchronously (e.g. after a response is written).
func pollUntil(t *testing.T, what string, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(e2eWait)
	for {
		if fn() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", e2eWait, what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// promValue parses the first sample (labelled or not) for a metric name out of
// a Prometheus text exposition body.
func promValue(body, name string) (float64, bool) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, name+" ") && !strings.HasPrefix(line, name+"{") {
			continue
		}
		if i := strings.LastIndexByte(line, ' '); i >= 0 {
			if v, err := strconv.ParseFloat(strings.TrimSpace(line[i+1:]), 64); err == nil {
				return v, true
			}
		}
	}
	return 0, false
}
