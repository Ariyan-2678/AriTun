package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Ariyan-2678/aritun/internal/protocol"
)

// TestWebSocketUpgrade proves that WebSocket handshakes survive the public
// HTTP router end to end: the Upgrade request and the 101 response pass
// through the reverse proxy untouched, and the hijacked duplex stream (a
// yamux stream under the hood) relays frames in both directions. The local
// service behind each tunnel is a real HTTP server doing what every WS
// library does: hijack the connection, answer 101, then speak the raw
// protocol over the socket.
func TestWebSocketUpgrade(t *testing.T) {

	t.Run("HTTPTunnel", func(t *testing.T) {
		env, tun := startWSTunnel(t, "wsraw", manualWSEchoHandler)

		conn, br, _ := wsHandshake(t, env, "wsraw."+e2eDomain, "/ws")
		for i := 0; i < 3; i++ {
			wsEchoRoundTrip(t, conn, br, fmt.Sprintf("ping-%d", i))
		}
		conn.Close() // ends the upgraded connection; the request is logged now

		// The hijacked 101 never reaches the counting writer, so the handler
		// must record the upgraded status explicitly for the inspector.
		pollUntil(t, "inspector entry with status 101 for /ws", func() bool {
			resp := env.adminGet("/api/requests?tunnel=" + tun.ID)
			if resp.status != http.StatusOK {
				return false
			}
			var payload struct {
				Requests []RequestLog `json:"requests"`
			}
			if err := json.Unmarshal([]byte(resp.body), &payload); err != nil {
				return false
			}
			for _, r := range payload.Requests {
				if r.URL == "/ws" && r.Status == http.StatusSwitchingProtocols {
					return true
				}
			}
			return false
		})
	})

	t.Run("MultiTunnel", func(t *testing.T) {
		svc := httptest.NewServer(http.HandlerFunc(manualWSEchoHandler))
		t.Cleanup(svc.Close)
		port := localPort(t, svc)
		env := startE2E(t, Config{})
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeMulti,
			LocalPort: port,
			Subdomain: "wsmulti",
		})
		cl.waitForTunnel("wsmulti")

		// Multi tunnels address the local port in the first path segment:
		// /<port>/ws must upgrade just like a plain http tunnel does.
		conn, br, _ := wsHandshake(t, env, "wsmulti."+e2eDomain, "/"+strconv.Itoa(port)+"/ws")
		wsEchoRoundTrip(t, conn, br, "ping-over-multi")
	})

	t.Run("RealWebSocket", func(t *testing.T) {
		// The same flow a browser or a WS client library performs, driven by
		// coder/websocket on both ends (already a dependency, used by the
		// control channel): real frames, not just raw bytes.
		svc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				return // handshake never completed; the client sees a non-101
			}
			defer ws.Close(websocket.StatusNormalClosure, "")
			ctx := context.Background()
			for {
				typ, data, err := ws.Read(ctx)
				if err != nil {
					return
				}
				if err := ws.Write(ctx, typ, data); err != nil {
					return
				}
			}
		}))
		t.Cleanup(svc.Close)

		env := startE2E(t, Config{})
		cl := env.startClient(e2eRootToken, protocol.Tunnel{
			Type:      protocol.TypeHTTP,
			LocalPort: localPort(t, svc),
			Subdomain: "wsecho",
		})
		cl.waitForTunnel("wsecho")

		// Dial the public router directly but with the tunnel's Host header,
		// the way Caddy would forward a request for wsecho.aritun.test.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ws, resp, err := websocket.Dial(ctx, "http://"+env.httpAddr+"/ws",
			&websocket.DialOptions{Host: "wsecho." + e2eDomain})
		if err != nil {
			if resp != nil {
				t.Fatalf("websocket dial through tunnel: %v (HTTP %d)", err, resp.StatusCode)
			}
			t.Fatalf("websocket dial through tunnel: %v", err)
		}
		defer ws.Close(websocket.StatusNormalClosure, "")

		for i := 0; i < 3; i++ {
			msg := fmt.Sprintf("frame-%d", i)
			if err := ws.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
				t.Fatalf("write frame %d: %v", i, err)
			}
			typ, got, err := ws.Read(ctx)
			if err != nil {
				t.Fatalf("read echoed frame %d: %v", i, err)
			}
			if typ != websocket.MessageText || string(got) != msg {
				t.Errorf("echoed frame = (%v, %q), want (text, %q)", typ, got, msg)
			}
		}
	})
}

// startWSTunnel boots an E2E environment with one http tunnel at sub whose
// local service runs the given handler, returning the registered tunnel.
func startWSTunnel(t *testing.T, sub string, handler http.HandlerFunc) (*e2eEnv, protocol.Tunnel) {
	t.Helper()
	svc := httptest.NewServer(handler)
	t.Cleanup(svc.Close)
	env := startE2E(t, Config{})
	cl := env.startClient(e2eRootToken, protocol.Tunnel{
		Type:      protocol.TypeHTTP,
		LocalPort: localPort(t, svc),
		Subdomain: sub,
	})
	return env, cl.waitForTunnel(sub)
}

// manualWSEchoHandler performs a WebSocket-style 101 handshake by hand —
// computing Sec-WebSocket-Accept the way every WS library does — and then
// echoes raw bytes over the upgraded connection. A request that is not an
// upgrade is rejected with 400 so a broken proxy fails loudly instead of
// silently degrading to a normal response.
func manualWSEchoHandler(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if key == "" ||
		!headerContainsToken(r.Header.Get("Connection"), "upgrade") ||
		!strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "expected a websocket upgrade", http.StatusBadRequest)
		return
	}

	conn, bufrw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	_, _ = io.WriteString(bufrw, "HTTP/1.1 101 Switching Protocols\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Accept: "+wsAcceptKey(key)+"\r\n\r\n")
	if err := bufrw.Flush(); err != nil {
		return
	}

	buf := make([]byte, 4096)
	for {
		n, err := bufrw.Read(buf)
		if n > 0 {
			if _, werr := bufrw.Write(buf[:n]); werr != nil {
				return
			}
			if ferr := bufrw.Flush(); ferr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// wsHandshake performs a raw WebSocket opening handshake against the public
// HTTP router (host/path as Caddy would forward them) and fails the test
// unless the 101 response — including the app-computed Sec-WebSocket-Accept —
// came back. The returned reader still holds anything the server sent past
// the response headers, ready for round trips.
func wsHandshake(t *testing.T, env *e2eEnv, host, path string) (net.Conn, *bufio.Reader, http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", env.httpAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial public router: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatalf("generate Sec-WebSocket-Key: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	_, err = io.WriteString(conn, "GET "+path+" HTTP/1.1\r\n"+
		"Host: "+host+"\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+
		"Sec-WebSocket-Key: "+key+"\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n")
	if err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		t.Fatalf("handshake status = %d, want 101 (body %q)", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Upgrade"); !strings.EqualFold(got, "websocket") {
		t.Errorf("Upgrade = %q, want websocket", got)
	}
	if got, want := resp.Header.Get("Sec-WebSocket-Accept"), wsAcceptKey(key); got != want {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q — accept key computed by the local app must survive the tunnel",
			got, want)
	}
	return conn, br, *resp
}

// wsEchoRoundTrip writes msg over the upgraded connection and reads exactly
// as many bytes back from the echo service on the other side of the tunnel.
func wsEchoRoundTrip(t *testing.T, conn net.Conn, br *bufio.Reader, msg string) {
	t.Helper()
	if _, err := io.WriteString(conn, msg); err != nil {
		t.Fatalf("write over upgraded connection: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(br, buf); err != nil {
		t.Fatalf("read echo over upgraded connection: %v", err)
	}
	if string(buf) != msg {
		t.Errorf("echo = %q, want %q", buf, msg)
	}
}

// wsAcceptKey computes the Sec-WebSocket-Accept value for a client key,
// per RFC 6455 section 4.2.2.
func wsAcceptKey(clientKey string) string {
	h := sha1.Sum([]byte(clientKey + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(h[:])
}
