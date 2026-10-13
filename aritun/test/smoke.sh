#!/usr/bin/env bash
# AriTun end-to-end smoke tests: HTTP, TCP, auth, WS, SOCKS5 and cleanup.
set -uo pipefail
cd "$(dirname "$0")/.."

ARITUND=./dist/aritund-windows-amd64.exe
CLIENT=./dist/aritun-windows-amd64.exe
TOKEN=dev
WEB_PORT=3456
ECHO_PORT=7777
SOCKS_PORT=10809
LOGDIR=./devdata/logs
mkdir -p "$LOGDIR"

# Keep this E2E suite local even if the user's shell is configured for a real VPS.
unset ARITUN_SERVER ARITUN_TOKEN ARITUN_CA ARITUN_PROXY ARITUN_ADMIN ARITUN_ADMIN_PORT
export TOKEN

PIDS=()
stop_pid() {
  local pid=${1:-}
  [ -z "$pid" ] && return
  kill "$pid" 2>/dev/null
  taskkill //PID "$pid" //F >/dev/null 2>&1
}
cleanup() { for pid in "${PIDS[@]:-}"; do stop_pid "$pid"; done; }
trap cleanup EXIT

pass=0; fail=0
ok()  { echo "  PASS  $1"; pass=$((pass+1)); }
bad() { echo "  FAIL  $1 — $2"; fail=$((fail+1)); }

MARKER="Directory listing for"
tunneled_body() { curl -s -m 10 -H "Host: $1" http://127.0.0.1:9001/ 2>&1; }
served() { tunneled_body "$1" | grep -qi "$MARKER"; }

# Start only the resources this script owns.
"$ARITUND" --control-addr 127.0.0.1:9000 --control-tls=false \
  --token "$TOKEN" --http-addr 127.0.0.1:9001 --admin-addr 127.0.0.1:9090 \
  --tcp-range 20000-20010 --data-dir ./devdata >"$LOGDIR/server.log" 2>&1 &
PIDS+=($!)
python -m http.server "$WEB_PORT" --bind 127.0.0.1 >"$LOGDIR/web.log" 2>&1 &
PIDS+=($!)
python -I ./test/echo_server.py "$ECHO_PORT" >"$LOGDIR/echo.log" 2>&1 &
PIDS+=($!)
sleep 2

"$CLIENT" http "$WEB_PORT" --subdomain testapp --server 127.0.0.1:9000 \
  --token "$TOKEN" --no-tls --name smoke-raw >"$LOGDIR/client-raw.log" 2>&1 &
TESTAPP_PID=$!
PIDS+=($TESTAPP_PID)
"$CLIENT" tcp "$ECHO_PORT" --server 127.0.0.1:9000 \
  --token "$TOKEN" --no-tls --name smoke-tcp >>"$LOGDIR/client-raw.log" 2>&1 &
PIDS+=($!)
sleep 3

echo "-- HTTP forwarding --"
if served testapp; then ok "HTTP forwarding works"; else bad "HTTP forwarding" "$(tunneled_body testapp | head -c 80)"; fi
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Host: nosuchtunnel" http://127.0.0.1:9001/)
if [ "$code" = 404 ]; then ok "unknown host returns 404"; else bad "unknown host" "HTTP $code"; fi

echo "-- TCP forwarding --"
pub=$(curl -s -m 10 http://127.0.0.1:9090/api/tunnels | python -c "import json,sys; print([t['public_port'] for t in json.load(sys.stdin)['tunnels'] if t['type']=='tcp'][0])" 2>&1)
if [[ "$pub" =~ ^[0-9]+$ ]]; then
  reply=$(python -I -c "import socket; s=socket.create_connection(('127.0.0.1',$pub),5); s.sendall(b'hello-aritun'); print(s.recv(100).decode()); s.close()")
  if [ "$reply" = "ECHO:hello-aritun" ]; then ok "TCP round-trip works"; else bad "TCP round-trip" "got $reply"; fi
else bad "TCP allocation" "$pub"; fi

echo "-- HTTP Basic Auth --"
"$CLIENT" http "$WEB_PORT" --subdomain locked --auth admin:s3cret --server 127.0.0.1:9000 \
  --token "$TOKEN" --no-tls --name smoke-auth >"$LOGDIR/client-auth.log" 2>&1 &
PIDS+=($!)
sleep 2
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Host: locked" http://127.0.0.1:9001/)
if [ "$code" = 401 ]; then ok "Basic Auth denies unauthenticated request"; else bad "Basic Auth" "HTTP $code"; fi
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -u admin:s3cret -H "Host: locked" http://127.0.0.1:9001/)
if [ "$code" = 200 ]; then ok "Basic Auth accepts valid credentials"; else bad "Basic Auth credentials" "HTTP $code"; fi

echo "-- WebSocket control --"
"$CLIENT" http "$WEB_PORT" --subdomain wstest --server ws://127.0.0.1:9001/control \
  --token "$TOKEN" --no-tls --name smoke-ws >"$LOGDIR/client-ws.log" 2>&1 &
PIDS+=($!)
sleep 2
if served wstest; then ok "WebSocket control forwards traffic"; else bad "WebSocket control" "$(tunneled_body wstest | head -c 80)"; fi

echo "-- invalid token --"
"$CLIENT" http "$WEB_PORT" --subdomain noauth --server 127.0.0.1:9000 --token WRONG --no-tls \
  >"$LOGDIR/client-badtoken.log" 2>&1
if grep -qi rejected "$LOGDIR/client-badtoken.log"; then ok "invalid token is rejected"; else bad "invalid token" "$(tail -2 "$LOGDIR/client-badtoken.log")"; fi

echo "-- dashboard/status --"
count=$(curl -s -m 10 http://127.0.0.1:9090/api/tunnels | python -c "import json,sys; print(json.load(sys.stdin)['tunnel_count'])" 2>&1)
if [ -n "$count" ] && [ "$count" -ge 2 ]; then ok "dashboard reports active forwardings"; else bad "dashboard" "$count"; fi
out=$(env -u ARITUN_SERVER -u ARITUN_ADMIN "$CLIENT" status --server 127.0.0.1:9000 2>&1)
if echo "$out" | grep -q "AriTun forwarding rule(s) active"; then ok "status derives dashboard URL"; else bad "status derivation" "${out:0:120}"; fi

python -I ./test/socks5_server.py --port "$SOCKS_PORT" --quiet >"$LOGDIR/socks.log" 2>&1 &
PIDS+=($!)
sleep 1

echo "-- port discovery safety --"
"$CLIENT" all --ports "$WEB_PORT,$SOCKS_PORT" --http-ports "$WEB_PORT" --server 127.0.0.1:9000 \
  --token "$TOKEN" --no-tls --proxy "socks5://127.0.0.1:$SOCKS_PORT" --name smoke-all-safe \
  >"$LOGDIR/client-allsafe.log" 2>&1 &
PIDS+=($!)
sleep 3
if grep -q "localhost:$SOCKS_PORT" "$LOGDIR/client-allsafe.log"; then bad "proxy exclusion" "proxy was published"; else ok "SOCKS proxy port is excluded"; fi
if grep -q "localhost:9000" "$LOGDIR/client-allsafe.log"; then bad "control exclusion" "control port was published"; else ok "server control port is excluded"; fi
if grep -q "localhost:$WEB_PORT" "$LOGDIR/client-allsafe.log"; then ok "explicit service port is published"; else bad "explicit port" "port missing"; fi

"$CLIENT" http "$WEB_PORT" --subdomain proxied --server 127.0.0.1:9000 --token "$TOKEN" --no-tls \
  --proxy "socks5://127.0.0.1:$SOCKS_PORT" --name smoke-proxy >"$LOGDIR/client-proxy.log" 2>&1 &
PIDS+=($!)
sleep 3
if served proxied; then ok "SOCKS5-proxied client forwards traffic"; else bad "SOCKS5 proxy" "$(tunneled_body proxied | head -c 80)"; fi
if grep -qi "proxy:" "$LOGDIR/client-proxy.log"; then ok "client reports active proxy"; else bad "proxy banner" "$(head -2 "$LOGDIR/client-proxy.log")"; fi

"$CLIENT" http "$WEB_PORT" --server 127.0.0.1:9000 --token "$TOKEN" --no-tls \
  --proxy "http://127.0.0.1:1" >"$LOGDIR/client-badproxy.log" 2>&1
if grep -qi "not supported" "$LOGDIR/client-badproxy.log"; then ok "unsupported proxy scheme is rejected"; else bad "bad proxy scheme" "$(tail -2 "$LOGDIR/client-badproxy.log")"; fi

echo "-- disconnect cleanup and re-register --"
stop_pid "$TESTAPP_PID"
sleep 2
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Host: testapp" http://127.0.0.1:9001/)
if [ "$code" = 404 ]; then ok "disconnected subdomain is released"; else bad "cleanup" "HTTP $code"; fi
"$CLIENT" http "$WEB_PORT" --subdomain testapp --server 127.0.0.1:9000 --token "$TOKEN" --no-tls \
  --name smoke-reconnect >"$LOGDIR/client-re.log" 2>&1 &
PIDS+=($!)
sleep 3
if served testapp; then ok "released subdomain can be registered again"; else bad "re-register" "$(tunneled_body testapp | head -c 80)"; fi

echo "==============================="
echo "  $pass passed, $fail failed"
echo "==============================="
[ "$fail" -eq 0 ]
