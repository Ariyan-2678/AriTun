#!/usr/bin/env bash
# TLS control, certificate verification, collision handling, all mode, and status.
set -uo pipefail
cd "$(dirname "$0")/.."

ARITUND=./dist/aritund-windows-amd64.exe
CLIENT=./dist/aritun-windows-amd64.exe
TOKEN=tlsdev
# This suite is local-only; never inherit real server/proxy settings.
unset ARITUN_SERVER ARITUN_TOKEN ARITUN_CA ARITUN_PROXY ARITUN_ADMIN ARITUN_ADMIN_PORT
WEB_PORT=3457
ECHO_PORT=7778
LOGDIR=./devdata/logs-tls
rm -rf ./devdata-tls
mkdir -p "$LOGDIR" ./devdata-tls

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

is_directory_listing() { echo "$1" | grep -qi "Directory listing for"; }

echo "== start local AriTun server with control TLS"
"$ARITUND" --control-addr 127.0.0.1:9443 --control-tls=true \
  --token "$TOKEN" --http-addr 127.0.0.1:9011 --admin-addr 127.0.0.1:9012 \
  --tcp-range 20100-20110 --data-dir ./devdata-tls \
  >"$LOGDIR/server.log" 2>&1 &
PIDS+=($!)

python -m http.server "$WEB_PORT" --bind 127.0.0.1 >"$LOGDIR/web.log" 2>&1 &
PIDS+=($!)
python -I ./test/echo_server.py "$ECHO_PORT" >"$LOGDIR/echo.log" 2>&1 &
PIDS+=($!)
sleep 2

echo
echo "-- generated control certificate --"
if [ -f ./devdata-tls/control-cert.pem ]; then
  ok "self-signed certificate generated on first start"
else
  bad "certificate" "devdata-tls/control-cert.pem missing"
fi

echo
echo "-- client trusts the generated certificate --"
"$CLIENT" http "$WEB_PORT" --subdomain tlsapp --server 127.0.0.1:9443 \
  --token "$TOKEN" --ca ./devdata-tls/control-cert.pem --name tls-ca \
  >"$LOGDIR/client-ca.log" 2>&1 &
PIDS+=($!)
sleep 3
body=$(curl -s -m 10 -H "Host: tlsapp" http://127.0.0.1:9011/ 2>&1)
if is_directory_listing "$body"; then
  ok "TLS control tunnel forwards HTTP"
else
  bad "TLS + --ca" "${body:0:140}"
  tail -3 "$LOGDIR/client-ca.log"
fi

echo
echo "-- reject an untrusted certificate --"
"$CLIENT" http "$WEB_PORT" --subdomain untrusted --server 127.0.0.1:9443 \
  --token "$TOKEN" >"$LOGDIR/client-noca.log" 2>&1
if grep -qiE "unknown authority|certificate" "$LOGDIR/client-noca.log"; then
  ok "client rejects self-signed cert without --ca"
else
  bad "certificate validation" "$(tail -2 "$LOGDIR/client-noca.log")"
fi

echo
echo "-- --insecure escape hatch --"
"$CLIENT" http "$WEB_PORT" --subdomain skipverify --server 127.0.0.1:9443 \
  --token "$TOKEN" --insecure --name tls-insecure \
  >"$LOGDIR/client-insec.log" 2>&1 &
PIDS+=($!)
sleep 3
body=$(curl -s -m 10 -H "Host: skipverify" http://127.0.0.1:9011/ 2>&1)
if is_directory_listing "$body"; then
  ok "--insecure connects and forwards"
else
  bad "--insecure" "${body:0:140}"
fi

echo
echo "-- reject a duplicate subdomain --"
"$CLIENT" http "$WEB_PORT" --subdomain dup --server 127.0.0.1:9443 \
  --token "$TOKEN" --ca ./devdata-tls/control-cert.pem --name first \
  >"$LOGDIR/client-dup1.log" 2>&1 &
PIDS+=($!)
sleep 3
"$CLIENT" http "$WEB_PORT" --subdomain dup --server 127.0.0.1:9443 \
  --token "$TOKEN" --ca ./devdata-tls/control-cert.pem --name second \
  >"$LOGDIR/client-dup2.log" 2>&1 &
PIDS+=($!)
sleep 3
if grep -qi "already in use" "$LOGDIR/client-dup2.log" \
   || curl -s -m 10 http://127.0.0.1:9012/api/tunnels | grep -q '"tunnel_count":3'; then
  ok "second client cannot take an occupied subdomain"
else
  bad "subdomain collision" "$(tail -2 "$LOGDIR/client-dup2.log")"
fi

echo
echo "-- AriTun all mode --"
"$CLIENT" all --ports "$WEB_PORT,$ECHO_PORT" --http-ports "$WEB_PORT" \
  --server 127.0.0.1:9443 --token "$TOKEN" \
  --ca ./devdata-tls/control-cert.pem --name all-mode \
  >"$LOGDIR/client-all.log" 2>&1 &
PIDS+=($!)
sleep 4
body=$(curl -s -m 10 -H "Host: p$WEB_PORT" http://127.0.0.1:9011/ 2>&1)
if is_directory_listing "$body"; then
  ok "all mode publishes the web port"
else
  bad "all (web port)" "${body:0:140}"
  tail -5 "$LOGDIR/client-all.log"
fi

pub=$(curl -s -m 10 http://127.0.0.1:9012/api/tunnels \
  | python -c "import json,sys; d=json.load(sys.stdin); found=[t['public_port'] for t in d['tunnels'] if t['type']=='tcp' and t['local_port']==$ECHO_PORT]; print(found[0] if found else '')" 2>&1)
if [[ "$pub" =~ ^[0-9]+$ ]]; then
  reply=$(python -I -c "import socket; s=socket.create_connection(('127.0.0.1',$pub),5); s.sendall(b'all-mode'); print(s.recv(100).decode()); s.close()")
  if [ "$reply" = "ECHO:all-mode" ]; then
    ok "all mode forwards raw TCP"
  else
    bad "all (TCP)" "got '$reply'"
  fi
else
  bad "all (TCP)" "no TCP forward allocated (got '$pub')"
fi

echo
echo "-- AriTun status --"
out=$("$CLIENT" status --admin http://127.0.0.1:9012 2>&1)
if echo "$out" | grep -q "AriTun forwarding rule(s) active" && echo "$out" | grep -q "all-mode"; then
  ok "status lists active clients"
else
  bad "status" "${out:0:160}"
fi

echo
echo "-- case-insensitive host routing --"
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Host: TLSAPP" http://127.0.0.1:9011/)
if [ "$code" = 200 ]; then ok "uppercase Host routes"; else bad "case folding" "got $code"; fi

echo
echo "-- Host with port suffix --"
code=$(curl -s -m 10 -o /dev/null -w '%{http_code}' -H "Host: tlsapp:443" http://127.0.0.1:9011/)
if [ "$code" = 200 ]; then ok "Host port suffix is stripped"; else bad "port stripping" "got $code"; fi

echo
echo "==============================="
echo "  $pass passed, $fail failed"
echo "==============================="
[ "$fail" -eq 0 ]
