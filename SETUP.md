# AriTun — Setup & Usage

**Languages:** English | [فارسی](SETUP.fa.md)

## 1 — Choose and build binaries

| Target | Server binary | Client binary |
|---|---|---|
| Linux amd64 | `dist/aritund-linux-amd64` | `dist/aritun-linux-amd64` |
| Linux arm64 | `dist/aritund-linux-arm64` | `dist/aritun-linux-arm64` |
| Windows amd64 | `dist/aritund-windows-amd64.exe` | `dist/aritun-windows-amd64.exe` |
| Windows arm64 | `dist/aritund-windows-arm64.exe` | `dist/aritun-windows-arm64.exe` |
| macOS amd64 / arm64 | `dist/aritund-darwin-*` | `dist/aritun-darwin-*` |

With Go installed, from the project root:

```bash
./build.sh              # Linux server + Windows/Linux clients
./build.sh all          # all six platform/arch combinations
./build.sh linux/arm64  # a single target
```

## 2 — Domain and DNS

Point these two records at the server IP. In Cloudflare, keep them **DNS only**:

| Type | Name | Value |
|---|---|---|
| A | `aritun` | `<SERVER_IP>` |
| A | `*.aritun` | `<SERVER_IP>` |

In the examples below, replace `aritun.yourdomain.com` with your own domain.

## 3 — Caddy with wildcard TLS

The wildcard certificate is obtained via DNS-01. Build Caddy with both addons and pin the version:

```bash
CGO_ENABLED=0 go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
export GOPROXY="https://proxy.golang.org,direct"
xcaddy build v2.11.7 \
  --with github.com/caddy-dns/cloudflare \
  --with github.com/caddyserver/caddy/v2/modules/caddytls
sudo install -m755 caddy /usr/local/bin/caddy
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/caddy
```

Both addons are required: the Cloudflare provider alone is not enough — `caddytls` is needed so the Caddyfile adapter loads the DNS challenge correctly. Scope the Cloudflare token to `Zone / DNS / Edit` on the same zone, and do not paste it into a file.

```bash
sudo cp Caddyfile.example /etc/caddy/Caddyfile
sudo sed -i "s|aritun\\.yourdomain\\.com|${DOMAIN}|g; s|YOUR_CLOUDFLARE_API_TOKEN|${CLOUDFLARE_API_TOKEN}|g" /etc/caddy/Caddyfile
```

The example Caddyfile only forwards `${DOMAIN}` and `*.${DOMAIN}` to `127.0.0.1:9001`.

Use the systemd unit at [`install/caddy.service`](install/caddy.service). Caddy needs a writable `HOME` and storage for the `caddy` user, plus the capability to bind ports 80/443:

```bash
sudo chown -R caddy:caddy /var/lib/caddy
sudo cp install/caddy.service /etc/systemd/system/caddy.service
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/caddy
sudo systemctl daemon-reload
sudo systemctl enable --now caddy
```

## 4 — Install the AriTun server

```bash
sudo useradd -r -M -s /usr/sbin/nologin aritun 2>/dev/null || true
sudo install -d -o root -g aritun -m 0750 /etc/aritun
sudo install -d -o aritun -g aritun -m 0700 /var/lib/aritun
sudo install -m755 dist/aritund-linux-amd64 /usr/local/bin/aritund
sudo /usr/local/bin/aritund --gen-token | sudo tee /etc/aritun/token
sudo chown root:aritun /etc/aritun/token
sudo chmod 0640 /etc/aritun/token
```

Install the service template:

```bash
sudo cp install/aritund.service /etc/systemd/system/aritund.service
```

Set `ARITUN_DOMAIN` to your domain. If clients connect from a public IP, add that IP to `ARITUN_CONTROL_HOSTS` so the control certificate's SAN covers it. Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aritund
sudo systemctl status aritund
sudo journalctl -u aritund -n 30 --no-pager
```

Firewall:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 20000:20999/tcp
```

Keep ports `9001` and `9090` bound to loopback; never expose them directly to the internet.

## 5 — Configure the Windows client

PowerShell — open a fresh terminal after `setx`:

```powershell
setx ARITUN_SERVER "wss://aritun.yourdomain.com/control"
setx ARITUN_TOKEN "<server token>"
setx ARITUN_PROXY "socks5://127.0.0.1:10808"
```

Caddy issues public certificates via Let's Encrypt, so do not set `ARITUN_CA`. Only set `ARITUN_CA` to a PEM path if you use a self-signed certificate.

## 6 — Usage

In PowerShell, from the `dist` folder:

```powershell
.\aritun-windows-amd64.exe http 3000
.\aritun-windows-amd64.exe http 8080 --subdomain demo --auth user:pass
.\aritun-windows-amd64.exe tcp 3389
.\aritun-windows-amd64.exe all --ports 3000,3389
.\aritun-windows-amd64.exe status
```

- `http <port>` gives you an HTTPS URL.
- `tcp <port>` gets a public TCP port from the range configured on the server.
- `all` finds listeners; it excludes proxy/server ports and sensitive ports. Narrow and review the list before publishing everything.

## 7 — Tests and development

```bash
go test ./...
go vet ./...
./test/smoke.sh
./test/smoke_tls_all.sh
```

For local testing without TLS, run `aritund --control-addr 127.0.0.1:9000 --control-tls=false --token dev`; then start a local service and `aritun http 3000 --server 127.0.0.1:9000 --token dev --no-tls`.

## 8 — GitHub

Repository: `https://github.com/Ariyan-2678/aritun`
