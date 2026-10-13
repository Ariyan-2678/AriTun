# AriTun — راه‌اندازی و استفاده

## ۱ — انتخاب و ساخت باینری

| سیستم مقصد | باینری سرور | باینری کلاینت |
|---|---|---|
| Linux amd64 | `dist/aritund-linux-amd64` | `dist/aritun-linux-amd64` |
| Linux arm64 | `dist/aritund-linux-arm64` | `dist/aritun-linux-arm64` |
| Windows amd64 | `dist/aritund-windows-amd64.exe` | `dist/aritun-windows-amd64.exe` |
| Windows arm64 | `dist/aritund-windows-arm64.exe` | `dist/aritun-windows-arm64.exe` |
| macOS amd64 / arm64 | `dist/aritund-darwin-*` | `dist/aritun-darwin-*` |

با Go نصب‌شده، از ریشه‌ی پروژه:

```bash
./build.sh              # Linux server + Windows/Linux clients
./build.sh all          # هر شش سیستم/معماری
./build.sh linux/arm64  # فقط یک target
```

## ۲ — دامنه و DNS

در DNS این دو رکورد را به IP سرور بده؛ در Cloudflare روی **DNS only** بگذار:

| نوع | نام | مقدار |
|---|---|---|
| A | `aritun` | `<SERVER_IP>` |
| A | `*.aritun` | `<SERVER_IP>` |

در مثال‌های این راهنما `aritun.yourdomain.com` را با دامنه‌ی خودت عوض کن.

## ۳ — Caddy با TLS wildcard

Wildcard certificate با DNS-01 ساخته می‌شود. Caddy را با هر دو addon بساز و نسخه را pin کن:

```bash
CGO_ENABLED=0 go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
export GOPROXY="https://proxy.golang.org,direct"
xcaddy build v2.11.7 \
  --with github.com/caddy-dns/cloudflare \
  --with github.com/caddyserver/caddy/v2/modules/caddytls
sudo install -m755 caddy /usr/local/bin/caddy
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/caddy
```

هر دو addon لازم‌اند: Cloudflare provider به‌تنهایی کافی نیست؛ `caddytls` لازم است تا Caddyfile adapter، DNS challenge را درست بارگذاری کند. توکن Cloudflare را به `Zone / DNS / Edit` در همان zone محدود کن و در فایل Caddyfile نچسبان.

```bash
sudo cp Caddyfile.example /etc/caddy/Caddyfile
sudo sed -i "s|aritun\\.yourdomain\\.com|${DOMAIN}|g; s|YOUR_CLOUDFLARE_API_TOKEN|${CLOUDFLARE_API_TOKEN}|g" /etc/caddy/Caddyfile
```

Caddyfile نمونه فقط `${DOMAIN}` و `*.${DOMAIN}` را به `127.0.0.1:9001` می‌فرستد.

برای سرویس systemd از [`install/caddy.service`](install/caddy.service) استفاده کن. Caddy به `HOME` و storage قابل‌نوشتن برای کاربر `caddy` نیاز دارد و برای bind به پورت‌های ۸۰/۴۴۳ باید capability داشته باشد:

```bash
sudo chown -R caddy:caddy /var/lib/caddy
sudo cp install/caddy.service /etc/systemd/system/caddy.service
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/caddy
sudo systemctl daemon-reload
sudo systemctl enable --now caddy
```

## ۴ — نصب سرور AriTun

```bash
sudo useradd -r -M -s /usr/sbin/nologin aritun 2>/dev/null || true
sudo install -d -o root -g aritun -m 0750 /etc/aritun
sudo install -d -o aritun -g aritun -m 0700 /var/lib/aritun
sudo install -m755 dist/aritund-linux-amd64 /usr/local/bin/aritund
sudo /usr/local/bin/aritund --gen-token | sudo tee /etc/aritun/token
sudo chown root:aritun /etc/aritun/token
sudo chmod 0640 /etc/aritun/token
```

سرویس template را نصب کن:

```bash
sudo cp install/aritund.service /etc/systemd/system/aritund.service
```

`ARITUN_DOMAIN` را با دامنه‌ی خودت تنظیم کن. اگر clients با public IP وصل می‌شوند، آن IP را در `ARITUN_CONTROL_HOSTS` اضافه کن تا SAN گواهی کنترل آن را پوشش دهد. سپس:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aritund
sudo systemctl status aritund
sudo journalctl -u aritund -n 30 --no-pager
```

فایروال:

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 20000:20999/tcp
```

پورت‌های `9001` و `9090` فقط روی loopback بمانند؛ مستقیم به اینترنت بازشان نکن.

## ۵ — تنظیم Windows client

PowerShell؛ بعد از `setx` یک ترمینال تازه باز کن:

```powershell
setx ARITUN_SERVER "wss://aritun.yourdomain.com/control"
setx ARITUN_TOKEN "<توکن سرور>"
setx ARITUN_PROXY "socks5://127.0.0.1:10808"
```

Caddy با Let’s Encrypt گواهی عمومی می‌دهد، پس `ARITUN_CA` را تنظیم نکن. اگر از self-signed certificate استفاده می‌کنی، فقط آن‌وقت مسیر PEM را در `ARITUN_CA` قرار بده.

## ۶ — استفاده

در PowerShell از پوشه‌ی `dist`:

```powershell
.\aritun-windows-amd64.exe http 3000
.\aritun-windows-amd64.exe http 8080 --subdomain demo --auth user:pass
.\aritun-windows-amd64.exe tcp 3389
.\aritun-windows-amd64.exe all --ports 3000,3389
.\aritun-windows-amd64.exe status
```

- `http <port>` یک HTTPS URL می‌دهد.
- `tcp <port>` یک public TCP port از محدوده‌ی تنظیم‌شده در سرور می‌گیرد.
- `all` listenerها را پیدا می‌کند؛ proxy/server ports و پورت‌های حساس را حذف می‌کند. قبل از انتشار همه‌ی سرویس‌ها، پورت‌ها را محدود و بازبینی کن.

## ۷ — تست و توسعه

```bash
go test ./...
go vet ./...
./test/smoke.sh
./test/smoke_tls_all.sh
```

برای تست محلی بدون TLS، `aritund --control-addr 127.0.0.1:9000 --control-tls=false --token dev` را اجرا کن؛ بعد یک سرویس محلی و `aritun http 3000 --server 127.0.0.1:9000 --token dev --no-tls` را اجرا کن.

## ۸ — GitHub

مخزن: `https://github.com/Ariyan-2678/aritun`
