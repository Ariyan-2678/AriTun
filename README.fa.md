# AriTun

**زبان‌ها:** [English](README.md) | فارسی

AriTun یک راه‌حل self-hosted برای انتشار سرویس‌های محلی از پشت NAT است — مثل ngrok، ولی روی سرور خودت.

```text
aritun http 3000

  https://swift-fox-42.aritun.example.com  ->  http://localhost:3000
```

برای چند سرویس همزمان:

```text
aritun all

  https://p3000.aritun.example.com  ->  http://localhost:3000
  tcp port 20003                    ->  tcp://localhost:22
```

## شروع سریع

**نصب با npm (پیشنهادی):**

```bash
# کلاینت (روی سیستم خودت)
npm install -g aritun-client

# سرور (روی VPS)
npm install -g aritun-server
```

**یا دانلود مستقیم:** [GitHub Releases](https://github.com/Ariyan-2678/AriTun/releases)

**سرور (لینوکس VPS):**

```bash
aritund --gen-token | sudo tee /etc/aritun/token
# برای Caddy و DNS و systemd به SETUP.md مراجعه کن
```

**کلاینت (روی سیستم خودت):**

```powershell
setx ARITUN_SERVER "wss://yourdomain.com/control"
setx ARITUN_TOKEN "<توکن سرور>"
setx ARITUN_PROXY "socks5://127.0.0.1:10808"   # اختیاری

aritun http 3000
```

راهنمای کامل راه‌اندازی: [SETUP.md](SETUP.md) ([فارسی](SETUP.fa.md))

## معماری

```text
  لپ‌تاپ (پشت NAT)                 سرور AriTun                       اینترنت
 ┌────────────────┐              ┌────────────────────────┐          ┌──────────┐
 │ اپ :3000       │              │ Caddy :443             │          │ مرورگر   │
 │ ssh :22        │◄─ yamux ─────┤ aritund :9001 (HTTP)   │◄─────────┤          │
 │ کلاینت aritun  │  یک session  │ aritund :9443 control  │          └──────────┘
 └────────────────┘              │ محدوده‌ی TCP قابل تنظیم│
                                 └────────────────────────┘
```

- **`aritun`** روی سیستمی اجرا می‌شود که سرویس‌های محلی روی آن هستند.
- **`aritund`** کلاینت‌ها را احراز هویت می‌کند، قوانین forward را ثبت می‌کند و ترافیک عمومی را مسیریابی می‌کند.
- **Caddy** اختیاری است؛ با DNS-01 گواهی wildcard و HTTPS فراهم می‌کند.

کلاینت یک اتصال outbound باز می‌کند. کنترل و دیتا روی yamux mux می‌شوند، پس کلاینت به هیچ mapping ورودی در NAT نیاز ندارد.

## دستورات

| دستور | کاربرد |
|---|---|
| `aritun http <port>` | انتشار یک پورت وب محلی با URL عمومی HTTPS |
| `aritun http <port> --subdomain demo` | انتخاب subdomain عمومی |
| `aritun http <port> --auth user:pass` | محافظت از یک forward با Basic Auth |
| `aritun tcp <port>` | انتشار یک سرویس TCP خام مثل SSH یا RDP |
| `aritun all` | کشف و انتشار listenerهای محلی |
| `aritun all --ports 3000,8080` | انتخاب صریح پورت‌ها |
| `aritun all --exclude 445,135` | حذف پورت‌های مشخص |
| `aritun all --http-only` / `--tcp-only` | انتخاب نوع forward |
| `aritun all --include-ephemeral` | شامل‌کردن پورت‌های موقت (معمولاً ناخواسته) |
| `aritun status` | نمایش forwardهای فعال |
| `aritun version` | نمایش نسخه و پلتفرم |

### پیکربندی کلاینت

| متغیر محیطی | فلگ | کاربرد |
|---|---|---|
| `ARITUN_SERVER` | `--server` | `host:9443` یا `wss://aritun.example.com/control` |
| `ARITUN_TOKEN` | `--token` | توکن مشترک سرور |
| `ARITUN_CA` | `--ca` | فایل PEM وقتی کنترل با گواهی self-signed بالا می‌رود |
| `ARITUN_PROXY` | `--proxy` | پروکسی SOCKS5، مثلاً `socks5://127.0.0.1:10808` |
| `ARITUN_ADMIN` | `--admin` | آدرس داشبورد برای `status` |
| `ARITUN_ADMIN_PORT` | — | پورت داشبورد (پیش‌فرض `9090`) |

## رفتار `all` و نکات امنیتی

کشف پورت از جدول listenerهای سیستم انجام می‌شود (`netstat` در ویندوز، `/proc/net/tcp` در لینوکس). پورت‌های وب شناخته‌شده subdomain می‌گیرند؛ بقیه یک پورت TCP خام عمومی.

پورت‌های سرور و پروکسی SOCKS همیشه حذف می‌شوند، حتی وقتی `--ports` صریح داده شود. پورت‌های سیستمی شناخته‌شده‌ی ویندوز هم حذف می‌شوند. در کشف خودکار، پورت‌های `>=5000` به‌طور پیش‌فرض رد می‌شوند چون معمولاً سوکت‌های خروجی موقت هستند؛ `--include-ephemeral` آن‌ها را اضافه می‌کند. `all` همچنان می‌تواند سرویس‌های حساس را منتشر کند — با یک لیست صریح `--ports` شروع کن و بازبینی‌اش کن.

توکن سرور را محرمانه نگه دار. داشبورد را روی loopback نگه دار یا جلویش احراز هویت بگذار. در شبکه‌هایی که اتصال مستقیم را مختل می‌کنند، `ARITUN_PROXY` را تنظیم کن یا `--proxy socks5://...` بده.

## توسعه و تست

```bash
go test ./...
go vet ./...
./test/smoke.sh
./test/smoke_tls_all.sh
```

اسکریپت‌های smoke پروسه‌های محلی سرور/کلاینت AriTun را اجرا می‌کنند و متغیرهای endpoint ارث‌برده‌شده را پاک می‌کنند، تا تصادفاً به یک VPS واقعی وصل نشوند.

## ساختار مخزن

```text
cmd/aritun/         کلاینت CLI
cmd/aritund/        سرور daemon
internal/client/    اتصال، پروکسی SOCKS5، کشف پورت، reconnect
internal/server/    sessionها، مسیریابی، registry، داشبورد
internal/protocol/  handshake، پیام‌ها، framing روی yamux
internal/tlsutil/   گواهی self-signed کنترل
npm/aritun-client/  پکیج npm (کلاینت)
npm/aritun-server/  پکیج npm (سرور)
scripts/            بسته‌بندی ریلیز
test/               تست‌های unit و end-to-end
install/            تمپلیت‌های systemd
```
