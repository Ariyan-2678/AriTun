# AriTun

AriTun is a self-hosted way to expose local services from behind NAT.

```text
aritun http 3000

  https://swift-fox-42.aritun.example.com  ->  http://localhost:3000
```

For several services at once:

```text
aritun all

  https://p3000.aritun.example.com  ->  http://localhost:3000
  tcp port 20003                    ->  tcp://localhost:22
```

## Architecture

```text
  laptop (behind NAT)               AriTun server                     internet
 ┌────────────────┐              ┌────────────────────────┐          ┌──────────┐
 │ app :3000      │              │ Caddy :443             │          │ browser  │
 │ ssh :22        │◄─ yamux ─────┤ aritund :9001 (HTTP)   │◄─────────┤          │
 │ aritun client  │  one session │ aritund :9443 control  │          └──────────┘
 └────────────────┘              │ configurable TCP range│
                                 └────────────────────────┘
```

- **`aritun`** runs on the machine hosting the local services.
- **`aritund`** authenticates clients, registers forwarding rules, and routes public traffic.
- **Caddy** is optional; it provides HTTPS and wildcard certificates via DNS-01.

The client opens one outbound connection. Control and data streams are multiplexed over yamux, so the client does not need an inbound NAT mapping.

## Commands

| Command | Purpose |
|---|---|
| `aritun http <port>` | Publish a local web port with an HTTPS URL |
| `aritun http <port> --subdomain demo` | Choose the public subdomain |
| `aritun http <port> --auth user:pass` | Protect an HTTP forwarding with Basic Auth |
| `aritun tcp <port>` | Publish a raw TCP service such as SSH or RDP |
| `aritun all` | Discover and publish local listeners |
| `aritun all --ports 3000,8080` | Select ports explicitly |
| `aritun all --exclude 445,135` | Exclude selected ports |
| `aritun all --http-only` / `--tcp-only` | Choose forwarding type |
| `aritun all --include-ephemeral` | Include dynamic ports (usually not desirable) |
| `aritun status` | List active forwardings |
| `aritun version` | Show version and platform |

### Client configuration

| Environment variable | Flag | Purpose |
|---|---|---|
| `ARITUN_SERVER` | `--server` | `host:9443` or `wss://aritun.example.com/control` |
| `ARITUN_TOKEN` | `--token` | Shared server token |
| `ARITUN_CA` | `--ca` | CA PEM when the control endpoint uses a self-signed certificate |
| `ARITUN_PROXY` | `--proxy` | SOCKS5 proxy, e.g. `socks5://127.0.0.1:10808` |
| `ARITUN_ADMIN` | `--admin` | Dashboard URL for `status` |
| `ARITUN_ADMIN_PORT` | — | Dashboard port (default `9090`) |

## `all` behavior and safety

Port discovery uses the OS listener table (`netstat` on Windows, `/proc/net/tcp` on Linux). Common web ports receive HTTP subdomains; other ports receive an allocated raw TCP port.

The server and SOCKS-proxy ports are always excluded, including when `--ports` is supplied. Known Windows system ports are excluded too. During automatic discovery, ports `>=5000` are skipped by default because they are often short-lived outbound sockets; `--include-ephemeral` opts in. `all` can still expose sensitive services—start with an explicit `--ports` list and review it.

Keep the server token secret. Leave the dashboard bound to loopback or put authentication in front of it. On networks that interfere with direct connections, set `ARITUN_PROXY` or pass `--proxy socks5://...`.

## Development and tests

```bash
go test ./...
go vet ./...
./test/smoke.sh
./test/smoke_tls_all.sh
```

The smoke scripts run local AriTun server/client processes and clear inherited endpoint variables, so they do not accidentally connect to a real VPS.

## Repository layout

```text
cmd/aritun/         client CLI
cmd/aritund/        server daemon
internal/client/    dialing, SOCKS5 proxy, discovery, reconnect
internal/server/    sessions, routing, registry, dashboard
internal/protocol/  handshake, messages, yamux framing
internal/tlsutil/   self-signed control certificate
test/               unit and end-to-end tests
install/            systemd templates
```
