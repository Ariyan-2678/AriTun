# aritun-sys

AriTun client — expose local services through your own server (self-hosted ngrok alternative).

## Install

```bash
npm install -g aritun-sys
```

## Usage

```bash
aritun http 3000
aritun tcp 22
aritun all
aritun status
aritun version
```

## Configuration

| Env | Flag | Purpose |
|---|---|---|
| `ARITUN_SERVER` | `--server` | Control endpoint, e.g. `wss://yourdomain.com/control` |
| `ARITUN_TOKEN` | `--token` | Shared server token |
| `ARITUN_PROXY` | `--proxy` | SOCKS5 proxy, e.g. `socks5://127.0.0.1:10808` |

See [AriTun](https://github.com/Ariyan-2678/AriTun) for full documentation.
