"""Minimal SOCKS5 relay used to exercise the client's --proxy code path.

Only RFC 1928 no-auth CONNECT is implemented, which is all the client needs
when no credentials are configured. Anything else is refused with the proper
SOCKS5 status code rather than hanging.
"""

import argparse
import socket
import struct
import threading

REP = {
    0x00: "succeeded",
    0x01: "general server failure",
    0x02: "connection not allowed",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x07: "command not supported",
    0x08: "address type not supported",
}


def reply(conn, code, addr=("0.0.0.0", 0)):
    host, port = addr
    try:
        packed = socket.inet_aton(host)
        atyp = 1
    except OSError:
        packed = socket.inet_pton(socket.AF_INET6, host) if ":" in host else socket.inet_aton(host)
        atyp = 4 if ":" in host else 1
    conn.sendall(b"\x05" + bytes([code, 0x00, atyp]) + packed + struct.pack("!H", port))


def _recv(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("short read")
        buf += chunk
    return buf


def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client, log):
    try:
        ver, nm = _recv(client, 2)
        if ver != 5:
            client.close()
            return
        methods = _recv(client, nm)
        if 0x00 not in methods:
            client.sendall(b"\x05\xff")
            client.close()
            return
        client.sendall(b"\x05\x00")

        ver, cmd, _, atyp = _recv(client, 4)
        if ver != 5:
            client.close()
            return
        if cmd != 1:  # only CONNECT
            reply(client, 0x07)
            client.close()
            return

        # Re-read the address; read_target expects the atyp byte already read.
        if atyp == 1:
            host = socket.inet_ntoa(_recv(client, 4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, _recv(client, 16))
        else:
            n = _recv(client, 1)[0]
            host = _recv(client, n).decode("idna", "replace")
        port = struct.unpack("!H", _recv(client, 2))[0]

        try:
            upstream = socket.create_connection((host, port), 10)
        except OSError as exc:
            log(f"  connect refused {host}:{port} -> {exc}")
            reply(client, 0x05)
            return

        reply(client, 0x00, upstream.getsockname()[:2])
        log(f"  relay {host}:{port} -> {upstream.getpeername()}")
        t = threading.Thread(target=pipe, args=(upstream, client), daemon=True)
        t.start()
        pipe(client, upstream)
        t.join(timeout=5)
    except Exception as exc:
        log(f"  handler error: {type(exc).__name__}: {exc}")
    finally:
        client.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=10809)
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    def log(msg):
        if not args.quiet:
            print(msg, flush=True)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.port))
    srv.listen(64)
    print(f"socks5 listening on {args.bind}:{args.port}", flush=True)

    while True:
        client, _ = srv.accept()
        threading.Thread(target=handle, args=(client, log), daemon=True).start()


if __name__ == "__main__":
    main()
