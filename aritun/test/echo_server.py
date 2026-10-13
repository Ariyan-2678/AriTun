"""Tiny TCP echo server used by the end-to-end test."""

import socket
import sys
import threading

port = int(sys.argv[1])


def handle(conn: socket.socket) -> None:
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                return
            conn.sendall(b"ECHO:" + data)


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(16)
print(f"echo listening on {port}", flush=True)

while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
