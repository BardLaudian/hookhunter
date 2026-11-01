"""Allow-list CONNECT proxy: the only way out of the agent network (docs/DECISIONS.md sections 4 and 15).

Agent containers sit on an ``--internal`` Docker network and can reach nothing but this proxy. It tunnels
HTTPS (CONNECT) to the allow-listed ``host:port`` pairs and refuses everything else, plain HTTP included.
Denied attempts are logged to stderr so the allow-list can be kept to what Claude Code strictly needs.
Standard library only, so it runs in a bare python image.
"""

from __future__ import annotations

import socket
import sys
import threading
from socketserver import StreamRequestHandler, ThreadingTCPServer

ALLOWED = frozenset({("api.anthropic.com", 443)})
MAX_HEADER = 16 * 1024


def parse_connect(line: str) -> tuple[str, int] | None:
    """``CONNECT host:port HTTP/1.1`` -> (host, port); None for anything else."""
    parts = line.strip().split()
    if len(parts) != 3 or parts[0].upper() != "CONNECT" or not parts[2].upper().startswith("HTTP/"):
        return None
    host, sep, port = parts[1].rpartition(":")
    if not sep or not host or not port.isdigit():
        return None
    return host.lower().strip("[]"), int(port)


def is_allowed(target: tuple[str, int], allowed: frozenset[tuple[str, int]] = ALLOWED) -> bool:
    return target in allowed


def _pipe(src: socket.socket, dst: socket.socket) -> None:
    try:
        while data := src.recv(65536):
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


class Handler(StreamRequestHandler):
    allowed: frozenset[tuple[str, int]] = ALLOWED

    def handle(self) -> None:
        request = self.rfile.readline(MAX_HEADER).decode("latin-1")
        size = len(request)
        while True:  # discard the remaining headers
            line = self.rfile.readline(MAX_HEADER)
            size += len(line)
            if line in (b"\r\n", b"\n", b"") or size > MAX_HEADER:
                break
        target = parse_connect(request)
        if target is None or not is_allowed(target, self.allowed):
            print(f"DENY {request.strip()[:200]!r}", file=sys.stderr, flush=True)
            self.wfile.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            return
        try:
            upstream = socket.create_connection(target, timeout=20)
        except OSError as exc:
            print(f"FAIL {target[0]}:{target[1]} {exc}", file=sys.stderr, flush=True)
            self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            return
        print(f"ALLOW {target[0]}:{target[1]}", file=sys.stderr, flush=True)
        self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        self.wfile.flush()
        client = self.request
        t = threading.Thread(target=_pipe, args=(upstream, client), daemon=True)
        t.start()
        _pipe(client, upstream)
        t.join(timeout=5)
        upstream.close()


class Server(ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve(host: str = "0.0.0.0", port: int = 3128, allowed: frozenset[tuple[str, int]] = ALLOWED) -> None:
    handler = type("BoundHandler", (Handler,), {"allowed": allowed})
    with Server((host, port), handler) as srv:
        print(f"proxy on {host}:{port}, allow-list {sorted(allowed)}", file=sys.stderr, flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    serve()
