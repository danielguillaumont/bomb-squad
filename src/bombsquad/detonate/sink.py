"""The local sink: the only thing on the detonation network.

It answers every DNS A query with its own address, accepts TCP connections on common ports,
and records each attempt as one JSON line on standard output: DNS names, ports, the first
bytes sent, the HTTP request line and Host header, and the TLS server name. It answers
nothing useful. It runs in its own container, so the package cannot change what it records.

Standard library only: this file is copied into the sink image and run as `python sink.py`.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
import sys
import threading
import time

TCP_PORTS = (21, 22, 25, 80, 443, 587, 1337, 3000, 4444, 5000, 6667, 8000, 8080, 8443, 9001)
MAX_BYTES = 65536  # kept per connection
MAX_EVENTS = 5000
READ_SECONDS = 3.0

_lock = threading.Lock()
_count = 0


def emit(event: dict) -> None:
    global _count
    with _lock:
        _count += 1
        if _count > MAX_EVENTS:
            if _count == MAX_EVENTS + 1:
                sys.stdout.write(json.dumps({"kind": "truncated", "after": MAX_EVENTS}) + "\n")
                sys.stdout.flush()
            return
        event["t"] = round(time.time(), 3)
        sys.stdout.write(json.dumps(event) + "\n")
        sys.stdout.flush()


# DNS ------------------------------------------------------------------------------------------

def parse_query(packet: bytes) -> tuple[int, str, int, int] | None:
    """(id, name, type, end of the question) of a DNS query, or None."""
    if len(packet) < 12:
        return None
    ident, flags, qdcount = struct.unpack("!HHH", packet[:6])
    if flags & 0x8000 or qdcount < 1:
        return None
    labels, i = [], 12
    while i < len(packet):
        length = packet[i]
        if length == 0:
            i += 1
            break
        if length & 0xC0 or i + 1 + length > len(packet):
            return None
        labels.append(packet[i + 1:i + 1 + length].decode("ascii", "replace"))
        i += 1 + length
    else:
        return None
    if i + 4 > len(packet):
        return None
    qtype, _ = struct.unpack("!HH", packet[i:i + 4])
    return ident, ".".join(labels), qtype, i + 4


def answer(packet: bytes, address: str) -> bytes | None:
    """An answer with `address` for an A query, and no records for anything else."""
    parsed = parse_query(packet)
    if parsed is None:
        return None
    ident, _, qtype, end = parsed
    question = packet[12:end]
    if qtype == 1:
        header = struct.pack("!HHHHHH", ident, 0x8180, 1, 1, 0, 0)
        record = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + socket.inet_aton(address)
        return header + question + record
    return struct.pack("!HHHHHH", ident, 0x8180, 1, 0, 0, 0) + question


def serve_dns(address: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 53))
    while True:
        packet, peer = sock.recvfrom(4096)
        parsed = parse_query(packet)
        emit({"kind": "dns", "peer": peer[0], "name": parsed[1] if parsed else None,
              "qtype": parsed[2] if parsed else None,
              "data": base64.b64encode(packet[:512]).decode()})
        reply = answer(packet, address)
        if reply:
            sock.sendto(reply, peer)


# TCP ------------------------------------------------------------------------------------------

def server_name(data: bytes) -> str | None:
    """The SNI host name of a TLS ClientHello, or None."""
    try:
        if data[0] != 0x16 or data[5] != 0x01:
            return None
        i = 9 + 2 + 32  # record and handshake headers, version, random
        i += 1 + data[i]  # session id
        i += 2 + struct.unpack("!H", data[i:i + 2])[0]  # cipher suites
        i += 1 + data[i]  # compression methods
        end = i + 2 + struct.unpack("!H", data[i:i + 2])[0]
        i += 2
        while i + 4 <= end:
            kind, length = struct.unpack("!HH", data[i:i + 4])
            if kind == 0:
                name_length = struct.unpack("!H", data[i + 7:i + 9])[0]
                return data[i + 9:i + 9 + name_length].decode("ascii", "replace")
            i += 4 + length
    except (IndexError, struct.error):
        return None
    return None


def http_request(data: bytes) -> dict | None:
    head, _, _ = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    parts = lines[0].split(b" ")
    if len(parts) != 3 or not parts[2].startswith(b"HTTP/"):
        return None
    host = next((line.split(b":", 1)[1].strip() for line in lines[1:]
                 if line.lower().startswith(b"host:")), b"")
    return {"method": parts[0].decode("ascii", "replace")[:16],
            "target": parts[1].decode("ascii", "replace")[:512],
            "host": host.decode("ascii", "replace")[:256]}


def _content_length(head: bytes) -> int:
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                return max(0, int(line.split(b":", 1)[1]))
            except ValueError:
                return 0
    return 0


def handle(conn: socket.socket, port: int, peer: str) -> None:
    data = b""
    conn.settimeout(READ_SECONDS)
    try:
        while len(data) < MAX_BYTES:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            head, sep, body = data.partition(b"\r\n\r\n")
            if sep and http_request(data) and len(body) >= min(_content_length(head),
                                                               MAX_BYTES):
                conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                             b"Connection: close\r\n\r\n")
                break
    except OSError:
        pass
    finally:
        conn.close()
    emit({"kind": "tcp", "port": port, "peer": peer, "bytes": len(data),
          "http": http_request(data), "sni": server_name(data),
          "data": base64.b64encode(data[:MAX_BYTES]).decode()})


def serve_tcp(port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    while True:
        conn, peer = sock.accept()
        threading.Thread(target=handle, args=(conn, port, peer[0]), daemon=True).start()


def main() -> None:
    address = socket.gethostbyname(socket.gethostname())
    for port in TCP_PORTS:
        threading.Thread(target=serve_tcp, args=(port,), daemon=True).start()
    emit({"kind": "ready", "address": address})
    serve_dns(address)


if __name__ == "__main__":
    main()
