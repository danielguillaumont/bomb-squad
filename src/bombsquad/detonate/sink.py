"""The local sink: the only thing on the detonation network.

It answers every DNS A query with its own address, accepts TCP connections on common ports,
and records each attempt as one JSON line on standard output: DNS names, ports, the first
bytes sent, the HTTP request line and Host header, and the TLS server name. It answers
nothing useful. It runs in its own container, so the package cannot change what it records.

TLS is read too. The sink makes a certificate authority for the run, whose certificate the
package's container trusts and whose key never leaves the sink. For each server name a
client asks for, it issues a certificate, completes the handshake, and records what the
client then sends. A client that does not trust the authority fails the handshake, and only
its server name is recorded.

Standard library only, plus the `openssl` command for the certificates: this file is copied
into the sink image and run as `python sink.py`.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

TCP_PORTS = (21, 22, 25, 80, 443, 587, 1337, 3000, 4444, 5000, 6667, 8000, 8080, 8443, 9001)
MAX_BYTES = 65536  # kept per connection
MAX_EVENTS = 5000
READ_SECONDS = 3.0
MAX_HELLO = 16384 + 5  # one TLS record
MAX_NAMES = 256  # server names given a certificate; later ones are not decrypted
HOST_NAME = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?")

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


# TLS ------------------------------------------------------------------------------------------

_CA_CONFIG = """[req]
distinguished_name = dn
prompt = no
[dn]
CN = Detonation sink CA
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
"""
_LEAF_CONFIG = """[req]
distinguished_name = dn
prompt = no
[dn]
CN = Detonation sink
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = DNS:{name}
"""


class Authority:
    """A certificate authority made for one run, and a certificate for each server name.

    Its files live in `folder`, inside the sink's container. Names are checked against
    HOST_NAME before they reach a configuration file, and `openssl` is given argument lists,
    never a shell."""

    def __init__(self, folder: Path, openssl: str = "openssl") -> None:
        self.folder = folder
        self.openssl = openssl
        self._lock = threading.Lock()
        self._contexts: dict[str, ssl.SSLContext] = {}
        self._key("ca.key")
        self._key("leaf.key")
        (folder / "ca.cnf").write_text(_CA_CONFIG, encoding="ascii")
        self._openssl("req", "-new", "-x509", "-key", "ca.key", "-config", "ca.cnf",
                      "-extensions", "ca", "-days", "2", "-set_serial", _serial(),
                      "-out", "ca.pem")
        self.pem = (folder / "ca.pem").read_text(encoding="ascii")

    def _openssl(self, *args: str) -> None:
        subprocess.run([self.openssl, *args], cwd=self.folder, check=True,
                       capture_output=True, timeout=30)

    def _key(self, name: str) -> None:
        self._openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", name)

    def context(self, name: str | None) -> ssl.SSLContext | None:
        """A server context with a certificate for `name`, or None when the name is not a
        host name or too many names have been seen."""
        if not name or not HOST_NAME.fullmatch(name):
            return None
        name = name.lower().rstrip(".")
        with self._lock:
            if name in self._contexts:
                return self._contexts[name]
            if len(self._contexts) >= MAX_NAMES:
                return None
            stem = f"leaf-{len(self._contexts)}"
            (self.folder / f"{stem}.cnf").write_text(_LEAF_CONFIG.format(name=name),
                                                     encoding="ascii")
            self._openssl("req", "-new", "-key", "leaf.key", "-config", f"{stem}.cnf",
                          "-out", f"{stem}.csr")
            self._openssl("x509", "-req", "-in", f"{stem}.csr", "-CA", "ca.pem", "-CAkey",
                          "ca.key", "-set_serial", _serial(), "-days", "2", "-extfile",
                          f"{stem}.cnf", "-extensions", "leaf", "-out", f"{stem}.pem")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.folder / f"{stem}.pem", self.folder / "leaf.key")
            context.set_alpn_protocols(["http/1.1"])
            self._contexts[name] = context
            return context


def _serial() -> str:
    return str(secrets.randbits(63) + 1)


def peek_hello(conn: socket.socket) -> bytes | None:
    """The first bytes the client sends, left unread, waiting for a whole TLS record when
    they start one. None when the client sends nothing in time."""
    deadline = time.monotonic() + READ_SECONDS
    while True:
        try:
            data = conn.recv(MAX_HELLO, socket.MSG_PEEK)
        except OSError:
            return None
        if not data or data[0] != 0x16 or (
                len(data) >= 5 and len(data) >= 5 + struct.unpack("!H", data[3:5])[0]):
            return data
        if time.monotonic() > deadline:
            return data
        time.sleep(0.05)


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


def _read(stream: socket.socket) -> bytes:
    """What the client sends, up to MAX_BYTES; an HTTP request is answered with a 404."""
    data = b""
    try:
        while len(data) < MAX_BYTES:
            chunk = stream.recv(4096)
            if not chunk:
                break
            data += chunk
            head, sep, body = data.partition(b"\r\n\r\n")
            if sep and http_request(data) and len(body) >= min(_content_length(head),
                                                               MAX_BYTES):
                stream.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n"
                               b"Connection: close\r\n\r\n")
                break
    except OSError:
        pass
    return data


def handle(conn: socket.socket, port: int, peer: str,
           authority: Authority | None = None) -> None:
    conn.settimeout(READ_SECONDS)
    data, sni, tls = b"", None, None
    try:
        hello = peek_hello(conn)
        if hello and hello[0] == 0x16:
            sni = server_name(hello)
            try:
                context = authority.context(sni) if authority else None
            except (OSError, subprocess.SubprocessError, ssl.SSLError):
                context = None
            if context is None:
                tls, data = "not decrypted", _read(conn)
            else:
                conn = context.wrap_socket(conn, server_side=True,
                                           do_handshake_on_connect=False)
                try:
                    conn.do_handshake()
                except OSError:  # ssl.SSLError included: the client refused the certificate
                    tls, data = "handshake failed", hello
                else:
                    tls, data = "decrypted", _read(conn)
        elif hello:
            data = _read(conn)
    finally:
        conn.close()
    emit({"kind": "tcp", "port": port, "peer": peer, "bytes": len(data),
          "http": http_request(data), "sni": sni or server_name(data), "tls": tls,
          "data": base64.b64encode(data[:MAX_BYTES]).decode()})


def serve_tcp(port: int, authority: Authority | None) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(64)
    while True:
        conn, peer = sock.accept()
        threading.Thread(target=handle, args=(conn, port, peer[0], authority),
                         daemon=True).start()


def main() -> None:
    address = socket.gethostbyname(socket.gethostname())
    try:
        authority: Authority | None = Authority(Path(tempfile.mkdtemp(prefix="sink-")))
    except (OSError, subprocess.SubprocessError) as error:
        authority = None
        emit({"kind": "error", "what": "certificate authority", "error": str(error)[:500]})
    for port in TCP_PORTS:
        threading.Thread(target=serve_tcp, args=(port, authority), daemon=True).start()
    emit({"kind": "ready", "address": address, "ca": authority.pem if authority else None})
    serve_dns(address)


if __name__ == "__main__":
    main()
