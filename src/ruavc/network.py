"""Bounded HTTPS downloads and Reality target qualification."""

import concurrent.futures
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import time
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener, HTTPSHandler

from .errors import Error
from .model import domain, https_url, target


class HTTPSRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit=4 * 1024 * 1024, timeout=20):
    https_url(url)
    # A privileged installer must not inherit an arbitrary caller's proxy.
    opener = build_opener(ProxyHandler({}), HTTPSRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    req = Request(url, headers={"User-Agent": "ruavc/0.1.0", "Accept": "application/vnd.github+json" if "api.github.com/" in url else "*/*"})
    try:
        with opener.open(req, timeout=timeout) as response:
            result = response.read(limit + 1)
            if len(result) > limit:
                raise Error("Загрузка превышает допустимый размер.")
            return result
    except (OSError, ValueError) as exc:
        raise Error(f"Не удалось загрузить данные по HTTPS ({type(exc).__name__}).", "sudo ruavc doctor") from None


def fetch_json(url):
    try:
        return json.loads(fetch(url))
    except (ValueError, UnicodeError):
        raise Error("Источник вернул некорректный JSON.") from None


def detect_address():
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            value = fetch(url, 128, 8).decode().strip()
            ip = ipaddress.IPv4Address(value)
            if ip.is_global:
                return str(ip)
        except (Error, ValueError, UnicodeError):
            continue
    raise Error("Не удалось определить публичный IPv4.", "Установка с --address ПУБЛИЧНЫЙ_IP")


def detect_country():
    for url in ("https://ipinfo.io/country", "https://ipapi.co/country/"):
        try:
            value = fetch(url, 128, 6).decode().strip().upper()
            if len(value) == 2 and value.isascii() and value.isalpha():
                return value
        except (Error, UnicodeError):
            continue
    return ""


def public_dns(host):
    ips = sorted({x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise Error("Reality target должен разрешаться только в публичные IP.")
    return ips


def tls_probe(host, number, sni, public=True, timeout=6):
    domain(sni)
    start = time.monotonic()
    ips = public_dns(host) if public else [host]
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    last = None
    for ip in ips:
        try:
            with socket.create_connection((ip, number), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=sni) as sock:
                    alpn = sock.selected_alpn_protocol()
                    version = sock.version()
        except OSError as exc:
            last = type(exc).__name__
            continue
        flight = reality_flight(ip, number, sni, timeout)
        return {"host": host, "sni": sni, "port": number, "ip": ip, "tls": version, "alpn": alpn,
                "latency_ms": round((time.monotonic() - start) * 1000), "certificate_valid": True, "first_flight_bytes": flight}
    raise Error(f"Reality target: не прошли TCP/TLS 1.3 и проверка сертификата ({last}).", "sudo ruavc reality check")


# REALITY copies the target's first TLS flight into a fixed buffer
# (xtls/reality tls.go: size = 8192, header included) and aborts the handshake
# for every client when the flight is larger. Browser fingerprints request OCSP
# stapling, SCTs and certificate compression; the probe offers the same, so a
# target whose stapled chain is sent uncompressed is rejected before use.
REALITY_FLIGHT_LIMIT = 8192
# Current fingerprints offer X25519MLKEM768; its ServerHello share is 1088 bytes
# longer than the X25519 share this probe requests.
HYBRID_SHARE_EXTRA = 1120 - 32
HELLO_RETRY = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def _extension(kind, body):
    return struct.pack("!HH", kind, len(body)) + body


def client_hello(sni):
    name = domain(sni).encode()
    alpn = b"".join(bytes([len(x)]) + x for x in (b"h2", b"http/1.1"))
    signatures = bytes.fromhex("040308040401050308050501080606010201")
    extensions = b"".join((
        _extension(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name),
        _extension(5, b"\x01\x00\x00\x00\x00"),
        _extension(10, bytes.fromhex("0006001d00170018")),
        _extension(13, struct.pack("!H", len(signatures)) + signatures),
        _extension(16, struct.pack("!H", len(alpn)) + alpn),
        _extension(18, b""),
        _extension(27, b"\x04\x00\x02\x00\x01"),
        _extension(43, b"\x02\x03\x04"),
        _extension(45, b"\x01\x01"),
        _extension(51, struct.pack("!HHH", 36, 0x1d, 32) + secrets.token_bytes(32)),
    ))
    body = (b"\x03\x03" + secrets.token_bytes(32) + b"\x20" + secrets.token_bytes(32)
            + bytes.fromhex("0006130113021303") + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions)
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def _exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionAbortedError("target closed the connection")
        data += chunk
    return data


def _server_hello(payload):
    if len(payload) < 4 or payload[0] != 2 or int.from_bytes(payload[1:4], "big") != len(payload) - 4:
        return False
    body = payload[4:]
    try:
        if body[:2] != b"\x03\x03" or body[2:34] == HELLO_RETRY:
            return False
        at = 35 + body[34]
        if body[at:at + 2] not in (b"\x13\x01", b"\x13\x02", b"\x13\x03") or body[at + 2] != 0:
            return False
        at += 3
        end = at + 2 + struct.unpack("!H", body[at:at + 2])[0]
        at += 2
        found = set()
        while at < end:
            kind, size = struct.unpack("!HH", body[at:at + 4])
            data = body[at + 4:at + 4 + size]
            if kind == 43 and data == b"\x03\x04":
                found.add("tls13")
            if kind == 51 and len(data) >= 4:
                group, length = struct.unpack("!HH", data[:4])
                if (group, length) in ((0x1d, 32), (0x11ec, 1120)) and len(data) == 4 + length:
                    found.add("x25519")
            at += 4 + size
    except (IndexError, struct.error):
        return False
    return found == {"tls13", "x25519"}


def reality_flight(ip, number, sni, timeout=6):
    """Mirror REALITY's target qualification on the records it actually copies."""
    try:
        with socket.create_connection((ip, number), timeout=timeout) as sock:
            sock.sendall(client_hello(sni))
            total = 0
            for index in range(6):
                header = _exact(sock, 5)
                size = struct.unpack("!H", header[3:5])[0]
                total += 5 + size
                if total + HYBRID_SHARE_EXTRA > REALITY_FLIGHT_LIMIT:
                    raise Error(f"Reality target несовместим: первый ответ TLS больше {REALITY_FLIGHT_LIMIT} байт (длинная цепочка сертификатов или OCSP).", "sudo ruavc reality auto")
                payload = _exact(sock, size)
                expected = (22, 20)[index] if index < 2 else 23
                if header[:3] != bytes([expected, 3, 3]) or (index == 0 and not _server_hello(payload)) or (index == 1 and payload != b"\x01"):
                    raise Error("Reality target несовместим: ответ TLS 1.3 не подходит для REALITY (X25519, отдельные записи).", "sudo ruavc reality auto")
                if index == 2 and 5 + size > 512:
                    break
            return total + HYBRID_SHARE_EXTRA
    except OSError as exc:
        raise Error(f"Reality target: не удалось получить первый ответ TLS ({type(exc).__name__}).", "sudo ruavc reality check") from None


# A replaceable candidate provider, not a target baked into the Xray renderer.
# Diversity covers independent operators and regions. Availability is measured on
# the VPS; no candidate is silently accepted merely because it is in this list.
CANDIDATES = (
    "www.apple.com", "www.samsung.com", "www.sony.com",
    "www.nvidia.com", "www.amd.com", "www.intel.com", "www.dell.com",
    "www.hp.com", "www.lenovo.com", "www.asus.com", "www.logitech.com",
    "www.adobe.com", "www.autodesk.com", "www.mozilla.org", "www.wikipedia.org",
    "www.bing.com", "www.amazon.com", "www.oracle.com", "www.ibm.com",
)


def choose_target(extra=()):
    candidates = list(dict.fromkeys([domain(x) for x in extra] + list(CANDIDATES)))
    good = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        jobs = [pool.submit(tls_probe, host, 443, host) for host in candidates]
        for job in concurrent.futures.as_completed(jobs):
            try:
                result = job.result()
                if result["alpn"] == "h2":
                    good.append(result)
            except (Error, OSError):
                pass
    if not good:
        raise Error("Подходящий Reality target не найден: нужны TLS 1.3, сертификат SNI и HTTP/2.", "Установка с --target ДОМЕН:443 --sni ДОМЕН")
    return min(good, key=lambda x: x["latency_ms"])


def check_target(config):
    host, number = target(config["reality"]["target"])
    result = tls_probe(host, number, config["reality"]["sni"])
    if result["alpn"] != "h2":
        raise Error("Reality target не согласовал HTTP/2.", "sudo ruavc reality auto")
    return result


class LocalHTTPS(http.client.HTTPSConnection):
    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def local_https(config, path, limit=4 * 1024 * 1024):
    w = config["web"]
    conn = LocalHTTPS(w["domain"], w["port"], timeout=8, context=ssl.create_default_context())
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read(limit + 1)
        if len(body) > limit:
            raise Error("Ответ подписки слишком большой.")
        return response.status, dict((k.lower(), v) for k, v in response.getheaders()), body
    except (OSError, http.client.HTTPException):
        raise Error("Не удалось проверить HTTPS подписок: TCP, TLS, сертификат или HTTP.") from None
    finally:
        conn.close()
