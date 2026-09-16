"""Bounded HTTPS downloads and Reality target qualification."""

import concurrent.futures
import http.client
import ipaddress
import json
import socket
import ssl
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
                    return {"host": host, "sni": sni, "port": number, "ip": ip,
                            "tls": sock.version(), "alpn": alpn, "latency_ms": round((time.monotonic() - start) * 1000), "certificate_valid": True}
        except OSError as exc:
            last = type(exc).__name__
    raise Error(f"Reality target: не прошли TCP/TLS 1.3 и проверка сертификата ({last}).", "sudo ruavc reality check")


# A replaceable candidate provider, not a target baked into the Xray renderer.
# Diversity covers independent operators and regions. Availability is measured on
# the VPS; no candidate is silently accepted merely because it is in this list.
CANDIDATES = (
    "www.microsoft.com", "www.apple.com", "www.samsung.com", "www.sony.com",
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
