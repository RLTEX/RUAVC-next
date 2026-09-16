"""Validated source documents. No executable configuration."""

import base64
import copy
import ipaddress
import re
import secrets
import time
import uuid
from urllib.parse import urlsplit

from .errors import Error

SCHEMA = 1
FINGERPRINTS = {"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"}
REPOSITORY = "RLTEX/RUAVC-next"
XRAY_VERSION = "26.3.27"
XRAY_SHA = {
    "amd64": "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
    "arm64": "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
}


def require(ok, message):
    if not ok:
        raise Error(message, "sudo ruavc help", 2)


def domain(value, allow_single=False):
    require(isinstance(value, str) and 0 < len(value) <= 253, "Некорректная длина домена.")
    try:
        result = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise Error("Некорректный домен.", code=2) from None
    parts = result.split(".")
    require((allow_single or len(parts) >= 2) and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in parts), "Некорректный домен.")
    require(not all(x.isdigit() for x in parts), "Вместо домена указан некорректный IP.")
    return result


def address(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return domain(value)


def port(value):
    require(type(value) is int and 1 <= value <= 65535, "Порт должен быть числом 1–65535.")
    return value


def target(value):
    require(isinstance(value, str), "Reality target должен быть адресом host:port.")
    parsed = urlsplit("//" + value)
    try:
        host, number = parsed.hostname, parsed.port
    except ValueError:
        raise Error("Reality target должен быть адресом host:port.", code=2) from None
    require(host and number and not parsed.username and not parsed.password and not parsed.path and not parsed.query and not parsed.fragment, "Reality target должен быть адресом host:port.")
    return address(host), port(number)


def https_url(value):
    p = urlsplit(value)
    require(p.scheme == "https" and p.hostname and not p.username and not p.password and not p.fragment, "Требуется HTTPS URL без credentials.")
    require(not any(ord(c) < 33 or c in '\\"' for c in value), "Недопустимый символ в URL.")
    return value


def device_name(value):
    require(isinstance(value, str) and re.fullmatch(r"[\w-]{1,40}", value, flags=re.UNICODE) and not value.startswith("_"), "Имя устройства: 1–40 букв, цифр, дефисов или подчёркиваний.")
    return value


def defaults(public_address, subscription_domain, country=""):
    return {
        "schema": SCHEMA,
        "server": {"address": address(public_address), "country": country},
        "reality": {"port": 443, "sni": "", "target": "", "fingerprint": "firefox", "flow": ""},
        "web": {"domain": domain(subscription_domain), "port": 9443},
        "routing": {"direct": True, "interval_hours": 12,
                    "geoip_repository": "golukon/russia-only-geoip",
                    "geosite_repository": "golukon/russia-only-geosite",
                    "remote_dns": "https://cloudflare-dns.com/dns-query", "remote_dns_ip": "1.1.1.1",
                    "domestic_dns": "https://common.dot.dns.yandex.net/dns-query", "domestic_dns_ip": "77.88.8.8"},
        "probe_url": "https://www.gstatic.com/generate_204",
    }


def migrate(config):
    result = copy.deepcopy(config)
    require(type(result.get("schema")) is int, "Отсутствует версия схемы конфигурации.")
    require(result["schema"] <= SCHEMA, "Конфигурация создана более новой версией RUAVC; требуется обновление программы.")
    # No older public schema exists in 0.1.0. Unknown formats must not be guessed.
    require(result["schema"] == SCHEMA, "Неизвестная старая схема; автоматическая миграция не определена.")
    return result


def normalize_rule(value):
    require(isinstance(value, str) and len(value) <= 512 and not any(ord(c) < 32 for c in value), "Некорректное правило sites.")
    value = value.strip()
    if "://" in value:
        p = urlsplit(value)
        require(p.scheme in {"https", "http"} and p.hostname and not p.username, "В sites требуется домен, IP или HTTP(S) URL.")
        value = p.hostname
    if value.startswith("*."):
        value = value[2:]
    for prefix in ("geosite:", "geoip:"):
        if value.startswith(prefix):
            require(re.fullmatch(r"[a-zA-Z0-9_!-]+", value[len(prefix):]), "Некорректная geo-категория.")
            return ("ip" if prefix == "geoip:" else "site"), value.lower()
    for prefix in ("domain:", "full:"):
        if value.startswith(prefix):
            return "site", prefix + domain(value[len(prefix):], allow_single=True)
    if value.startswith(("regexp:", "keyword:")):
        require(len(value.split(":", 1)[1]) > 0, "Пустое правило sites.")
        return "site", value  # Final regex validation is performed by Xray, using RE2.
    try:
        network = ipaddress.ip_network(value, strict=False)
        return "ip", str(network) if "/" in value else str(network.network_address)
    except ValueError:
        require(not re.fullmatch(r"[\d./:]+", value), "Некорректный IP или CIDR в sites.")
    return "site", "domain:" + domain(value)


def parse_sites(text):
    result = {"direct": [], "proxy": []}
    section = None
    for number, line in enumerate(text.splitlines(), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = {"[напрямую]": "direct", "[direct]": "direct", "[через vpn]": "proxy", "[vpn]": "proxy", "[proxy]": "proxy"}.get(line.lower())
            require(section is not None, f"sites, строка {number}: неизвестный раздел.")
            continue
        require(section is not None, f"sites, строка {number}: запись вне раздела.")
        _, normalized = normalize_rule(line)
        if normalized not in result[section]:
            result[section].append(normalized)
    return result


def sites_text(sites):
    return "[напрямую]\n" + "\n".join(sites["direct"]) + "\n\n[через vpn]\n" + "\n".join(sites["proxy"]) + "\n"


def new_device(name):
    return {"name": device_name(name), "uuid": str(uuid.uuid4()), "token": secrets.token_hex(32), "created_at": int(time.time())}


def validate(bundle):
    c = bundle["config"]
    require(set(c) == {"schema", "server", "reality", "web", "routing", "probe_url"}, "Неизвестные или отсутствующие разделы конфигурации.")
    migrate(c)
    expected = defaults("192.0.2.1", "vpn.example.com")
    for section in ("server", "reality", "web", "routing"):
        require(isinstance(c[section], dict) and set(c[section]) == set(expected[section]), f"Некорректные поля раздела {section}.")
    address(c["server"]["address"])
    require(re.fullmatch(r"(?:[A-Z]{2})?", c["server"]["country"]) is not None, "Код страны: две заглавные буквы.")
    r = c["reality"]
    port(r["port"])
    domain(r["sni"])
    target(r["target"])
    require(r["fingerprint"] in FINGERPRINTS, "Неподдерживаемый fingerprint Reality.")
    require(r["flow"] in {"", "xtls-rprx-vision"}, "Неподдерживаемый flow.")
    w = c["web"]
    domain(w["domain"])
    port(w["port"])
    require(w["port"] != r["port"] and 80 not in (w["port"], r["port"]), "Порты Reality, HTTPS и ACME (80) должны различаться.")
    routing = c["routing"]
    require(type(routing["direct"]) is bool, "routing.direct должен быть true или false.")
    require(type(routing["interval_hours"]) is int and 1 <= routing["interval_hours"] <= 168, "Интервал правил: 1–168 часов.")
    for key in ("geoip_repository", "geosite_repository"):
        require(re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", routing[key]) is not None, "Некорректный GitHub repository.")
    for prefix in ("remote", "domestic"):
        https_url(routing[prefix + "_dns"])
        ipaddress.ip_address(routing[prefix + "_dns_ip"])
    https_url(c["probe_url"])
    s = bundle["secrets"]
    require(set(s) == {"private_key", "public_key", "short_id"}, "Некорректный документ секретов.")
    for key in ("private_key", "public_key"):
        require(re.fullmatch(r"[A-Za-z0-9_-]{43}", s[key]) is not None and len(base64.urlsafe_b64decode(s[key] + "=")) == 32, "Некорректный ключ Reality.")
    require(re.fullmatch(r"(?:[0-9a-f]{2}){1,8}", s["short_id"]) is not None, "shortId: 2–16 hex-символов, чётная длина.")
    seen = {"name": set(), "uuid": set(), "token": set()}
    require(isinstance(bundle["devices"], list) and len(bundle["devices"]) <= 1000, "Слишком много устройств.")
    for d in bundle["devices"]:
        require(set(d) == {"name", "uuid", "token", "created_at"}, "Некорректная запись устройства.")
        device_name(d["name"])
        require(str(uuid.UUID(d["uuid"])) == d["uuid"], "Некорректный UUID устройства.")
        require(re.fullmatch(r"[0-9a-f]{64}", d["token"]) is not None, "Некорректный токен устройства.")
        require(type(d["created_at"]) is int, "Некорректная дата устройства.")
        for key in seen:
            require(d[key] not in seen[key], f"Повторяющееся поле устройства: {key}.")
            seen[key].add(d[key])
    require(set(bundle["sites"]) == {"direct", "proxy"}, "Некорректные разделы sites.")
    for entries in bundle["sites"].values():
        require(isinstance(entries, list) and len(entries) <= 10000, "Слишком много правил sites.")
        for entry in entries:
            normalize_rule(entry)
    release = bundle["release"]
    for key in ("code_sha256", "xray_sha256", "dataset"):
        require(re.fullmatch(r"[0-9a-f]{64}", release[key]) is not None, "Некорректный digest release state.")
    for key in ("version", "xray_version"):
        require(re.fullmatch(r"\d+\.\d+\.\d+", release[key]) is not None, "Некорректная версия компонента.")
    require(type(release["routing_revision"]) is int and release["routing_revision"] > 0, "Некорректная ревизия маршрутизации.")
    return bundle
