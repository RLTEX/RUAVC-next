"""Pure renderers: all output is derived from validated source documents."""

import base64
from urllib.parse import quote, urlencode, urlsplit

from .model import normalize_rule

LOCAL_IPS = ["geoip:private", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8"]
# No geosite: references: INCY for Windows resolves them in its bundled geo files.
RU_SITES = ["domain:ru", "domain:su", "domain:xn--p1ai", "domain:xn--p1acf"]
COUNTRIES = {"DE": "Германия", "NL": "Нидерланды", "FI": "Финляндия", "FR": "Франция", "US": "США", "GB": "Великобритания", "RU": "Россия", "TR": "Турция", "KZ": "Казахстан", "SE": "Швеция", "PL": "Польша", "CH": "Швейцария", "AT": "Австрия", "CA": "Канада", "AM": "Армения", "GE": "Грузия", "JP": "Япония", "SG": "Сингапур"}


def flag(country):
    return "".join(chr(127397 + ord(c)) for c in country)


def origin(c):
    w = c["web"]
    return "https://" + w["domain"] + (":" + str(w["port"]) if w["port"] != 443 else "")


def link(c, device):
    return origin(c) + "/sub/" + device["token"]


def autorouting(c, device):
    return "incy://autorouting/onadd/" + origin(c) + "/routing/" + device["token"] + ".json"


def vless(bundle, device):
    c, s = bundle["config"], bundle["secrets"]
    r = c["reality"]
    query = {"encryption": "none", "security": "reality", "sni": r["sni"], "fp": r["fingerprint"], "pbk": s["public_key"], "sid": s["short_id"], "type": "tcp", "headerType": "none"}
    if r["flow"]:
        query["flow"] = r["flow"]
    host = c["server"]["address"]
    if ":" in host:
        host = "[" + host + "]"
    title = (flag(c["server"]["country"]) + " " + device["name"]).strip()
    return f'vless://{device["uuid"]}@{host}:{r["port"]}?' + urlencode(query, quote_via=quote) + "#" + quote(title, safe="")


def subscription(bundle, device):
    c = bundle["config"]
    country = c["server"]["country"]
    label = (flag(country) + " " + COUNTRIES.get(country, country)).strip() or "VPN"
    title = base64.b64encode(label.encode()).decode()
    return f"#profile-title: base64:{title}\n#profile-update-interval: 24\n{vless(bundle, device)}\n{autorouting(c, device)}\n"


def routing(bundle, ru_sites=()):
    """ru_sites: the expanded ru-inside category (datasets.direct_sites)."""
    c = bundle["config"]
    r = c["routing"]
    base = origin(c) + "/rules/" + bundle["release"]["dataset"]
    result = {"Name": "Маршрутизация сервера", "GlobalProxy": "true", "LastUpdated": str(bundle["release"]["routing_revision"]),
              "RemoteDNSType": "DoH" if r["remote_dns"] else "DoU", "RemoteDNSDomain": r["remote_dns"], "RemoteDNSIP": r["remote_dns_ip"],
              "DomesticDNSType": "DoH" if r["domestic_dns"] else "DoU", "DomesticDNSDomain": r["domestic_dns"], "DomesticDNSIP": r["domestic_dns_ip"],
              "DnsHosts": {urlsplit(r[k + "_dns"]).hostname: r[k + "_dns_ip"] for k in ("remote", "domestic") if r[k + "_dns"]},
              "Geoipurl": base + "/geoip.dat", "Geositeurl": base + "/geosite.dat",
              "DirectSites": RU_SITES + list(ru_sites) if r["direct"] else [], "DirectIp": LOCAL_IPS + (["geoip:ru"] if r["direct"] else []),
              "ProxySites": [], "ProxyIp": [], "BlockSites": [], "BlockIp": [],
              "RouteOrder": "block-proxy-direct", "DomainStrategy": "IPIfNonMatch", "FakeDNS": "false"}
    for section, entries in bundle["sites"].items():
        for entry in entries:
            kind, value = normalize_rule(entry)
            key = ("Direct" if section == "direct" else "Proxy") + ("Ip" if kind == "ip" else "Sites")
            if value == "geosite:ru-inside":
                result[key].extend(RU_SITES + list(ru_sites))
            else:
                result[key].append(value)
    for key in ("DirectSites", "DirectIp", "ProxySites", "ProxyIp"):
        result[key] = sorted(set(result[key]))
    return result


def xray(bundle):
    c, s = bundle["config"], bundle["secrets"]
    r = c["reality"]
    clients = [{"id": d["uuid"], **({"flow": r["flow"]} if r["flow"] else {})} for d in bundle["devices"]]
    return {"log": {"loglevel": "none"}, "inbounds": [{"tag": "vless-reality", "listen": "0.0.0.0", "port": r["port"], "protocol": "vless",
            "settings": {"clients": clients, "decryption": "none"},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {"show": False, "target": r["target"], "xver": 0, "serverNames": [r["sni"]], "privateKey": s["private_key"], "shortIds": [s["short_id"]]}},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": True}}],
            "outbounds": [{"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "block"}],
            "routing": {"rules": [{"type": "field", "ip": ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10"], "outboundTag": "block"}]}}


def probe_client(bundle, device, socks_port):
    c, s = bundle["config"], bundle["secrets"]
    r = c["reality"]
    user = {"id": device["uuid"], "encryption": "none"}
    if r["flow"]:
        user["flow"] = r["flow"]
    # Info level is where Xray reports REALITY/VLESS failures; it contains no credentials.
    return {"log": {"loglevel": "info", "access": "none", "dnsLog": False}, "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": r["port"], "users": [user]}]},
            "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {"serverName": r["sni"], "fingerprint": r["fingerprint"], "password": s["public_key"], "shortId": s["short_id"]}}}]}


def routing_test(bundle, ru_sites=()):
    p = routing(bundle, ru_sites)
    rules = []
    for prefix, out in (("Proxy", "proxy"), ("Direct", "direct")):
        for suffix, field in (("Sites", "domain"), ("Ip", "ip")):
            if p[prefix + suffix]:
                rules.append({"type": "field", field: p[prefix + suffix], "outboundTag": out})
    return {"log": {"loglevel": "none"}, "outbounds": [{"protocol": "freedom", "tag": "proxy"}, {"protocol": "freedom", "tag": "direct"}], "routing": {"domainStrategy": p["DomainStrategy"], "rules": rules}}


def nginx(bundle, generation, datasets):
    c = bundle["config"]
    w = c["web"]
    web = generation / "web"
    # Paths are manager-owned, fixed Linux locations, never user text.
    return f'''user www-data;
worker_processes 1;
pid /run/ruavc-web/nginx.pid;
error_log /dev/null crit;
events {{ worker_connections 256; }}
http {{
    access_log off;
    server_tokens off;
    client_max_body_size 1k;
    client_body_timeout 10s;
    client_header_timeout 10s;
    keepalive_timeout 15s;
    # The unit's file system is read-only except /run/ruavc-web.
    client_body_temp_path /run/ruavc-web/body;
    proxy_temp_path /run/ruavc-web/proxy;
    fastcgi_temp_path /run/ruavc-web/fastcgi;
    uwsgi_temp_path /run/ruavc-web/uwsgi;
    scgi_temp_path /run/ruavc-web/scgi;
    sendfile on;
    server {{
        listen {w["port"]} ssl;
        server_name {w["domain"]};
        ssl_certificate /etc/letsencrypt/live/{w["domain"]}/fullchain.pem;
        ssl_certificate_key /etc/letsencrypt/live/{w["domain"]}/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_session_tickets off;
        autoindex off;
        log_not_found off;
        if ($host != {w["domain"]}) {{ return 404; }}
        if ($request_method !~ ^(GET|HEAD)$) {{ return 405; }}
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy no-referrer always;
        location ~ "^/sub/(?<ruavc_token>[a-f0-9]{{64}})$" {{
            root {web};
            try_files $uri =404;
            default_type text/plain;
            charset utf-8;
            add_header Cache-Control "no-store" always;
            add_header Referrer-Policy no-referrer always;
            add_header X-Content-Type-Options nosniff always;
            add_header profile-update-interval "24";
            add_header autorouting "incy://autorouting/onadd/{origin(c)}/routing/$ruavc_token.json";
        }}
        location ~ "^/routing/[a-f0-9]{{64}}\\.json$" {{
            root {web};
            try_files $uri =404;
            default_type application/json;
            add_header Cache-Control "no-store" always;
            add_header Referrer-Policy no-referrer always;
        }}
        location ~ "^/rules/(?<ruavc_dataset>[a-f0-9]{{64}})/(?<ruavc_file>geo(?:ip|site)\\.dat(?:\\.sha256)?)$" {{
            alias {datasets}/$ruavc_dataset/$ruavc_file;
            default_type application/octet-stream;
            add_header Cache-Control "public, max-age=31536000, immutable";
        }}
        location / {{ return 404; }}
    }}
}}
'''
