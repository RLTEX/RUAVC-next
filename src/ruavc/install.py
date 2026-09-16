"""Fresh install with explicit ownership and restoration of managed units."""

import json
import os
from pathlib import Path
import socket
import sys

from . import __version__, datasets, model, network, releases, system
from .errors import Error
from .storage import encoded, mkdir, read, read_json, safe_path, write
from .transaction import Transaction

LAUNCHER = '''#!/usr/bin/python3 -I
import json, os, re
from pathlib import Path
base = Path("/etc/ruavc")
name = os.readlink(base / "current") if (base / "current").is_symlink() else ""
if re.fullmatch(r"generations/g-[0-9a-f]{24}", name):
    code = json.loads((base / name / "generated/launch.json").read_text())["code"]
    if not re.fullmatch(r"/opt/ruavc/code/[0-9a-f]{64}/ruavc\\.pyz", code):
        raise SystemExit("Некорректный путь программы")
else:
    code = "/opt/ruavc/bootstrap.pyz"
os.execv("/usr/bin/python3", ["python3", "-I", code, *os.sys.argv[1:]])
'''

UNITS = {
    "ruavc-xray.service": '''[Unit]
Description=RUAVC VLESS Reality
After=network-online.target ruavc-recover.service
Wants=network-online.target
Requires=ruavc-recover.service
ConditionPathExists=/etc/ruavc/current/generated/xray.json
[Service]
User=ruavc-xray
Group=ruavc-xray
ExecStart=/usr/local/sbin/ruavc _xray
Restart=on-failure
RestartSec=3
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
''',
    "ruavc-web.service": '''[Unit]
Description=RUAVC HTTPS subscriptions
After=network-online.target ruavc-recover.service
Requires=ruavc-recover.service
ConditionPathExists=/etc/ruavc/current/generated/nginx.conf
[Service]
Type=simple
ExecStart=/usr/local/sbin/ruavc _web
ExecReload=/bin/kill -HUP $MAINPID
RuntimeDirectory=ruavc-web
RuntimeDirectoryMode=0755
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/run/ruavc-web
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
[Install]
WantedBy=multi-user.target
''',
    "ruavc-recover.service": '''[Unit]
Description=RUAVC recovery before service startup
Before=ruavc-xray.service ruavc-web.service
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ruavc recover --boot
RemainAfterExit=yes
UMask=0077
[Install]
WantedBy=multi-user.target
''',
    "ruavc-rules.service": '''[Unit]
Description=RUAVC routing dataset refresh
After=network-online.target ruavc-recover.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/ruavc update routing --scheduled
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
TimeoutStartSec=10min
''',
    "ruavc-rules.timer": '''[Unit]
Description=RUAVC routing refresh scheduler
[Timer]
OnBootSec=10min
OnUnitActiveSec=1h
RandomizedDelaySec=10min
Persistent=true
[Install]
WantedBy=timers.target
''',
}


def check_os():
    data = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v.strip('"')
    if data.get("ID") != "ubuntu" or data.get("VERSION_ID") not in {"22.04", "24.04", "26.04"}:
        raise Error("Поддерживаются Ubuntu 22.04, 24.04 и 26.04.")
    releases.architecture()
    if not Path("/run/systemd/system").is_dir():
        raise Error("Требуется VPS с работающим systemd.")
    return data


def gids():
    import grp
    return {"xray": grp.getgrnam("ruavc-xray").gr_gid, "web": grp.getgrnam("www-data").gr_gid}


def certificate(config):
    name = model.domain(config["web"]["domain"])
    result = system.run(["/usr/bin/certbot", "certificates", "--cert-name", name], check=False)
    # certonly --keep-until-expiring preserves an existing valid certificate.
    if not system.free_port(80):
        live = Path("/etc/letsencrypt/live") / name / "fullchain.pem"
        if live.is_file() and result.returncode == 0:
            return
        raise Error("TCP 80 занят: невозможно пройти ACME без остановки чужого сервиса.", "sudo ruavc doctor")
    system.run(["/usr/bin/certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos", "--register-unsafely-without-email", "--keep-until-expiring", "--cert-name", name, "-d", name,
                "--deploy-hook", "/usr/bin/systemctl try-reload-or-restart ruavc-web.service"], timeout=240)


def setup(store, args):
    check_os()
    if (store.etc / "settings.env").exists():
        raise Error("Обнаружена прежняя реализация RUAVC. Автоматическая установка поверх неё отключена.", "Для новой версии требуется отдельный чистый VPS")
    services = system.Services(store)
    if store.active_name():
        if any((args.address, args.domain, args.target, args.sni, args.port, args.web_port, args.country)):
            raise Error("RUAVC уже установлен; параметры меняются транзакционно через config.", "sudo ruavc config")
        tx = Transaction(store, services, gids())
        tx.recover()
        current = tx.verify_generation(store.active_name())
        services.validate(store.generation(store.active_name()), current)
        services.health(store.generation(store.active_name()), current)
        print("RUAVC уже установлен. Конфигурация и credentials сохранены.")
        return
    for name in UNITS:
        if Path("/etc/systemd/system", name).exists():
            raise Error("Обнаружены существующие службы RUAVC без управляемого состояния. Изменений нет.")
    if Path("/usr/local/sbin/ruavc").exists():
        raise Error("Команда ruavc уже существует и не принадлежит новой установке.")
    print("1/5: проверка VPS, портов и сети…", flush=True)
    address = args.address or network.detect_address()
    config = model.defaults(address, args.domain or address.replace(".", "-") + ".sslip.io", args.country or network.detect_country())
    config["routing"]["direct"] = not args.no_direct
    if args.port:
        config["reality"]["port"] = args.port
    elif not system.free_port(443):
        config["reality"]["port"] = next((p for p in (2053, 2083, 2087, 2096, 8443) if system.free_port(p)), 443)
    if args.web_port:
        config["web"]["port"] = args.web_port
    model.port(config["reality"]["port"])
    model.port(config["web"]["port"])
    model.require(len({80, config["reality"]["port"], config["web"]["port"]}) == 3, "Порты ACME, VPN и подписок должны различаться.")
    for number in (80, config["reality"]["port"], config["web"]["port"]):
        if not system.free_port(number):
            raise Error(f"TCP {number} занят другим сервисом; установка остановлена до изменения сервера.")
    resolved = {x[4][0] for x in socket.getaddrinfo(config["web"]["domain"], 80, type=socket.SOCK_STREAM)}
    if address not in resolved:
        raise Error("Домен подписок не указывает на публичный адрес сервера.", "Установка с --domain ДОМЕН_С_A_ЗАПИСЬЮ")
    if args.target:
        host, _ = model.target(args.target)
        config["reality"].update(target=args.target, sni=args.sni or model.domain(host))
        network.check_target(config)
    else:
        selected = network.choose_target([args.sni] if args.sni else [])
        config["reality"].update(target=f'{selected["host"]}:443', sni=selected["sni"])
    print(f'Выбран Reality target: {config["reality"]["target"]}. Проверены DNS, TCP, сертификат, TLS 1.3 и HTTP/2.', flush=True)
    print("2/5: зависимости и проверенные компоненты…", flush=True)
    had_nginx = Path("/usr/sbin/nginx").exists()
    system.run(["/usr/bin/apt-get", "update"], timeout=240)
    system.run(["/usr/bin/apt-get", "install", "-y", "python3", "ca-certificates", "nginx", "certbot", "curl", "openssl", "qrencode"], timeout=600, env_extra={"DEBIAN_FRONTEND": "noninteractive"})
    if not had_nginx:
        system.run(["/usr/bin/systemctl", "disable", "--now", "nginx.service"])
    if system.run(["/usr/bin/getent", "group", "ruavc-xray"], check=False).returncode:
        system.run(["/usr/sbin/groupadd", "--system", "ruavc-xray"])
    if system.run(["/usr/bin/id", "-u", "ruavc-xray"], check=False).returncode:
        system.run(["/usr/sbin/useradd", "--system", "--gid", "ruavc-xray", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "ruavc-xray"])
    store.initialize()
    version, binary_sha = releases.install_xray(store)
    code = Path(sys.argv[0]).read_bytes()
    code_sha = releases.install_code(store, code)
    write(store.opt / "bootstrap.pyz", code, 0o644)
    print("3/5: сертификат HTTPS и маршрутизация…", flush=True)
    certificate(config)
    dataset = datasets.download(store, config)
    bundle = {"config": config, "secrets": system.keys(), "devices": [], "sites": {"direct": [], "proxy": []},
              "release": {"version": __version__, "code_sha256": code_sha, "xray_version": version, "xray_sha256": binary_sha, "dataset": dataset, "routing_revision": 1}}
    model.validate(bundle)
    print("4/5: применение и проверка служб…", flush=True)
    installed = []
    try:
        for name, content in UNITS.items():
            path = Path("/etc/systemd/system") / name
            write(path, content, 0o644)
            installed.append(path)
        mkdir(Path("/usr/local/sbin"), 0o755)
        launcher = Path("/usr/local/sbin/ruavc")
        write(launcher, LAUNCHER, 0o755)
        installed.append(launcher)
        mkdir(Path("/run/ruavc-web"), 0o755)
        system.run(["/usr/bin/systemctl", "daemon-reload"])
        # Recovery has nothing to do before the first transaction. Mark it active
        # first so restart dependencies cannot race with the install lock/journal.
        system.run(["/usr/bin/systemctl", "start", "ruavc-recover.service"])
        Transaction(store, services, gids()).apply(bundle, "install")
        system.run(["/usr/bin/systemctl", "enable", "ruavc-xray.service", "ruavc-web.service", "ruavc-recover.service", "ruavc-rules.timer"])
        system.run(["/usr/bin/systemctl", "start", "ruavc-rules.timer"])
    except BaseException:
        if not store.active_name():
            system.run(["/usr/bin/systemctl", "disable", "--now", *UNITS], check=False)
            for path in installed:
                safe_path(path).unlink(missing_ok=True)
            system.run(["/usr/bin/systemctl", "daemon-reload"], check=False)
        raise
    print("5/5: установка завершена. Устройства: sudo ruavc add phone")
    print(f'Требуемые входящие TCP: 80 (ACME), {config["reality"]["port"]} (VPN), {config["web"]["port"]} (подписки). Firewall не изменялся.')
    print("VLESS self-test будет выполнен после создания первого устройства.")
    print("Внешняя доступность из РФ не проверена")
