"""Small, consistent CLI. Credentials require an explicit reveal command."""

import argparse
import copy
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time

from . import __version__, backup, datasets, doctor, install, model, network, releases, render, system
from .errors import Error
from .storage import Store, encoded, read, read_json, safe_path, write
from .transaction import Transaction

HELP = """RUAVC — управление личным VPN-сервером
  status [--json]                  быстрое состояние без секретов
  add ИМЯ                         создание отдельного устройства
  qr ИМЯ | link ИМЯ               ссылка подписки и QR / только ссылка
  reissue ИМЯ | revoke ИМЯ        смена UUID и ссылки / отзыв доступа
  direct on|off                   российские ресурсы напрямую / через VPN
  sites [add|remove direct|proxy ЗАПИСЬ]  просмотр и правка своих правил
  config [set КЛЮЧ ЗНАЧЕНИЕ ...]   просмотр и транзакционная настройка
  reality check|auto|rotate-keys|rotate-short-id|import-keys
  doctor [--json] | logs          глубокая диагностика / журнал
  check-update | update [ruavc|xray|routing]
  backup create|list|restore ФАЙЛ  резервные копии
  rollback | recover | repair     откат / восстановление / пересборка
  country [КОД|auto] | version
  uninstall --yes                 удаление с сохранением backup
Подробности: ruavc КОМАНДА --help
"""


def parser():
    p = argparse.ArgumentParser(prog="ruavc", description="Управление VPN-сервером")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("help")
    sub.add_parser("version")
    setup = sub.add_parser("setup", help="Установка на чистый Ubuntu VPS")
    for flag in ("address", "domain", "target", "sni", "country"):
        setup.add_argument("--" + flag)
    setup.add_argument("--port", type=int)
    setup.add_argument("--web-port", type=int)
    setup.add_argument("--no-direct", action="store_true")
    for name in ("status", "doctor"):
        sub.add_parser(name).add_argument("--json", action="store_true")
    for name in ("add", "qr", "link", "reissue", "revoke"):
        sub.add_parser(name).add_argument("name")
    sub.add_parser("direct").add_argument("state", choices=("on", "off"), nargs="?")
    country = sub.add_parser("country")
    country.add_argument("value", nargs="?")
    config = sub.add_parser("config", description="Несколько пар КЛЮЧ ЗНАЧЕНИЕ применяются одной транзакцией. Список ключей: ruavc config")
    config.add_argument("action", nargs="?", choices=("set",), default=None)
    config.add_argument("pairs", nargs="*")
    reality = sub.add_parser("reality", description="import-keys читает JSON private_key/public_key/short_id из stdin; секреты не передаются аргументами.")
    reality.add_argument("action", choices=("check", "auto", "rotate-keys", "rotate-short-id", "import-keys"))
    sites = sub.add_parser("sites", description="Правила действуют при direct on и off. proxy имеет приоритет. import читает разделы [напрямую]/[через vpn] из stdin.")
    sites.add_argument("action", nargs="?", choices=("add", "remove", "import", "edit"))
    sites.add_argument("section", nargs="?", choices=("direct", "proxy"))
    sites.add_argument("rule", nargs="?")
    sub.add_parser("logs").add_argument("--lines", type=int, default=60)
    sub.add_parser("check-update")
    update = sub.add_parser("update")
    update.add_argument("component", nargs="?", choices=("ruavc", "xray", "routing"), default="ruavc")
    update.add_argument("--scheduled", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("rollback")
    sub.add_parser("repair")
    sub.add_parser("recover").add_argument("--boot", action="store_true")
    b = sub.add_parser("backup")
    b.add_argument("action", choices=("create", "list", "restore"))
    b.add_argument("name", nargs="?")
    sub.add_parser("uninstall").add_argument("--yes", action="store_true")
    upgrade = sub.add_parser("_upgrade", help=argparse.SUPPRESS)
    upgrade.add_argument("checksum")
    return p


def find_device(bundle, name):
    model.device_name(name)
    for device in bundle["devices"]:
        if device["name"] == name:
            return device
    raise Error("Устройство не найдено.", "sudo ruavc status", 2)


def reveal(bundle, device, qr=False):
    value = render.link(bundle["config"], device)
    print(value, flush=True)
    if qr:
        result = system.run(["/usr/bin/qrencode", "-t", "ANSIUTF8", "-m", "2", "-o", "-"], input_data=value.encode())
        sys.stdout.write(result.stdout.decode("utf-8"))


def set_config(bundle, pairs):
    model.require(len(pairs) > 0 and len(pairs) % 2 == 0, "config set принимает пары КЛЮЧ ЗНАЧЕНИЕ.")
    c = bundle["config"]
    for key, text in zip(pairs[::2], pairs[1::2]):
        if key == "probe_url":
            c[key] = model.https_url(text)
            continue
        parts = key.split(".")
        model.require(len(parts) == 2 and parts[0] in c and isinstance(c[parts[0]], dict) and parts[1] in c[parts[0]], "Неизвестный ключ config; список: sudo ruavc config")
        group, field = parts
        value = c[group][field]
        if type(value) is bool:
            model.require(text.lower() in {"true", "false", "on", "off"}, "Логическое значение: true/false или on/off.")
            value = text.lower() in {"true", "on"}
        elif type(value) is int:
            try:
                value = int(text)
            except ValueError:
                raise Error("Значение должно быть целым числом.", code=2) from None
        else:
            value = text
        if key in {"web.domain", "reality.sni"}:
            value = model.domain(value)
        if key == "server.country":
            value = value.upper()
        if key == "server.address":
            value = model.address(value)
        c[group][field] = value
    model.validate(bundle)


def print_status(result, as_json):
    if as_json:
        print(encoded(result).decode(), end="")
        return
    print(f'RUAVC {result["installed_version"]} · Xray {result["xray_version"]}')
    print(f'VPN: {result["address"]}:{result["reality_port"]}')
    print("Российские ресурсы: " + ("напрямую" if result["direct"] else "через VPN"))
    for name, active in result["services"].items():
        print(name + ": " + ("работает" if active else "не работает"))
    print("Устройства: " + (", ".join(result["devices"]) or "нет"))
    print("Автообновление правил: " + ("включено" if result["routing_timer"] else "выключено"))
    if result["pending_recovery"]:
        print("Незавершённая операция: sudo ruavc recover")
    print(result["external_ru"])


def service_entry(name):
    # Services resolve the pointer ONCE and launch an immutable configuration.
    base = Path("/etc/ruavc")
    target = os.readlink(base / "current")
    import re
    if not re.fullmatch(r"generations/g-[0-9a-f]{24}", target):
        raise Error("Неверный current в service launcher.")
    generation = base / target
    if name == "_xray":
        launch = json.loads((generation / "generated/launch.json").read_text())
        binary = launch["xray"]
        if not re.fullmatch(r"/opt/ruavc/xray/[0-9a-f]{64}/xray", binary):
            raise Error("Неверный путь Xray.")
        os.execv(binary, [binary, "run", "-config", str(generation / "generated/xray.json")])
    else:
        os.execv("/usr/sbin/nginx", ["nginx", "-c", str(generation / "generated/nginx.conf"), "-g", "daemon off;"])


def dispatch(args, store, services, tx):
    cmd = args.command
    if cmd == "recover":
        recovered = tx.recover(boot=args.boot)
        print("Предыдущее состояние восстановлено." if recovered else "Незавершённых операций нет.")
        return 0
    if cmd == "setup":
        install.setup(store, args)
        return 0
    bundle = store.load()
    if cmd == "status":
        result = doctor.status(store, services)
        print_status(result, args.json)
        return 0 if all(result["services"].values()) and not result["pending_recovery"] else 1
    if cmd == "doctor":
        result = doctor.diagnose(store, services, tx)
        if args.json:
            print(encoded(result).decode(), end="")
        else:
            for check in result:
                print(f'[{check["layer"]}] {check["state"]}: {check["check"]} — {check["detail"]}')
                if check.get("next"):
                    print("  Следующая команда: " + check["next"])
        return int(any(c["state"] == "fail" for c in result))
    if cmd in {"qr", "link"}:
        reveal(bundle, find_device(bundle, args.name), qr=cmd == "qr")
        return 0
    if cmd == "config" and args.action is None:
        print(encoded(bundle["config"]).decode(), end="")
        return 0
    if cmd == "direct" and args.state is None:
        print("on" if bundle["config"]["routing"]["direct"] else "off")
        return 0
    if cmd == "country" and args.value is None:
        print(bundle["config"]["server"]["country"] or "Не определена")
        return 0
    if cmd == "sites" and args.action is None:
        print(model.sites_text(bundle["sites"]), end="")
        return 0
    if cmd == "logs":
        model.require(1 <= args.lines <= 1000, "Количество строк: 1–1000.")
        path = Path("/var/log/ruavc/manager.log")
        if path.exists():
            print(system.redact("\n".join(read(path, private=True).decode("utf-8", "replace").splitlines()[-args.lines:])))
        else:
            print("Журнал операций пуст.")
        return 0
    if cmd == "check-update":
        for title, repo, current in (("RUAVC", model.REPOSITORY, bundle["release"]["version"]), ("Xray", "XTLS/Xray-core", bundle["release"]["xray_version"])):
            release = releases.latest(repo)
            print(f'{title}: установлена {current}, последняя {release["tag_name"]}')
        return 0
    if cmd == "backup" and args.action == "list":
        for path in sorted(store.backups.glob("backup-*.tar.gz")):
            print(path.name)
        return 0
    # Read-only commands above never repair or silently mutate state.
    if store.pending.exists():
        raise Error("Требуется восстановить прерванную операцию.", "sudo ruavc recover")
    if cmd != "repair":
        tx.verify_generation(store.active_name())
    if cmd == "backup":
        if args.action == "create":
            print(str(store.backups / backup.create(store)))
        else:
            model.require(args.name is not None, "Требуется имя backup.")
            backup.restore(store, args.name, tx)
            print("Резервная копия применена. Credentials соответствуют этой копии.")
        return 0
    if cmd == "rollback":
        tx.rollback()
        print("Предыдущая рабочая версия восстановлена. INCY получит новую ревизию профиля.")
        return 0
    if cmd == "uninstall":
        model.require(args.yes, "Удаление требует --yes; backup будет сохранён.")
        for name, content in install.UNITS.items():
            path = Path("/etc/systemd/system") / name
            if read(path).decode() != content:
                raise Error("Системная служба изменена вне RUAVC; автоматическое удаление остановлено.")
        saved = backup.create(store)
        system.run(["/usr/bin/systemctl", "disable", "--now", *install.UNITS], timeout=60)
        for name in install.UNITS:
            safe_path(Path("/etc/systemd/system") / name).unlink()
        safe_path(Path("/usr/local/sbin/ruavc")).unlink()
        for path in (store.etc, store.state, store.opt):
            safe_path(path)
            shutil.rmtree(path)
        system.run(["/usr/bin/systemctl", "daemon-reload"])
        print("RUAVC удалён. Backup: " + str(store.backups / saved))
        print("Сертификаты, системные пакеты и пользователь службы сохранены.")
        return 0
    if cmd == "add":
        model.device_name(args.name)
        model.require(not any(d["name"] == args.name for d in bundle["devices"]), "Устройство уже существует.")
        bundle["devices"].append(model.new_device(args.name))
    elif cmd == "reissue":
        device = find_device(bundle, args.name)
        device.update(model.new_device(args.name))
    elif cmd == "revoke":
        device = find_device(bundle, args.name)
        bundle["devices"].remove(device)
    elif cmd == "direct":
        bundle["config"]["routing"]["direct"] = args.state == "on"
    elif cmd == "country":
        bundle["config"]["server"]["country"] = network.detect_country() if args.value == "auto" else args.value.upper()
    elif cmd == "config":
        before = copy.deepcopy(bundle["config"])
        set_config(bundle, args.pairs)
        c = bundle["config"]
        if c["reality"] != before["reality"]:
            network.check_target(c)
        for section in ("reality", "web"):
            if c[section]["port"] != before[section]["port"] and not system.free_port(c[section]["port"]):
                raise Error("Новый порт уже занят.")
        if c["web"]["domain"] != before["web"]["domain"]:
            install.certificate(c)
        if any(c["routing"][k] != before["routing"][k] for k in ("geoip_repository", "geosite_repository")):
            bundle["release"]["dataset"] = datasets.download(store, c)
    elif cmd == "sites":
        if args.action == "import":
            bundle["sites"] = model.parse_sites(sys.stdin.read(2 * 1024 * 1024))
        elif args.action == "edit":
            editor = shutil.which("nano", path="/usr/bin:/bin") or shutil.which("vi", path="/usr/bin:/bin")
            if not editor:
                raise Error("Не найден nano или vi.", "sudo ruavc sites add direct ДОМЕН")
            with tempfile.TemporaryDirectory(prefix="sites-", dir=store.etc) as directory:
                path = Path(directory) / "sites.txt"
                write(path, model.sites_text(bundle["sites"]))
                import subprocess
                result = subprocess.run([editor, str(path)], check=False, env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TERM": os.environ.get("TERM", "xterm")})
                if result.returncode:
                    raise Error("Редактор завершился с ошибкой; изменения не применены.")
                bundle["sites"] = model.parse_sites(read(path, private=True).decode())
        else:
            model.require(args.section and args.rule, "Требуются раздел direct|proxy и правило.")
            _, rule = model.normalize_rule(args.rule)
            entries = bundle["sites"][args.section]
            if args.action == "add" and rule not in entries:
                entries.append(rule)
            elif args.action == "remove":
                model.require(rule in entries, "Правило не найдено.")
                entries.remove(rule)
    elif cmd == "reality":
        if args.action == "check":
            print(encoded(network.check_target(bundle["config"])).decode(), end="")
            return 0
        if args.action == "auto":
            selected = network.choose_target()
            bundle["config"]["reality"].update(target=f'{selected["host"]}:443', sni=selected["sni"])
        elif args.action == "rotate-keys":
            new = system.keys()
            bundle["secrets"].update(private_key=new["private_key"], public_key=new["public_key"])
        elif args.action == "rotate-short-id":
            bundle["secrets"]["short_id"] = secrets.token_hex(8)
        elif args.action == "import-keys":
            try:
                bundle["secrets"] = json.loads(sys.stdin.read(4096))
            except ValueError:
                raise Error("В stdin требуется JSON с ключами Reality.", code=2) from None
    elif cmd == "update":
        if args.component == "routing":
            if args.scheduled and (store.state / "routing-update.json").exists():
                record = read_json(store.state / "routing-update.json")
                if time.time() - record["success_at"] < bundle["config"]["routing"]["interval_hours"] * 3600:
                    return 0
            identifier = datasets.download(store, bundle["config"])
            if identifier == bundle["release"]["dataset"]:
                write(store.state / "routing-update.json", encoded({"success_at": int(time.time())}))
                print("Правила актуальны.")
                return 0
            bundle["release"]["dataset"] = identifier
        elif args.component == "xray":
            version, checksum = releases.install_xray(store, update=True)
            if version_tuple(version) < version_tuple(bundle["release"]["xray_version"]):
                raise Error("Автоматическое понижение версии Xray запрещено.")
            bundle["release"].update(xray_version=version, xray_sha256=checksum)
        else:
            release = releases.latest(model.REPOSITORY)
            version = release["tag_name"][1:]
            if version_tuple(version) <= version_tuple(bundle["release"]["version"]):
                print("RUAVC актуален.")
                return 0
            checksum = releases.install_code(store, releases.asset(release, "ruavc.pyz", model.REPOSITORY, 8 * 1024 * 1024))
            path = store.opt / "code" / checksum / "ruavc.pyz"
            # exec closes the CLOEXEC lock descriptor; the new program reacquires it.
            os.execv("/usr/bin/python3", ["python3", "-I", str(path), "_upgrade", checksum])
    elif cmd == "_upgrade":
        from .storage import digest
        if digest(Path(sys.argv[0]).read_bytes()) != args.checksum:
            raise Error("Пакет обновления не совпадает с проверенной загрузкой.")
        bundle["config"] = model.migrate(bundle["config"])
        bundle["release"].update(version=__version__, code_sha256=args.checksum)
    elif cmd != "repair":
        raise Error("Неизвестная команда.", "ruavc help", 2)
    tx.apply(bundle, cmd)
    if cmd == "update" and args.component == "routing":
        write(store.state / "routing-update.json", encoded({"success_at": int(time.time())}))
    if cmd in {"add", "reissue"}:
        print("Устройство сохранено и проверено. Ссылка и QR: sudo ruavc qr " + args.name)
    else:
        print("Изменения применены и проверены.")
    if cmd in {"config", "reality", "direct", "sites", "country", "repair"}:
        print("Изменения на устройствах появятся после обновления подписки в INCY.")
    return 0


def version_tuple(value):
    return tuple(int(x) for x in value.split("."))


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in {"help", "--help", "-h"}:
        print(HELP)
        return 0
    if argv == ["version"]:
        print(__version__)
        return 0
    try:
        if argv[0] in {"_xray", "_web"}:
            service_entry(argv[0])
        args = parser().parse_args(argv)
        if os.name != "posix" or os.geteuid() != 0:
            raise Error("Требуются Linux и права root.", "sudo ruavc " + args.command, 2)
        os.umask(0o077)
        store = Store()
        services = system.Services(store)
        # Starting recovery as a systemd dependency during a fresh installation
        # must not contend with its parent's already-held mutation lock.
        if args.command == "recover" and args.boot and not store.pending.exists():
            return 0
        groups = install.gids() if store.active_name() else None
        tx = Transaction(store, services, groups)
        # Readers also hold the lock to get one consistent generation across files.
        with store.lock():
            return dispatch(args, store, services, tx)
    except Error as exc:
        if os.name == "posix" and os.geteuid() == 0:
            try:
                system.log(str(exc) + ("; cause=" + str(exc.__cause__) if exc.__cause__ else ""))
            except (Error, OSError):
                pass
        print("Ошибка: " + system.redact(str(exc)), file=sys.stderr)
        print("Следующая команда: " + exc.hint, file=sys.stderr)
        print("Подробный журнал: /var/log/ruavc/manager.log", file=sys.stderr)
        return exc.code
    except (OSError, ValueError, KeyError, TypeError) as exc:
        try:
            system.log(type(exc).__name__ + ": " + str(exc))
        except (Error, OSError):
            pass
        print("Операция остановлена: " + type(exc).__name__ + ". Проверка: sudo ruavc doctor", file=sys.stderr)
        print("Подробный журнал: /var/log/ruavc/manager.log", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
