"""Layered diagnostics; a local probe never implies reachability from Russia."""

import json
import time
from pathlib import Path

from . import __version__, datasets, model, network, render, system
from .errors import Error
from .storage import read_json


def status(store, services):
    b = store.load()
    c, r = b["config"], b["release"]
    return {"version": __version__, "installed_version": r["version"], "xray_version": r["xray_version"],
            "address": c["server"]["address"], "reality_port": c["reality"]["port"], "subscription_origin": render.origin(c),
            "direct": c["routing"]["direct"], "devices": [d["name"] for d in b["devices"]],
            "services": {name: services.active(name) for name in services.names},
            "routing_timer": services.active("ruavc-rules.timer"), "pending_recovery": store.pending.exists(),
            "external_ru": "Внешняя доступность из РФ не проверена"}


def diagnose(store, services, tx):
    results = []

    def check(layer, name, function, hint):
        try:
            detail = function()
            results.append({"layer": layer, "check": name, "state": "ok", "detail": str(detail) if detail is not None else "Проверено"})
            return True
        except (Error, OSError, ValueError, KeyError, TypeError) as exc:
            results.append({"layer": layer, "check": name, "state": "fail", "detail": system.redact(str(exc)), "next": hint})
            return False

    def assert_ok(condition, message):
        if not condition:
            raise Error(message)

    if not check("SYSTEM", "Конфигурация, права и целостность", lambda: model.validate(tx.verify_generation(store.active_name())) and "JSON, manifest и permissions проверены", "sudo ruavc backup list"):
        return results + [{"layer": "NETWORK", "check": "Доступность из РФ", "state": "not_checked", "detail": "Внешняя доступность из РФ не проверена"}]
    bundle = store.load()
    config = bundle["config"]
    generation = store.generation(store.active_name())
    check("SYSTEM", "Незавершённая операция", lambda: assert_ok(not store.pending.exists(), "Есть durable journal незавершённой операции."), "sudo ruavc recover")
    check("XRAY", "Компоненты, Xray config и конфиг INCY", lambda: services.validate(generation, bundle), "sudo ruavc rollback")
    check("XRAY", "Запущенная версия конфигурации", lambda: services.running_generation(generation), "sudo ruavc repair")
    check("XRAY", "Локальный TCP порт", lambda: assert_ok(system.listening(config["reality"]["port"]), "Порт Reality не слушается."), "sudo ruavc logs")
    check("REALITY", "DNS, TCP, TLS 1.3, сертификат SNI, HTTP/2", lambda: network.check_target(config), "sudo ruavc reality auto")
    check("REALITY", "Маскировка на локальном входе", lambda: network.tls_probe("127.0.0.1", config["reality"]["port"], config["reality"]["sni"], public=False), "sudo ruavc reality check")
    if bundle["devices"]:
        check("REALITY", "VLESS self-test самого VPS", lambda: services.probe_vless(bundle, bundle["devices"][0]), "sudo ruavc logs")
    else:
        results.append({"layer": "REALITY", "check": "VLESS self-test", "state": "not_checked", "detail": "Нет устройств: sudo ruavc add phone"})
    check("WEB", "HTTPS, сертификат, подписки и совпадение конфигурации", lambda: services.health(generation, bundle), "sudo ruavc repair")
    check("ROUTING", "SHA-256 и структура geo-файлов", lambda: datasets.verify(store, bundle["release"]["dataset"]) and "Проверены SHA-256, protobuf и обязательные категории", "sudo ruavc update routing")
    check("ROUTING", "Таймер обновлений", lambda: assert_ok(services.active("ruavc-rules.timer"), "Таймер обновления правил неактивен."), "sudo systemctl enable --now ruavc-rules.timer")
    def routing_age():
        state = store.state / "routing-update.json"
        if not state.exists():
            return "Первое плановое обновление ещё не запускалось"
        record = read_json(state)
        assert_ok(time.time() - record["success_at"] < config["routing"]["interval_hours"] * 7200, "Последнее успешное обновление правил слишком старое.")
    check("ROUTING", "Последнее обновление", routing_age, "sudo ruavc update routing")
    check("NETWORK", "Публичный IPv4", lambda: assert_ok(network.detect_address() == config["server"]["address"], "Публичный IPv4 отличается от настройки server.address."), "sudo ruavc config")
    if Path("/usr/sbin/ufw").exists():
        results.append({"layer": "NETWORK", "check": "UFW", "state": "info", "detail": system.run(["/usr/sbin/ufw", "status"], check=False).stdout.decode("utf-8", "replace").strip()})
    results.append({"layer": "NETWORK", "check": "Firewall хостинга и входящий внешний TCP", "state": "not_checked", "detail": "Для проверки требуется внешняя точка наблюдения."})
    results.append({"layer": "NETWORK", "check": "Доступность из РФ", "state": "not_checked", "detail": "Внешняя доступность из РФ не проверена"})
    return results
