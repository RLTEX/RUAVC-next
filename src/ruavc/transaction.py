"""One generation pointer and a durable write-ahead rollback journal."""

import copy
import os
import secrets
import time

from . import datasets, model, render
from .errors import Error
from .storage import digest, encoded, mkdir, read, read_json, sync_dir, write


class Transaction:
    def __init__(self, store, services, gids=None):
        self.store, self.services = store, services
        self.gids = gids or {"xray": None, "web": None}

    def prepare(self, bundle):
        model.validate(bundle)
        datasets.verify(self.store, bundle["release"]["dataset"])
        ru_sites = datasets.direct_sites(self.store, bundle["release"]["dataset"])
        name = "g-" + secrets.token_hex(12)
        generation = mkdir(self.store.generation(name), 0o711)
        for part in ("config", "secrets", "devices", "sites", "release"):
            write(generation / (part + ".json"), encoded(bundle[part]))
        generated = mkdir(generation / "generated", 0o755)
        write(generated / "xray.json", encoded(render.xray(bundle)), 0o640, self.gids["xray"])
        write(generated / "routing-test.json", encoded(render.routing_test(bundle, ru_sites)))
        launch = {"code": str(self.store.opt / "code" / bundle["release"]["code_sha256"] / "ruavc.pyz"), "xray": str(self.services.xray_path(bundle))}
        write(generated / "launch.json", encoded(launch), 0o644)
        write(generated / "nginx.conf", render.nginx(bundle, generation, self.store.state / "datasets"), 0o644)
        web = mkdir(generation / "web", 0o750, self.gids["web"])
        for sub in ("sub", "routing"):
            mkdir(web / sub, 0o750, self.gids["web"])
        for device in bundle["devices"]:
            write(web / "sub" / device["token"], render.subscription(bundle, device), 0o640, self.gids["web"])
            write(web / "routing" / (device["token"] + ".json"), encoded(render.routing(bundle, ru_sites)), 0o640, self.gids["web"])
        manifest = {}
        for path in sorted(generation.rglob("*")):
            if path.is_file():
                manifest[path.relative_to(generation).as_posix()] = digest(read(path))
        write(generation / "manifest.json", encoded(manifest))
        self.services.validate(generation, bundle)
        sync_dir(generation)
        sync_dir(self.store.generations)
        return name

    def verify_generation(self, name, sources_only=False):
        generation = self.store.generation(name)
        manifest = read_json(generation / "manifest.json")
        for relative, expected in manifest.items():
            if sources_only and relative not in {part + ".json" for part in ("config", "secrets", "devices", "sites", "release")}:
                continue
            from pathlib import PurePosixPath
            path = PurePosixPath(relative)
            if path.is_absolute() or ".." in path.parts or "\\" in relative:
                raise Error("Небезопасный путь в manifest версии состояния.")
            if digest(read(generation / relative)) != expected:
                raise Error("Версия состояния изменена вне RUAVC; требуется backup restore.")
        return self.store.load(name)

    def recover(self, boot=False):
        if not self.store.pending.exists():
            return False
        journal = read_json(self.store.pending)
        previous = journal["previous"]
        if previous:
            self.verify_generation(previous)
        self.store.activate(previous)
        if not boot:
            if previous:
                self.services.restart()
                self.services.health(self.store.generation(previous), self.store.load(previous))
            else:
                self.services.stop()
        if "runtime" in journal:
            if journal["runtime"] is None:
                (self.store.state / "runtime.json").unlink(missing_ok=True)
            else:
                write(self.store.state / "runtime.json", encoded(journal["runtime"]))
        self.store.pending.unlink()
        sync_dir(self.store.state)
        return True

    def apply(self, bundle, reason):
        if self.store.pending.exists():
            raise Error("Найдена незавершённая операция.", "sudo ruavc recover")
        previous = self.store.active_name()
        old = self.verify_generation(previous, sources_only=reason == "repair") if previous else None
        bundle = copy.deepcopy(bundle)
        # INCY ignores a profile with a non-increasing timestamp, including rollback.
        bundle["release"]["routing_revision"] = max(int(time.time()), (old["release"]["routing_revision"] + 1) if old else 1)
        name = self.prepare(bundle)
        if previous:
            write(self.store.backups / (name + ".json"), encoded({"generation": previous, "reason": reason, "created_at": int(time.time())}))
        runtime_path = self.store.state / "runtime.json"
        journal = {"previous": previous, "candidate": name, "reason": reason,
                   "runtime": read_json(runtime_path) if runtime_path.exists() else None}
        write(self.store.pending, encoded(journal))
        try:
            self.store.activate(name)
            self.services.restart()
            new_tokens = {d["token"] for d in bundle["devices"]}
            revoked = [d["token"] for d in old["devices"] if d["token"] not in new_tokens] if old else []
            self.services.health(self.store.generation(name), bundle, revoked_tokens=revoked)
            write(self.store.state / "runtime.json", encoded({"generation": name, "previous": previous, "checked_at": int(time.time()), "vless_test": "passed" if bundle["devices"] else "not_run_no_devices"}))
            self.store.pending.unlink()
            sync_dir(self.store.state)
            return name
        except BaseException as original:
            try:
                self.recover()
            except BaseException:
                raise Error("Применение не завершено; автоматическое восстановление тоже не прошло. Журнал восстановления сохранён.", "sudo ruavc recover", 4) from original
            raise Error("Изменение отменено: предыдущая конфигурация восстановлена.", "sudo ruavc doctor") from original

    def rollback(self):
        runtime = read_json(self.store.state / "runtime.json")
        name = runtime.get("previous")
        if not name:
            raise Error("Нет предыдущей рабочей версии.")
        bundle = self.verify_generation(name)
        return self.apply(bundle, "rollback")
