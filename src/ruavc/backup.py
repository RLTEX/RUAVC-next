"""Portable root-only backups with a strict, non-extracting archive reader."""

import io
import json
import os
from pathlib import Path
import re
import tarfile
import time

from . import datasets, model, releases
from .errors import Error
from .storage import digest, encoded, mkdir, read, write

DOCUMENTS = {p + ".json" for p in ("config", "secrets", "devices", "sites", "release")}
FILES = DOCUMENTS | {"ruavc.pyz", "xray", "geoip.dat", "geosite.dat", "geoip.dat.sha256", "geosite.dat.sha256", "dataset.json", "checksums.json"}


def create(store):
    bundle = store.load()
    data = {part + ".json": encoded(value) for part, value in bundle.items()}
    r = bundle["release"]
    data["ruavc.pyz"] = read(store.opt / "code" / r["code_sha256"] / "ruavc.pyz")
    data["xray"] = read(store.opt / "xray" / r["xray_sha256"] / "xray", limit=128 * 1024 * 1024)
    path = store.state / "datasets" / r["dataset"]
    for name in ("geoip.dat", "geosite.dat", "geoip.dat.sha256", "geosite.dat.sha256"):
        data[name] = read(path / name, limit=32 * 1024 * 1024)
    data["dataset.json"] = read(path / "manifest.json")
    data["checksums.json"] = encoded({name: digest(value) for name, value in data.items()})
    import secrets
    name = "backup-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4) + ".tar.gz"
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for filename, value in sorted(data.items()):
            info = tarfile.TarInfo(filename)
            info.size = len(value)
            info.mode = 0o600
            info.mtime = int(time.time())
            archive.addfile(info, io.BytesIO(value))
    write(store.backups / name, output.getvalue())
    return name


def restore(store, name, transaction):
    if not re.fullmatch(r"backup-[0-9TZ]+-[a-f0-9]{8}\.tar\.gz", name):
        raise Error("Некорректное имя backup; допустим файл из ruavc backup list.")
    raw = read(store.backups / name, private=True, limit=200 * 1024 * 1024)
    data = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for member in archive:
                total += member.size
                if member.name not in FILES or member.name in data or not member.isfile() or member.size < 0 or total > 200 * 1024 * 1024:
                    raise Error("Backup содержит недопустимые файлы или превышает размер.")
                data[member.name] = archive.extractfile(member).read(member.size + 1)
    except (tarfile.TarError, OSError):
        raise Error("Повреждён архив backup.") from None
    if set(data) != FILES:
        raise Error("Backup неполный.")
    try:
        hashes = json.loads(data["checksums.json"])
        if hashes != {k: digest(v) for k, v in data.items() if k != "checksums.json"}:
            raise Error("Контрольные суммы backup не совпадают.")
        bundle = {name.removesuffix(".json"): json.loads(data[name]) for name in DOCUMENTS}
        model.validate(bundle)
    except (ValueError, TypeError, KeyError):
        raise Error("Некорректные документы backup.") from None
    r = bundle["release"]
    if digest(data["xray"]) != r["xray_sha256"] or digest(data["ruavc.pyz"]) != r["code_sha256"]:
        raise Error("Компоненты backup не соответствуют состоянию релиза.")
    releases.install_code(store, data["ruavc.pyz"])
    binary = mkdir(store.opt / "xray" / r["xray_sha256"], 0o755) / "xray"
    if not binary.exists():
        write(binary, data["xray"], 0o755)
    path = mkdir(store.state / "datasets" / r["dataset"], 0o755)
    for key in ("geoip.dat", "geosite.dat", "geoip.dat.sha256", "geosite.dat.sha256"):
        if not (path / key).exists():
            write(path / key, data[key], 0o644)
    if not (path / "manifest.json").exists():
        write(path / "manifest.json", data["dataset.json"], 0o644)
    datasets.verify(store, r["dataset"])
    from .install import certificate
    certificate(bundle["config"])
    return transaction.apply(bundle, "backup restore")
