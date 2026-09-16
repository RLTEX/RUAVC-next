"""Immutable, checksum-verified routing datasets with protobuf validation."""

import ipaddress
import os
import re
import tempfile
import shutil

from .errors import Error
from .network import branch_commit, fetch
from .storage import digest, encoded, mkdir, read, read_json, sync_dir, write


def varint(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise Error("Оборванный protobuf в geo-файле.")
        byte = data[offset]
        offset += 1
        value |= (byte & 127) << shift
        if byte < 128:
            return value, offset
    raise Error("Некорректный varint в geo-файле.")


def fields(data):
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        number, kind = key >> 3, key & 7
        if not number:
            raise Error("Нулевой тег protobuf.")
        if kind == 0:
            value, offset = varint(data, offset)
        elif kind == 2:
            size, offset = varint(data, offset)
            if size > len(data) - offset:
                raise Error("Некорректная длина protobuf.")
            value = data[offset:offset + size]
            offset += size
        elif kind in (1, 5):
            size = 8 if kind == 1 else 4
            if offset + size > len(data):
                raise Error("Оборванный protobuf.")
            value = data[offset:offset + size]
            offset += size
        else:
            raise Error("Неподдерживаемое поле protobuf.")
        yield number, kind, value


def validate_geo(data, kind):
    if not 8 <= len(data) <= 32 * 1024 * 1024:
        raise Error("Недопустимый размер geo-файла.")
    tags = {}
    try:
        for number, wire, group in fields(data):
            if number != 1 or wire != 2:
                raise Error("Неверная структура GeoList.")
            code = None
            count = 0
            for field, typ, value in fields(group):
                if field == 1 and typ == 2:
                    code = value.decode("ascii").lower()
                    if not re.fullmatch(r"[a-z0-9_-]+", code):
                        raise Error("Некорректное имя geo-категории.")
                elif field == 2 and typ == 2:
                    entry = {k: (t, v) for k, t, v in fields(value)}
                    if kind == "geoip":
                        raw_ip = entry.get(1, (2, b""))[1]
                        prefix = entry.get(2, (0, 0))[1]
                        ip = ipaddress.ip_address(raw_ip)
                        if not isinstance(prefix, int) or not 0 <= prefix <= ip.max_prefixlen:
                            raise Error("Некорректный CIDR geoip.")
                    else:
                        entry_type = entry.get(1, (0, 0))[1]
                        raw_domain = entry.get(2, (2, b""))[1]
                        if entry_type not in (0, 1, 2, 3) or not isinstance(raw_domain, bytes) or not raw_domain or len(raw_domain) > 4096:
                            raise Error("Некорректная доменная запись geosite.")
                        raw_domain.decode("utf-8")
                    count += 1
            if not code or count == 0 or code in tags:
                raise Error("Пустая или повторная geo-категория.")
            tags[code] = count
    except (ValueError, TypeError, UnicodeError):
        raise Error("Повреждена структура geo-файла.") from None
    required = {"ru", "private"} if kind == "geoip" else {"ru-inside"}
    if not required.issubset(tags):
        raise Error("Geo-файл не содержит обязательных российских/локальных категорий.")
    return tags


# Xray Domain.Type -> rule prefix.
DOMAIN_RULES = {0: "keyword:", 1: "regexp:", 2: "domain:", 3: "full:"}
RU_ZONES = ("ru", "su", "xn--p1ai", "xn--p1acf")
DIRECT_CATEGORY = "ru-inside"


def category_rules(data, code):
    rules = set()
    for _, _, group in fields(data):
        entries = list(fields(group))
        if not any(f == 1 and v.decode("ascii").lower() == code for f, _, v in entries):
            continue
        for f, _, value in entries:
            if f == 2:
                entry = {k: v for k, _, v in fields(value)}
                rules.add(DOMAIN_RULES[entry.get(1, 0)] + entry[2].decode("utf-8"))
    return rules


def direct_sites(store, identifier):
    """Russian services as explicit rules: clients may route with their own geo files.

    INCY for Windows applies the server profile with its bundled geosite.dat,
    which has no RU-INSIDE category, so a geosite: reference breaks Xray there.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", identifier):
        raise Error("Неверный идентификатор geo-данных.")
    data = read(store.state / "datasets" / identifier / "geosite.dat", limit=32 * 1024 * 1024)
    zones = tuple("." + zone for zone in RU_ZONES)
    result = []
    for rule in sorted(category_rules(data, DIRECT_CATEGORY)):
        prefix, _, value = rule.partition(":")
        if prefix in ("domain", "full") and not re.fullmatch(r"[a-z0-9._-]+", value):
            raise Error("Некорректный домен в geo-категории.")
        # The zones are routed directly by suffix rules already.
        if prefix in ("domain", "full") and ("." + value).endswith(zones):
            continue
        result.append(rule)
    return result


def download(store, config):
    parts = {}
    metadata = {}
    for kind in ("geoip", "geosite"):
        repo = config["routing"][kind + "_repository"]
        commit = branch_commit(repo, "release")
        base = f"https://raw.githubusercontent.com/{repo}/{commit}/{kind}.dat"
        expected = fetch(base + ".sha256sum", 1024).decode("ascii").split()[0].lower()
        data = fetch(base, 32 * 1024 * 1024, 60)
        actual = digest(data)
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or actual != expected:
            raise Error("SHA-256 geo-файла не совпадает; рабочие правила сохранены.")
        tags = validate_geo(data, kind)
        parts[kind] = data
        metadata[kind] = {"repository": repo, "commit": commit, "sha256": actual, "tags": tags}
    identifier = digest(encoded({k: digest(v) for k, v in parts.items()}))
    destination = store.state / "datasets" / identifier
    if destination.exists():
        verify(store, identifier)
        return identifier
    from pathlib import Path
    staging = Path(tempfile.mkdtemp(prefix=".download-", dir=destination.parent))
    try:
        for kind, data in parts.items():
            write(staging / (kind + ".dat"), data, 0o644)
            write(staging / (kind + ".dat.sha256"), digest(data) + "\n", 0o644)
        write(staging / "manifest.json", encoded(metadata), 0o644)
        os.chmod(staging, 0o755)
        sync_dir(staging)
        os.rename(staging, destination)
        sync_dir(destination.parent)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return identifier


def verify(store, identifier):
    if not re.fullmatch(r"[0-9a-f]{64}", identifier):
        raise Error("Неверный идентификатор geo-данных.")
    path = store.state / "datasets" / identifier
    manifest = read_json(path / "manifest.json", private=False)
    hashes = {}
    for kind in ("geoip", "geosite"):
        data = read(path / (kind + ".dat"), limit=32 * 1024 * 1024)
        hashes[kind] = digest(data)
        if hashes[kind] != manifest[kind]["sha256"] or read(path / (kind + ".dat.sha256")).decode().strip() != hashes[kind]:
            raise Error("Geo-файл не совпадает с manifest/SHA-256.")
        validate_geo(data, kind)
    if digest(encoded(hashes)) != identifier:
        raise Error("Хеш набора geo-данных не совпадает.")
    return manifest
