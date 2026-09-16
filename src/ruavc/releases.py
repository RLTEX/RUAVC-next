"""Verified component acquisition. Components are updated independently."""

import io
import platform
import re
import zipfile

from . import model
from .errors import Error
from .network import fetch, fetch_json
from .storage import digest, mkdir, read, write


def architecture():
    arch = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if not arch:
        raise Error("Поддерживаются amd64 и arm64.")
    return arch


def latest(repository):
    release = fetch_json(f"https://api.github.com/repos/{repository}/releases/latest")
    if not re.fullmatch(r"v\d+\.\d+\.\d+", release.get("tag_name", "")) or release.get("draft") or release.get("prerelease"):
        raise Error("Источник не вернул стабильный релиз с корректной версией.")
    return release


def asset(release, name, repository, maximum):
    matches = [a for a in release.get("assets", []) if a.get("name") == name]
    if len(matches) != 1:
        raise Error("В релизе отсутствует обязательный файл.")
    item = matches[0]
    expected_url = f'https://github.com/{repository}/releases/download/{release["tag_name"]}/{name}'
    if item.get("browser_download_url") != expected_url:
        raise Error("Неожиданный источник release asset.")
    checksum = item.get("digest", "") or ""
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", checksum):
        raise Error("GitHub не предоставил SHA-256 asset; обновление остановлено.")
    data = fetch(expected_url, maximum, 60)
    if digest(data) != checksum[7:]:
        raise Error("SHA-256 загруженного компонента не совпадает.")
    return data


def install_code(store, data):
    # The trusted release is a zipapp; reject malformed packages before execution.
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = archive.namelist()
            if "__main__.py" not in names or "ruavc/cli.py" not in names or len(names) > 200 or any(n.startswith("/") or ".." in n.split("/") for n in names):
                raise Error("Некорректный пакет RUAVC.")
            if sum(x.file_size for x in archive.infolist()) > 16 * 1024 * 1024:
                raise Error("Слишком большой пакет RUAVC.")
            if archive.testzip() is not None:
                raise Error("Повреждён пакет RUAVC.")
    except zipfile.BadZipFile:
        raise Error("Некорректный архив RUAVC.") from None
    checksum = digest(data)
    path = mkdir(store.opt / "code" / checksum, 0o755) / "ruavc.pyz"
    if path.exists() and read(path) != data:
        raise Error("Существующий пакет RUAVC повреждён.")
    if not path.exists():
        write(path, data, 0o644)
    return checksum


def install_xray(store, update=False):
    arch = architecture()
    suffix = {"amd64": "64", "arm64": "arm64-v8a"}[arch]
    name = f"Xray-linux-{suffix}.zip"
    if update:
        release = latest("XTLS/Xray-core")
        data = asset(release, name, "XTLS/Xray-core", 64 * 1024 * 1024)
        version = release["tag_name"][1:]
    else:
        version = model.XRAY_VERSION
        url = f"https://github.com/XTLS/Xray-core/releases/download/v{version}/{name}"
        data = fetch(url, 64 * 1024 * 1024, 60)
        if digest(data) != model.XRAY_SHA[arch]:
            raise Error("SHA-256 Xray не совпадает с закреплённой версией.")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = [x for x in archive.infolist() if x.filename == "xray"]
            if len(entries) != 1 or entries[0].file_size > 128 * 1024 * 1024:
                raise Error("В архиве отсутствует допустимый бинарник Xray.")
            binary = archive.read(entries[0])
    except zipfile.BadZipFile:
        raise Error("Повреждён архив Xray.") from None
    if not binary.startswith(b"\x7fELF"):
        raise Error("Xray не является Linux ELF-файлом.")
    checksum = digest(binary)
    path = mkdir(store.opt / "xray" / checksum, 0o755) / "xray"
    if path.exists() and digest(read(path, limit=128 * 1024 * 1024)) != checksum:
        raise Error("Существующий бинарник Xray повреждён.")
    if not path.exists():
        write(path, binary, 0o755)
    return version, checksum
