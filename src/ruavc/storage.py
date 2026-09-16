"""Root-owned storage, durable writes, and one interprocess mutation lock."""

import contextlib
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

from .errors import Error


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")


def sync_dir(path):
    if os.name == "posix":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def safe_path(path, allow_missing=True):
    path = Path(path).absolute()
    for part in reversed([path, *path.parents]):
        try:
            info = part.lstat()
        except FileNotFoundError:
            if allow_missing:
                continue
            raise Error("Не найден обязательный файл или каталог.") from None
        if stat.S_ISLNK(info.st_mode):
            raise Error("Обнаружена неподдерживаемая символическая ссылка в управляемом пути.")
        if os.name == "posix" and (info.st_uid not in {0, os.geteuid()} or info.st_mode & 0o022):
            # Sticky /tmp is permitted only as an ancestor of a private test/staging root.
            if not (part == Path("/tmp") and info.st_mode & stat.S_ISVTX):
                raise Error("Управляемый путь не принадлежит root или доступен для посторонней записи.")
    return path


def mkdir(path, mode=0o700, gid=None):
    path = safe_path(path)
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    os.chmod(path, mode)
    if gid is not None and os.name == "posix":
        os.chown(path, 0, gid)
    return path


def write(path, data, mode=0o600, gid=None):
    path = safe_path(path)
    if isinstance(data, str):
        data = data.encode("utf-8")
    fd, temp = tempfile.mkstemp(prefix=".write-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            if os.name == "posix":
                os.fchmod(f.fileno(), mode)
                if gid is not None:
                    os.fchown(f.fileno(), os.geteuid(), gid)
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        sync_dir(path.parent)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def read(path, private=False, limit=8 * 1024 * 1024):
    path = safe_path(path, allow_missing=False)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit or (os.name == "posix" and private and info.st_mode & 0o077):
            raise Error("Неверный тип, размер или права файла конфигурации.")
        return f.read(limit + 1)


def read_json(path, private=True):
    try:
        return json.loads(read(path, private))
    except (ValueError, UnicodeError):
        raise Error("Повреждён JSON-документ; требуется восстановление.") from None


class Store:
    def __init__(self, root=Path("/")):
        self.root = Path(root).absolute()
        self.etc = self.root / "etc/ruavc"
        self.generations = self.etc / "generations"
        self.state = self.root / "var/lib/ruavc"
        self.opt = self.root / "opt/ruavc"
        self.backups = self.root / "var/backups/ruavc"
        self.current = self.etc / "current"
        self.pending = self.state / "pending.json"

    def initialize(self):
        for path, mode in ((self.etc, 0o711), (self.generations, 0o711), (self.state, 0o711),
                           (self.state / "datasets", 0o755), (self.opt, 0o755),
                           (self.opt / "code", 0o755), (self.opt / "xray", 0o755), (self.backups, 0o700)):
            mkdir(path, mode)

    def generation(self, name):
        import re
        if not isinstance(name, str) or not re.fullmatch(r"g-[0-9a-f]{24}", name):
            raise Error("Некорректный идентификатор версии состояния.")
        path = self.generations / name
        safe_path(path)
        return path

    def active_name(self):
        if not self.current.is_symlink():
            if self.current.exists():
                raise Error("current должен быть управляемой символической ссылкой.")
            return None
        raw = os.readlink(self.current)
        name = raw.removeprefix("generations/")
        if raw != "generations/" + name:
            raise Error("current указывает за пределы хранилища.")
        self.generation(name)
        return name

    def activate(self, name):
        safe_path(self.etc)
        self.active_name()
        if name is None:
            if self.current.is_symlink():
                self.current.unlink()
                sync_dir(self.etc)
            return
        self.generation(name)
        import secrets
        link = self.etc / (".pointer-" + secrets.token_hex(8))
        os.symlink("generations/" + name, link, target_is_directory=True)
        os.replace(link, self.current)
        sync_dir(self.etc)

    def load(self, name=None):
        name = name or self.active_name()
        if not name:
            raise Error("RUAVC ещё не установлен.", "Команда установки из README")
        generation = self.generation(name)
        return {part: read_json(generation / (part + ".json")) for part in ("config", "secrets", "devices", "sites", "release")}

    @contextlib.contextmanager
    def lock(self):
        import fcntl
        self.initialize()
        path = safe_path(self.etc / "lock")
        fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            if os.fstat(fd).st_uid != os.geteuid() or os.fstat(fd).st_mode & 0o077:
                raise Error("Небезопасные права lock-файла.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("Другая операция RUAVC уже выполняется.", "Повторный запуск после завершения операции", 3) from None
            yield
        finally:
            os.close(fd)
