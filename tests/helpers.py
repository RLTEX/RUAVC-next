import base64
import io
import os
from pathlib import Path
import sys
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ruavc import model
from ruavc.storage import Store, digest, encoded, mkdir, write


def vi(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, value):
    return vi((number << 3) | 2) + vi(len(value)) + value


def geo(kind):
    if kind == "geoip":
        return b"".join(field(1, field(1, tag) + field(2, field(1, ip) + b"\x10\x08")) for tag, ip in ((b"RU", b"\x05\x00\x00\x00"), (b"PRIVATE", b"\x0a\x00\x00\x00")))
    return field(1, field(1, b"RU-INSIDE") + field(2, b"\x08\x02" + field(2, b"example.ru")))


def bundle():
    config = model.defaults("192.0.2.10", "vpn.example.com", "DE")
    config["reality"].update(target="example.com:443", sni="example.com")
    return {"config": config, "secrets": {"private_key": base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("="), "public_key": base64.urlsafe_b64encode(bytes(range(32, 64))).decode().rstrip("="), "short_id": "a1b2c3d4e5f60718"},
            "devices": [model.new_device("телефон-1")], "sites": {"direct": [], "proxy": []},
            "release": {"version": "0.1.0", "xray_version": "26.3.27", "code_sha256": "0" * 64, "xray_sha256": "1" * 64, "dataset": "2" * 64, "routing_revision": 100}}


class PortableStore(Store):
    """Windows lacks unprivileged symlinks; Linux exercises the real pointer."""
    def active_name(self):
        if os.name == "posix":
            return super().active_name()
        return self.current.read_text() if self.current.exists() else None

    def activate(self, name):
        if os.name == "posix":
            return super().activate(name)
        if name:
            write(self.current, name)
        else:
            self.current.unlink(missing_ok=True)


class FakeServices:
    names = ("ruavc-xray.service", "ruavc-web.service")

    def __init__(self, store):
        self.store = store
        self.failure = None
        self.restarts = 0
        self.stops = 0
        self.revoked = []

    def xray_path(self, bundle):
        return self.store.opt / "xray" / bundle["release"]["xray_sha256"] / "xray"

    def active(self, name):
        return True

    def validate(self, generation, bundle):
        self.check("validate")

    def restart(self):
        self.restarts += 1
        self.check("restart")

    def stop(self):
        self.stops += 1

    def health(self, generation, bundle, revoked_tokens=()):
        self.revoked.extend(revoked_tokens)
        self.check("health")

    def check(self, phase):
        if self.failure == phase:
            self.failure = None
            from ruavc.errors import Error
            raise Error("Injected " + phase)


def populate(store, b):
    store.initialize()
    parts = {kind: geo(kind) for kind in ("geoip", "geosite")}
    hashes = {k: digest(v) for k, v in parts.items()}
    identifier = digest(encoded(hashes))
    path = mkdir(store.state / "datasets" / identifier, 0o755)
    for kind, data in parts.items():
        write(path / (kind + ".dat"), data, 0o644)
        write(path / (kind + ".dat.sha256"), hashes[kind] + "\n", 0o644)
    write(path / "manifest.json", encoded({k: {"sha256": v} for k, v in hashes.items()}), 0o644)
    b["release"]["dataset"] = identifier
    package = io.BytesIO()
    with zipfile.ZipFile(package, "w") as z:
        z.writestr("__main__.py", "pass\n")
        z.writestr("ruavc/cli.py", "pass\n")
    from ruavc.releases import install_code
    b["release"]["code_sha256"] = install_code(store, package.getvalue())
    binary = b"\x7fELFtest-only-not-executable"
    b["release"]["xray_sha256"] = digest(binary)
    write(mkdir(store.opt / "xray" / digest(binary), 0o755) / "xray", binary, 0o755)
    return b
