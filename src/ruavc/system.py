"""System boundary: subprocesses, service health, secret-safe diagnostics."""

import base64
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time

from .errors import Error
from . import network, render
from .storage import digest, encoded, mkdir, read, safe_path, write


def redact(text):
    text = re.sub(r"vless://[^\s\"']+", "[VLESS скрыт]", text)
    text = re.sub(r"(?i)(/(?:sub|routing)/)[^\s\"'<>]+", r"\1[скрыто]", text)
    text = re.sub(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", "[UUID скрыт]", text)
    text = re.sub(r"(?<![\w-])[A-Za-z0-9_-]{43,}(?![\w-])", "[ключ/хеш скрыт]", text)
    text = re.sub(r'(?i)(short_?id[s]?\s*[":= ]+)[^\s,}\]]+', r"\1[скрыто]", text)
    return text


def probe_diagnostic(bundle, device, curl_error, xray_output, limit=4000):
    text = "curl: " + curl_error.decode("utf-8", "replace").strip()[-500:] + "\nxray: " + xray_output.decode("utf-8", "replace")[-limit:]
    # Known credentials are removed verbatim before the generic patterns run.
    for value in (device["uuid"], device["token"], *bundle["secrets"].values()):
        text = text.replace(value, "[скрыто]")
    return redact(text)


def log(message):
    path = Path("/var/log/ruavc")
    mkdir(path)
    file = safe_path(path / "manager.log")
    # Bound size without following pre-existing links or logging secrets.
    if file.exists() and file.stat().st_size > 2 * 1024 * 1024:
        write(path / "manager.previous.log", read(file))
        write(file, b"")
    fd = os.open(file, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + " " + redact(str(message)) + "\n")


def run(args, input_data=None, timeout=30, check=True, env_extra=None, quiet=False):
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": "/root"}
    if env_extra:
        env.update(env_extra)
    try:
        result = subprocess.run([str(x) for x in args], input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f"Не удалось выполнить {Path(str(args[0])).name} ({type(exc).__name__}).") from None
    if result.returncode and check:
        if not quiet:
            log(Path(str(args[0])).name + ": " + result.stderr.decode("utf-8", "replace")[-12000:])
        raise Error(f"Команда {Path(str(args[0])).name} завершилась с кодом {result.returncode}.")
    return result


def free_port(number):
    try:
        with socket.socket() as sock:
            sock.bind(("0.0.0.0", number))
        return True
    except OSError:
        return False


def listening(number):
    try:
        with socket.create_connection(("127.0.0.1", number), timeout=1):
            return True
    except OSError:
        return False


def keys():
    private = run(["/usr/bin/openssl", "genpkey", "-algorithm", "X25519", "-outform", "DER"], quiet=True).stdout
    public = run(["/usr/bin/openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input_data=private, quiet=True).stdout
    return {"private_key": base64.urlsafe_b64encode(private[-32:]).decode().rstrip("="), "public_key": base64.urlsafe_b64encode(public[-32:]).decode().rstrip("="), "short_id": secrets.token_hex(8)}


def validate_keypair(secret):
    raw = base64.urlsafe_b64decode(secret["private_key"] + "=")
    der = bytes.fromhex("302e020100300506032b656e04220420") + raw
    result = run(["/usr/bin/openssl", "pkey", "-inform", "DER", "-pubout", "-outform", "DER"], input_data=der, quiet=True).stdout
    if base64.urlsafe_b64encode(result[-32:]).decode().rstrip("=") != secret["public_key"]:
        raise Error("Приватный и публичный ключи Reality не образуют пару.")


class Services:
    names = ("ruavc-xray.service", "ruavc-web.service")

    def __init__(self, store):
        self.store = store

    def xray_path(self, bundle):
        return self.store.opt / "xray" / bundle["release"]["xray_sha256"] / "xray"

    def active(self, name):
        return run(["/usr/bin/systemctl", "is-active", "--quiet", name], check=False).returncode == 0

    def validate(self, generation, bundle):
        validate_keypair(bundle["secrets"])
        binary = self.xray_path(bundle)
        if digest(read(binary, limit=128 * 1024 * 1024)) != bundle["release"]["xray_sha256"]:
            raise Error("Хеш исполняемого файла Xray не совпадает.")
        code = self.store.opt / "code" / bundle["release"]["code_sha256"] / "ruavc.pyz"
        if digest(read(code)) != bundle["release"]["code_sha256"]:
            raise Error("Хеш программы RUAVC не совпадает.")
        run([binary, "run", "-test", "-config", generation / "generated/xray.json"])
        run([binary, "run", "-test", "-config", generation / "generated/routing-test.json"], env_extra={"XRAY_LOCATION_ASSET": str(self.store.state / "datasets" / bundle["release"]["dataset"])})
        run(["/usr/sbin/nginx", "-t", "-c", generation / "generated/nginx.conf"])

    def restart(self):
        run(["/usr/bin/systemctl", "restart", *self.names], timeout=45)
        for _ in range(30):
            if all(self.active(n) for n in self.names):
                return
            time.sleep(0.2)
        raise Error("Службы не перешли в состояние active после применения.")

    def stop(self):
        run(["/usr/bin/systemctl", "stop", *self.names], timeout=45)

    def running_generation(self, generation):
        pid = run(["/usr/bin/systemctl", "show", "-p", "MainPID", "--value", "ruavc-xray.service"]).stdout.decode().strip()
        if not pid.isdigit() or pid == "0":
            raise Error("Нет работающего процесса Xray.")
        try:
            argv = Path("/proc") / pid / "cmdline"
            args = argv.read_bytes().split(b"\0")
        except OSError:
            raise Error("Не удалось определить запущенную конфигурацию Xray.") from None
        if str(generation / "generated/xray.json").encode() not in args:
            raise Error("Xray работает с другой версией конфигурации.")

    def probe_vless(self, bundle, device):
        run_dir = mkdir(self.store.root / "run/ruavc", 0o700)
        with tempfile.TemporaryDirectory(prefix="probe-", dir=run_dir) as work:
            with socket.socket() as sock:
                sock.bind(("127.0.0.1", 0))
                number = sock.getsockname()[1]
            config = Path(work) / "client.json"
            write(config, encoded(render.probe_client(bundle, device, number)))
            binary = self.xray_path(bundle)
            run([binary, "run", "-test", "-config", config], quiet=True)
            output = Path(work) / "client.log"
            fd = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as sink:
                process = subprocess.Popen([str(binary), "run", "-config", str(config)], stdout=sink, stderr=subprocess.STDOUT,
                                           env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            failure, detail = None, b""
            try:
                for _ in range(50):
                    if process.poll() is not None:
                        failure = "Временный Xray-клиент не запустился."
                        break
                    if listening(number):
                        break
                    time.sleep(0.1)
                if failure is None:
                    # Only a non-secret probe URL is in argv. Device keys stay in 0600 file.
                    result = run(["/usr/bin/curl", "--silent", "--show-error", "--fail", "--proto", "=https", "--max-time", "15", "--socks5-hostname", f"127.0.0.1:{number}", "--output", "/dev/null", bundle["config"]["probe_url"]], timeout=20, check=False, quiet=True)
                    if process.poll() is not None or result.returncode:
                        failure, detail = "VLESS self-test VPS не прошёл: ключ, Reality handshake или выход в Интернет.", result.stderr
                        time.sleep(0.5)  # Xray reports the outbound error right after closing the SOCKS stream.
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            if failure:
                log("VLESS self-test: " + probe_diagnostic(bundle, device, detail, read(output)))
                raise Error(failure + " Диагностика: /var/log/ruavc/manager.log.", "sudo ruavc doctor")

    def ready(self, generation, bundle, timeout=20):
        # Type=simple units are "active" before the launcher execs Xray/nginx and
        # before they listen, so a restart is followed by a bounded wait.
        c = bundle["config"]
        deadline = time.monotonic() + timeout
        while True:
            try:
                for name in self.names:
                    if not self.active(name):
                        raise Error(f"Служба {name} не работает.")
                self.running_generation(generation)
                for number in (c["reality"]["port"], c["web"]["port"]):
                    if not listening(number):
                        raise Error(f"Служба не слушает TCP {number}.")
                return
            except Error:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)

    def health(self, generation, bundle, revoked_tokens=()):
        self.ready(generation, bundle)
        c = bundle["config"]
        network.tls_probe("127.0.0.1", c["reality"]["port"], c["reality"]["sni"], public=False)
        status, _, _ = network.local_https(c, "/")
        if status != 404:
            raise Error("HTTPS endpoint обслуживается неожиданным обработчиком.")
        dataset = bundle["release"]["dataset"]
        for kind in ("geoip", "geosite"):
            base = "/rules/" + dataset + "/" + kind + ".dat"
            code, _, data = network.local_https(c, base, limit=32 * 1024 * 1024)
            expected = read(self.store.state / "datasets" / dataset / (kind + ".dat.sha256")).decode().strip()
            if code != 200 or digest(data) != expected:
                raise Error("HTTPS отдаёт неверный geo-файл.")
            code, _, data = network.local_https(c, base + ".sha256")
            if code != 200 or data.decode().strip() != expected:
                raise Error("HTTPS отдаёт неверную контрольную сумму geo-файла.")
        for device in bundle["devices"]:
            code, headers, body = network.local_https(c, "/sub/" + device["token"])
            if code != 200 or body != render.subscription(bundle, device).encode() or headers.get("autorouting") != render.autorouting(c, device):
                raise Error("Подписка не соответствует активной конфигурации.")
            code, _, body = network.local_https(c, "/routing/" + device["token"] + ".json")
            if code != 200 or body != encoded(render.routing(bundle)):
                raise Error("INCY получает устаревший профиль маршрутизации.")
        for token in revoked_tokens:
            for path in ("/sub/" + token, "/routing/" + token + ".json"):
                if network.local_https(c, path)[0] != 404:
                    raise Error("Старая ссылка продолжает обслуживаться после отзыва.")
        for device in bundle["devices"]:
            self.probe_vless(bundle, device)
