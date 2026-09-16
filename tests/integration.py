"""Real Linux binaries, TLS, served subscriptions and VLESS round-trip.

Runs in disposable Ubuntu CI containers, never against an existing VPS.
"""

import copy
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ruavc import datasets, model, render, releases, system
from ruavc.install import gids
from ruavc.storage import Store, encoded, mkdir, read_json, write
from ruavc.transaction import Transaction


def main():
    if os.geteuid() != 0 or Path("/etc/ruavc/current").exists():
        raise SystemExit("Requires an empty disposable Linux container")
    store = Store()
    store.initialize()
    system.run(["/usr/sbin/groupadd", "--system", "ruavc-xray"])
    system.run(["/usr/sbin/useradd", "--system", "--gid", "ruavc-xray", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "ruavc-xray"])
    version, sha = releases.install_xray(store)
    code_sha = releases.install_code(store, Path("dist/ruavc.pyz").read_bytes())
    c = model.defaults("192.0.2.10", "vpn.example.com", "DE")
    c["reality"].update(port=19443, target="www.microsoft.com:443", sni="www.microsoft.com")
    c["web"]["port"] = 19444
    dataset = datasets.download(store, c)
    secret = system.keys()
    system.validate_keypair(secret)
    b = {"config": c, "secrets": secret, "devices": [model.new_device("phone")], "sites": {"direct": [], "proxy": ["domain:example.ru"]},
         "release": {"version": "0.1.0", "xray_version": version, "code_sha256": code_sha, "xray_sha256": sha, "dataset": dataset, "routing_revision": 1}}
    # Local CA is trusted only in this disposable test container.
    cert = mkdir(Path("/etc/letsencrypt/live/vpn.example.com"), 0o755)
    system.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=vpn.example.com", "-addext", "subjectAltName=DNS:vpn.example.com", "-keyout", cert / "privkey.pem", "-out", cert / "fullchain.pem"], quiet=True)
    shutil.copyfile(cert / "fullchain.pem", "/usr/local/share/ca-certificates/ruavc-test.crt")
    system.run(["/usr/sbin/update-ca-certificates"])
    mkdir(Path("/run/ruavc-web"), 0o755)
    services = system.Services(store)
    tx = Transaction(store, services, gids())
    name = tx.prepare(b)
    g = store.generation(name)
    store.activate(name)
    # Drop to the same service user: catches parent traversal/file mode regressions.
    processes = [subprocess.Popen(["/usr/sbin/runuser", "-u", "ruavc-xray", "--", str(services.xray_path(b)), "run", "-config", str(g / "generated/xray.json")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL),
                 subprocess.Popen(["/usr/sbin/nginx", "-c", str(g / "generated/nginx.conf"), "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)]
    try:
        for _ in range(60):
            if any(p.poll() is not None for p in processes):
                raise AssertionError("A real service failed to start")
            if system.listening(19443) and system.listening(19444):
                break
            time.sleep(0.1)
        from ruavc import network
        d = b["devices"][0]
        status, headers, body = network.local_https(c, "/sub/" + d["token"])
        assert status == 200 and body == render.subscription(b, d).encode()
        assert headers["autorouting"] == render.autorouting(c, d)
        assert network.local_https(c, "/sub/" + "0" * 64)[0] == 404
        assert network.local_https(c, "/rules/../secrets.json")[0] != 200
        status, _, body = network.local_https(c, "/routing/" + d["token"] + ".json")
        assert status == 200 and body == encoded(render.routing(b))
        for kind in ("geoip", "geosite"):
            status, _, body = network.local_https(c, f"/rules/{dataset}/{kind}.dat")
            assert status == 200
            datasets.validate_geo(body, kind)
        services.probe_vless(b, d)
        wrong = copy.deepcopy(d)
        wrong["uuid"] = model.new_device("wrong")["uuid"]
        from ruavc.errors import Error
        try:
            services.probe_vless(b, wrong)
        except Error:
            pass
        else:
            raise AssertionError("Wrong UUID unexpectedly authenticated")
        print("PASS: real Xray validation, non-root launch, nginx TLS, INCY content, geo endpoints, VLESS positive/negative")
    finally:
        for p in processes:
            p.terminate()
        for p in processes:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)


if __name__ == "__main__":
    main()
