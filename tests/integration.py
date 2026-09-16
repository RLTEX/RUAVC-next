"""Real Linux binaries, TLS, served subscriptions and VLESS round-trip.

Runs in disposable Ubuntu CI containers, never against an existing VPS.
The Reality target and the probe endpoint are local nginx fixtures, so the
result does not depend on third-party sites. The container needs NET_ADMIN
to give the probe endpoint a non-private address (Xray blocks private ones).
"""

import copy
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ruavc import datasets, model, network, render, releases, system
from ruavc.errors import Error
from ruavc.install import gids
from ruavc.storage import Store, encoded, mkdir, read_json, write
from ruavc.transaction import Transaction

FIXTURES = Path("/run/ruavc-fixture")
PROBE_ADDRESS = "198.18.0.10"  # RFC 2544 benchmark range: global enough for Xray routing, never routed
REALITY_SNI = "reality.ruavc.test"
OVERSIZED_SNI = "oversized.ruavc.test"
PROBE_HOST = "probe.ruavc.test"
MANAGER_LOG = Path("/var/log/ruavc/manager.log")


def certificate(name, *extra):
    # Local CA is trusted only in this disposable test container.
    key, crt = FIXTURES / (name + ".key"), FIXTURES / (name + ".crt")
    system.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=" + name,
                "-addext", "subjectAltName=DNS:" + name, *extra, "-keyout", key, "-out", crt], quiet=True)
    shutil.copyfile(crt, f"/usr/local/share/ca-certificates/{name}.crt")
    return key, crt


def local_address(address, *names):
    system.run([shutil.which("ip", path="/usr/sbin:/usr/bin:/sbin:/bin"), "address", "add", address + "/32", "dev", "lo"])
    if names:
        with open("/etc/hosts", "a", encoding="utf-8") as hosts:
            hosts.write(address + " " + " ".join(names) + "\n")


def fixtures(reality_listen="127.0.0.1:19445"):
    """Reality targets (compatible and oversized) and the probe endpoint."""
    mkdir(FIXTURES, 0o755)
    local_address(PROBE_ADDRESS, PROBE_HOST)
    small = certificate(REALITY_SNI)
    # Incompressible payload: TLS certificate compression must not hide the size,
    # like a stapled OCSP chain that is larger than REALITY's 8192-byte buffer.
    blob = secrets.token_bytes(9000).hex()
    large = certificate(OVERSIZED_SNI, "-addext", "1.3.6.1.4.1.55555.1=ASN1:FORMAT:HEX,OCTETSTRING:" + blob)
    probe = certificate(PROBE_HOST)
    system.run(["/usr/sbin/update-ca-certificates"])

    def server(listen, name, files, body):
        return f"""    server {{
        listen {listen} ssl http2;
        server_name {name};
        ssl_protocols TLSv1.3;
        ssl_certificate {files[1]};
        ssl_certificate_key {files[0]};
        {body}
    }}
"""
    servers = (server(reality_listen, REALITY_SNI, small, "return 404;")
               + server("127.0.0.1:19446", OVERSIZED_SNI, large, "return 404;")
               + server(PROBE_ADDRESS + ":443", PROBE_HOST, probe, "location = /generate_204 { return 204; } location / { return 404; }"))
    conf = FIXTURES / "nginx.conf"
    write(conf, f"""pid {FIXTURES}/nginx.pid;
error_log stderr warn;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {FIXTURES}/body;
{servers}}}
""", mode=0o644)
    return conf


def spawn(name, args):
    with open(FIXTURES / (name + ".out"), "wb") as sink:
        return subprocess.Popen([str(x) for x in args], stdout=sink, stderr=subprocess.STDOUT)


def wait_ports(processes, ports):
    for _ in range(100):
        if any(p.poll() is not None for p in processes):
            raise AssertionError("A real service failed to start")
        if all(system.listening(n) for n in ports):
            return
        time.sleep(0.1)
    raise AssertionError(f"Services are not listening on {ports}")


def expect_probe_failure(services, bundle, device, reason):
    before = MANAGER_LOG.read_bytes() if MANAGER_LOG.exists() else b""
    try:
        services.probe_vless(bundle, device)
    except Error:
        pass
    else:
        raise AssertionError(reason + " unexpectedly passed the VLESS self-test")
    entry = MANAGER_LOG.read_text(encoding="utf-8")[len(before.decode("utf-8")):]
    assert "VLESS self-test" in entry and "xray:" in entry, entry
    for value in (device["uuid"], device["token"], *bundle["secrets"].values()):
        assert value not in entry, "Diagnostic log leaked a credential"
    return entry


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
    c["reality"].update(port=19443, target="127.0.0.1:19445", sni=REALITY_SNI)
    c["web"]["port"] = 19444
    c["probe_url"] = f"https://{PROBE_HOST}/generate_204"
    dataset = datasets.download(store, c)
    secret = system.keys()
    system.validate_keypair(secret)
    b = {"config": c, "secrets": secret, "devices": [model.new_device("phone")], "sites": {"direct": [], "proxy": ["domain:example.ru"]},
         "release": {"version": "0.1.0", "xray_version": version, "code_sha256": code_sha, "xray_sha256": sha, "dataset": dataset, "routing_revision": 1}}
    cert = mkdir(Path("/etc/letsencrypt/live/vpn.example.com"), 0o755)
    system.run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=vpn.example.com", "-addext", "subjectAltName=DNS:vpn.example.com", "-keyout", cert / "privkey.pem", "-out", cert / "fullchain.pem"], quiet=True)
    shutil.copyfile(cert / "fullchain.pem", "/usr/local/share/ca-certificates/ruavc-test.crt")
    fixture_conf = fixtures()
    mkdir(Path("/run/ruavc-web"), 0o755)
    services = system.Services(store)
    tx = Transaction(store, services, gids())
    name = tx.prepare(b)
    g = store.generation(name)
    store.activate(name)

    # Same target as the Microsoft failure, reproduced locally: REALITY cannot copy it.
    big = copy.deepcopy(b)
    big["config"]["reality"].update(port=19447, target="127.0.0.1:19446", sni=OVERSIZED_SNI)
    big_config = FIXTURES / "oversized-xray.json"
    write(big_config, encoded(render.xray(big)))

    processes = [spawn("fixture-nginx", ["/usr/sbin/nginx", "-c", fixture_conf, "-g", "daemon off;"])]
    try:
        wait_ports(processes, (19445, 19446))
        # Drop to the same service user: catches parent traversal/file mode regressions.
        processes += [spawn("xray", ["/usr/sbin/runuser", "-u", "ruavc-xray", "--", services.xray_path(b), "run", "-config", g / "generated/xray.json"]),
                      spawn("nginx", ["/usr/sbin/nginx", "-c", g / "generated/nginx.conf", "-g", "daemon off;"]),
                      spawn("oversized-xray", [services.xray_path(b), "run", "-config", big_config])]
        wait_ports(processes, (19443, 19444, 19447))

        result = network.tls_probe("127.0.0.1", 19445, REALITY_SNI, public=False)
        assert result["alpn"] == "h2" and result["first_flight_bytes"] <= network.REALITY_FLIGHT_LIMIT, result
        try:
            network.tls_probe("127.0.0.1", 19446, OVERSIZED_SNI, public=False)
        except Error as exc:
            assert str(network.REALITY_FLIGHT_LIMIT) in str(exc), exc
        else:
            raise AssertionError("Oversized Reality target was accepted")
        # Through the running Reality port an unauthenticated client sees the target.
        network.tls_probe("127.0.0.1", 19443, REALITY_SNI, public=False)

        d = b["devices"][0]
        status, headers, body = network.local_https(c, "/sub/" + d["token"])
        assert status == 200 and body == render.subscription(b, d).encode()
        assert headers["autorouting"] == render.autorouting(c, d)
        assert network.local_https(c, "/sub/" + "0" * 64)[0] == 404
        assert network.local_https(c, "/rules/../secrets.json")[0] != 200
        status, _, body = network.local_https(c, "/routing/" + d["token"] + ".json")
        assert status == 200 and body == encoded(render.routing(b, datasets.direct_sites(store, dataset)))
        assert "geosite:" not in body.decode()
        for kind in ("geoip", "geosite"):
            status, _, body = network.local_https(c, f"/rules/{dataset}/{kind}.dat")
            assert status == 200
            datasets.validate_geo(body, kind)

        services.probe_vless(b, d)

        wrong = copy.deepcopy(d)
        wrong["uuid"] = model.new_device("wrong")["uuid"]
        expect_probe_failure(services, b, wrong, "Wrong UUID")
        foreign = copy.deepcopy(b)
        foreign["secrets"]["public_key"] = system.keys()["public_key"]
        expect_probe_failure(services, foreign, d, "Wrong Reality public key")
        entry = expect_probe_failure(services, big, d, "Oversized Reality target")
        assert "proxy/vless/outbound" in entry, entry
        print("PASS: real Xray validation, non-root launch, nginx TLS, INCY content, geo endpoints, "
              "Reality target qualification, VLESS positive/negative with redacted diagnostics")
    except BaseException:
        for log in sorted(FIXTURES.glob("*.out")) + [MANAGER_LOG]:
            if log.exists():
                print(f"----- {log.name} (tail) -----", file=sys.stderr)
                print(system.redact(log.read_bytes()[-6000:].decode("utf-8", "replace")), file=sys.stderr)
        raise
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
