"""Full installation through the real installer and systemd units.

Runs inside a disposable Ubuntu container booted with systemd as PID 1.
Only ACME is replaced: a diverted certbot issues a certificate trusted in this
container. The Reality target and the probe endpoint are local nginx fixtures.
"""

import os
from pathlib import Path
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import integration as fx
from ruavc import system
from ruavc.storage import write

# ipaddress treats it as global, as the installer requires for a target; it is
# bound only to lo inside this container.
TARGET_ADDRESS = "11.255.255.1"
SERVER_ADDRESS = "192.0.2.10"
DOMAIN = "vpn.example.com"
CERTBOT = """#!/bin/sh
# ACME test double: a certificate trusted only inside this container.
set -e
[ "$1" = certonly ] || exit 0
name=""
while [ $# -gt 0 ]; do
    if [ "$1" = --cert-name ]; then name="$2"; fi
    shift
done
dir="/etc/letsencrypt/live/$name"
mkdir -p "$dir"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$name" -addext "subjectAltName=DNS:$name" \\
    -keyout "$dir/privkey.pem" -out "$dir/fullchain.pem" 2>/dev/null
cp "$dir/fullchain.pem" "/usr/local/share/ca-certificates/$name.crt"
update-ca-certificates >/dev/null
"""


def sh(*args, expect=0):
    result = subprocess.run([str(x) for x in args], capture_output=True, text=True, timeout=900)
    print("$ " + " ".join(str(x) for x in args), flush=True)
    print(system.redact(result.stdout + result.stderr), flush=True)
    if expect is not None and result.returncode != expect:
        raise AssertionError(f"{args[0]} exited with {result.returncode}, expected {expect}")
    return result


def ubuntu_like_host():
    # Cloud images ship /var/log as root:syslog 0775; the manager log must still work.
    if subprocess.run(["getent", "group", "syslog"], capture_output=True).returncode:
        sh("groupadd", "--system", "syslog")
    os.chown("/var/log", 0, int(sh("getent", "group", "syslog").stdout.split(":")[2]))
    os.chmod("/var/log", 0o775)
    sh("dpkg-divert", "--local", "--rename", "--divert", "/usr/bin/certbot.distrib", "--add", "/usr/bin/certbot")
    write(Path("/usr/bin/certbot"), CERTBOT, 0o755)
    fx.local_address(TARGET_ADDRESS)
    with open("/etc/hosts", "a", encoding="utf-8") as hosts:
        hosts.write(f"{SERVER_ADDRESS} {DOMAIN}\n")


def main():
    if os.geteuid() != 0 or not Path("/run/systemd/system").is_dir() or Path("/etc/ruavc").exists():
        raise SystemExit("Requires an empty disposable container booted with systemd")
    ubuntu_like_host()
    conf = fx.fixtures(reality_listen=f"{TARGET_ADDRESS}:443")
    with open("/etc/hosts", "a", encoding="utf-8") as hosts:
        hosts.write(f"{TARGET_ADDRESS} {fx.REALITY_SNI}\n")
    nginx = fx.spawn("fixture-nginx", ["/usr/sbin/nginx", "-c", conf, "-g", "daemon off;"])
    try:
        fx.wait_ports([nginx], (19446,))
        sh("python3", "-I", "dist/ruavc.pyz", "setup", "--address", SERVER_ADDRESS, "--domain", DOMAIN,
           "--target", fx.REALITY_SNI + ":443", "--sni", fx.REALITY_SNI, "--port", "8443", "--country", "DE")
        ruavc = "/usr/local/sbin/ruavc"
        sh(ruavc, "status")
        sh(ruavc, "config", "set", "probe_url", f"https://{fx.PROBE_HOST}/generate_204")
        # Adding a device restarts both units and runs the VLESS self-test through them.
        sh(ruavc, "add", "phone")
        sh(ruavc, "status")
        # A restart recreates RuntimeDirectory; nginx must rebuild its temp paths.
        sh("systemctl", "restart", "ruavc-xray.service", "ruavc-web.service")
        sh(ruavc, "repair")
        sh(ruavc, "rollback")
        sh(ruavc, "status")
        failed = sh(ruavc, "add", "phone", expect=1)
        assert "Устройство уже существует" in failed.stderr, failed.stderr
        log = Path("/var/log/ruavc/manager.log")
        assert log.is_file() and stat.S_IMODE(log.stat().st_mode) == 0o600, "manager.log is not written"
        assert "Устройство уже существует" in log.read_text(encoding="utf-8")
        sh(ruavc, "logs", "--lines", "20")
        print("PASS: installer, systemd units, restart, repair, rollback, VLESS self-test and manager log")
    except BaseException:
        subprocess.run(["journalctl", "--no-pager", "-n", "200", "-u", "ruavc-xray", "-u", "ruavc-web", "-u", "ruavc-recover"])
        for path in [Path("/var/log/ruavc/manager.log"), *sorted(fx.FIXTURES.glob("*.out"))]:
            if path.exists():
                print(f"----- {path} (tail) -----", file=sys.stderr)
                print(system.redact(path.read_bytes()[-6000:].decode("utf-8", "replace")), file=sys.stderr)
        raise
    finally:
        nginx.terminate()
        nginx.wait(timeout=10)


if __name__ == "__main__":
    main()
