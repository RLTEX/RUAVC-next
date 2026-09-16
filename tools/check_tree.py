"""Cheap release hygiene checks, with no runtime credentials in the source tree."""

from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
files = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
bad = []
for name in filter(None, files):
    path = root / name
    if not path.is_file():
        continue
    raw = path.read_bytes()
    if b"\r\n" in raw or path.suffix in {".pem", ".key", ".pyz"} or name.startswith("dist/"):
        bad.append(name)
    if re.search(rb"-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}", raw):
        bad.append(name)
if bad:
    raise SystemExit("Release hygiene failed: " + ", ".join(sorted(set(bad))))
print("Release tree checks passed")
