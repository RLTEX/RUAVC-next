#!/usr/bin/env python3
"""Deterministic zipapp and a version-pinned HTTPS bootstrap."""

import argparse
import hashlib
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def build(output, repository):
    version = (ROOT / "VERSION").read_text().strip()
    if not re.fullmatch(r"\d+\.\d+\.\d+", version) or not re.fullmatch(r"[A-Za-z0-9_-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("Invalid version/repository")
    output.mkdir(parents=True, exist_ok=True)
    package = output / "ruavc.pyz"
    with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for source in sorted((ROOT / "src").rglob("*.py")):
            relative = source.relative_to(ROOT / "src").as_posix()
            info = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, source.read_bytes().replace(b"\r\n", b"\n"))
    checksum = hashlib.sha256(package.read_bytes()).hexdigest()
    setup = (ROOT / "packaging/setup.sh.in").read_text(encoding="utf-8")
    setup = setup.replace("@VERSION@", version).replace("@REPOSITORY@", repository).replace("@SHA256@", checksum)
    (output / "ruavc-setup.sh").write_text(setup, encoding="utf-8", newline="\n")
    lines = [f'{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n' for name in ("ruavc.pyz", "ruavc-setup.sh")]
    (output / "SHA256SUMS").write_text("".join(lines), encoding="ascii", newline="\n")
    print(f"RUAVC {version}: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=ROOT / "dist")
    parser.add_argument("--repository", default="RLTEX/RUAVC-next")
    args = parser.parse_args()
    build(args.out, args.repository)
