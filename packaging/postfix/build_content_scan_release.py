#!/usr/bin/env python3
"""Build the small, deterministic Postfix after-queue collector bundle."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.1.1-pilot"
FILES = (
    "integrations/postfix/README.md",
    "integrations/postfix/postfix_content_scan_manager.py",
    "integrations/postfix/postfix_content_filter.py",
    "integrations/postfix/install-content-scan.sh",
    "integrations/postfix/validate-content-scan.sh",
    "integrations/postfix/activate-content-scan.sh",
    "integrations/postfix/healthcheck-content-scan.sh",
    "integrations/postfix/uninstall-content-scan.sh",
    "integrations/content_scan/scan_client.py",
    "licence.txt",
)


def _add_bytes(archive, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.uid = info.gid = 0
    info.uname = info.gname = "root"
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def build(version=VERSION):
    if not version or any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for ch in version):
        raise ValueError("invalid release version")
    release_dir = ROOT / "packaging" / "postfix" / "releases"
    release_dir.mkdir(parents=True, exist_ok=True)
    name = "had-content-scan-postfix-{0}.tar.gz".format(version)
    target = release_dir / name
    package_dir = "had-content-scan-postfix-{0}".format(version)
    fd, temporary = tempfile.mkstemp(prefix=".had-content-scan-", dir=str(release_dir))
    os.close(fd)
    try:
        with open(temporary, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
                with tarfile.open(fileobj=zipped, mode="w", format=tarfile.PAX_FORMAT) as archive:
                    _add_bytes(archive, package_dir + "/VERSION", (version + "\n").encode("ascii"))
                    for relative in FILES:
                        source = ROOT / relative
                        if not source.is_file():
                            raise FileNotFoundError("release input missing: " + relative)
                        mode = 0o755 if source.suffix == ".sh" else 0o644
                        _add_bytes(archive, package_dir + "/" + relative,
                                  source.read_bytes(), mode)
        os.replace(temporary, target)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise

    digest = hashlib.sha256(target.read_bytes()).hexdigest()
    sidecar = release_dir / (name + ".sha256")
    sidecar.write_text("{0}  {1}\n".format(digest, name), encoding="ascii")
    return target, digest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=VERSION)
    args = parser.parse_args()
    target, digest = build(args.version)
    print("{0}\nSHA256 {1}".format(target, digest))


if __name__ == "__main__":
    main()
