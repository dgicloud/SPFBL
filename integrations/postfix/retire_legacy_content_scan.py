#!/usr/bin/env python3
"""Safely retire the old Postfix full-message upload transport for Rspamd."""

from __future__ import print_function

import argparse
import os
import shutil
import socket
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


MAIN = "/etc/postfix/main.cf"
MASTER = "/etc/postfix/master.cf"
MAIN_BEGIN = b"# BEGIN SFOX-CONTENT-SCAN SETTINGS"
MAIN_END = b"# END SFOX-CONTENT-SCAN SETTINGS"
MASTER_BEGIN = b"# BEGIN SFOX-CONTENT-SCAN TRANSPORT"
MASTER_END = b"# END SFOX-CONTENT-SCAN TRANSPORT"
RETIRED_PATHS = (
    "etc/sfox-content-scan",
    "etc/had-content-scan",
    "var/lib/sfox-content-scan",
    "var/lib/had-content-scan",
    "usr/local/libexec/sfox-content-scan",
    "usr/local/libexec/had-content-scan",
    "opt/spamfox-postfix",
    "root/rollback-spamfox-postfix.py",
)


class RetireError(RuntimeError):
    pass


def strip_marked_block(data, begin, end, signature):
    lines = data.splitlines(keepends=True)
    starts = [i for i, line in enumerate(lines) if line.strip() == begin]
    ends = [i for i, line in enumerate(lines) if line.strip() == end]
    if not starts and not ends:
        return data, False
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise RetireError("ambiguous marker block " + begin.decode("ascii"))
    block = b"".join(lines[starts[0]:ends[0] + 1])
    if signature not in block:
        raise RetireError("marker block differs from retired content scan; preserved")
    return b"".join(lines[:starts[0]] + lines[ends[0] + 1:]), True


def transform(main, master):
    main, main_changed = strip_marked_block(
        main, MAIN_BEGIN, MAIN_END, b"sfox-content-scan_destination_recipient_limit")
    master, master_changed = strip_marked_block(
        master, MASTER_BEGIN, MASTER_END,
        b"/usr/local/libexec/sfox-content-scan/postfix_content_filter.py")
    if main_changed != master_changed:
        raise RetireError("partial content-scan config; preserved for manual review")
    return main, master, main_changed


def run(args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    if check and result.returncode:
        raise RetireError("{} failed: {}".format(args[0], (result.stdout + result.stderr)[-1200:]))
    return result


def _postconf(name):
    return run(["postconf", "-h", name], check=False).stdout.strip()


def _queue_is_empty():
    return "Mail queue is empty" in run(["postqueue", "-p"]).stdout


def _existing_paths():
    found = []
    for relative in RETIRED_PATHS:
        path = Path("/" + relative)
        if path.exists() or path.is_symlink():
            found.append(path)
    return found


def _archive(main, master, retired, stamp):
    backup_dir = Path("/var/backups/spamfox")
    backup_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(str(backup_dir), 0o700)
    archive = backup_dir / ("retired-afterqueue-content-scan-" + stamp + ".tar.gz")
    with tarfile.open(str(archive), "w:gz") as stream:
        for path, name in ((Path(MAIN), "etc/postfix/main.cf"),
                           (Path(MASTER), "etc/postfix/master.cf")):
            stream.add(str(path), arcname=name)
        for path in retired:
            stream.add(str(path), arcname=str(path).lstrip("/"), recursive=True)
    os.chmod(str(archive), 0o600)
    return archive


def _write_atomic(path, data, metadata):
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".spamfox.",
                                     dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        os.chmod(temporary, metadata[0])
        os.chown(temporary, metadata[1], metadata[2])
        os.replace(temporary, str(path))
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def retire(check=False):
    if os.geteuid() != 0:
        raise RetireError("run as root")
    if not os.path.isfile(MAIN) or not os.path.isfile(MASTER):
        raise RetireError("Postfix config files are missing")

    with open(MAIN, "rb") as stream:
        old_main = stream.read()
    with open(MASTER, "rb") as stream:
        old_master = stream.read()
    new_main, new_master, changed = transform(old_main, old_master)
    retired = _existing_paths()
    if not changed and not retired:
        return "No retired after-queue content scanner found."
    if _postconf("content_filter"):
        raise RetireError("content_filter is active; disable it and drain the queue before cleanup")
    if not _queue_is_empty():
        raise RetireError("Postfix queue is not empty; cleanup refused to avoid stranded mail")
    if check:
        return "Retired content scanner found; updater can remove it safely."

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    archive = _archive(MAIN, MASTER, retired, stamp)
    if changed:
        main_stat = os.stat(MAIN)
        master_stat = os.stat(MASTER)
        main_meta = (main_stat.st_mode & 0o777, main_stat.st_uid, main_stat.st_gid)
        master_meta = (master_stat.st_mode & 0o777, master_stat.st_uid, master_stat.st_gid)
        _write_atomic(Path(MAIN), new_main, main_meta)
        _write_atomic(Path(MASTER), new_master, master_meta)
        reload_attempted = False
        try:
            run(["postfix", "check"])
            reload_attempted = True
            run(["postfix", "reload"])
            if _postconf("content_filter"):
                raise RetireError("content_filter became active")
            if run(["systemctl", "is-active", "postfix"], check=False).stdout.strip() != "active":
                raise RetireError("Postfix is not active after reload")
        except Exception:
            _write_atomic(Path(MAIN), old_main, main_meta)
            _write_atomic(Path(MASTER), old_master, master_meta)
            run(["postfix", "check"], check=False)
            if reload_attempted:
                run(["postfix", "reload"], check=False)
            raise

    for path in retired:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(str(path))
        else:
            path.unlink()
    run(["postfix", "check"])
    return "Removed retired after-queue content scanner; Rspamd Milter was left unchanged. Backup: {}".format(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="inspect without changing files")
    args = parser.parse_args()
    try:
        print(retire(check=args.check))
        return 0
    except (OSError, RetireError) as exc:
        print("SpamFox Postfix cleanup: " + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
