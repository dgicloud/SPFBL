#!/usr/bin/env python3
"""Remove the retired full-message BSMTP pipe from cPanel's persistent Exim source."""

from __future__ import print_function

import argparse
import os
import shutil
import tempfile
import time


LOCAL_CONFIG = "/etc/exim.conf.local"


class CleanupError(RuntimeError):
    pass


def remove_legacy_pipe(data):
    lines = data.splitlines(keepends=True)
    assignment = [
        i for i, line in enumerate(lines)
        if line.strip() == b"system_filter_pipe_transport = sfox_content_pipe"
    ]
    starts = [i for i, line in enumerate(lines) if line.strip() == b"sfox_content_pipe:"]
    if not assignment and not starts:
        return data, False
    if len(assignment) != 1 or len(starts) != 1:
        raise CleanupError("SFOX content pipe is partial or duplicated; preserved")

    start = starts[0]
    end = None
    for i in range(start + 1, len(lines)):
        if lines[i].lstrip().startswith(b"@TRANSPORT"):
            end = i
            break
    if end is None:
        raise CleanupError("SFOX content pipe has no cPanel transport boundary; preserved")

    block = b"".join(lines[start:end])
    if not all(token in block for token in (
            b"SFOX_BSMTP=1", b"driver = pipe", b"use_bsmtp = true")):
        raise CleanupError("SFOX content pipe differs from the retired upload transport; preserved")
    if b"command =" in block:
        raise CleanupError("SFOX content pipe has an executable command; preserved")

    out = [line for i, line in enumerate(lines) if i != assignment[0]]
    start = next(i for i, line in enumerate(out) if line.strip() == b"sfox_content_pipe:")
    end = next(i for i in range(start + 1, len(out))
               if out[i].lstrip().startswith(b"@TRANSPORT"))
    return b"".join(out[:start] + out[end:]), True


def apply(path=LOCAL_CONFIG, check=False):
    if not os.path.isfile(path) or os.path.islink(path):
        raise CleanupError("regular Exim local config not found; preserved")
    with open(path, "rb") as stream:
        original = stream.read()
    candidate, changed = remove_legacy_pipe(original)
    if not changed:
        return "No retired after-queue content pipe found."
    if check:
        return "Retired after-queue content pipe found; updater will remove it."

    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    backup_dir = "/var/backups/spamfox/retired-exim-content-pipe"
    os.makedirs(backup_dir, mode=0o700, exist_ok=True)
    os.chmod(backup_dir, 0o700)
    backup = os.path.join(backup_dir, "exim.conf.local." + stamp + ".bak")
    shutil.copy2(path, backup)
    metadata = os.stat(path)
    fd, temporary = tempfile.mkstemp(prefix=".exim.conf.local.spamfox.", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(candidate)
        os.chmod(temporary, metadata.st_mode & 0o777)
        os.chown(temporary, metadata.st_uid, metadata.st_gid)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return "Removed retired after-queue content pipe; backup: " + backup


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="inspect without changing files")
    args = parser.parse_args(argv)
    try:
        print(apply(check=args.check))
        return 0
    except (OSError, CleanupError) as exc:
        print("SpamFox cPanel cleanup: " + str(exc))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
