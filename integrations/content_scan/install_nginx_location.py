#!/usr/bin/env python3
"""Add the private SFOX scan location to the existing matrix HTTPS vhost."""

from __future__ import print_function

import argparse
import glob
import os
import re
import shutil
import stat
import tempfile

MARKER = "# HAD-SFOX-SCAN-LOCATION"
INCLUDE = "include /etc/nginx/snippets/had-sfox-scan-location.conf;"


def _server_blocks(source):
    depth = 0
    directive_start = 0
    server_open = None
    quote = None
    escaped = False
    comment = False
    for index, char in enumerate(source):
        if comment:
            if char == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char == "#":
            comment = True
        elif char in ("'", '"'):
            quote = char
        elif char == "{":
            header = source[directive_start:index]
            header = re.sub(r"(?m)#.*$", "", header).strip()
            depth += 1
            if header == "server":
                server_open = (index, depth)
            directive_start = index + 1
        elif char == "}":
            if server_open and depth == server_open[1]:
                start, _ = server_open
                yield start, index, source[start:index + 1]
                server_open = None
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced closing brace in Nginx config")
            directive_start = index + 1
        elif char == ";":
            directive_start = index + 1
    if depth != 0 or quote:
        raise ValueError("incomplete Nginx server block")


def matching_server(path, hostname):
    with open(path, "r") as stream:
        source = stream.read()
    matches = []
    for start, close, block in _server_blocks(source):
        names = re.search(r"(?m)^\s*server_name\s+([^;]+);", block)
        listens = re.findall(r"(?m)^\s*listen\s+([^;]+);", block)
        if not names or hostname not in names.group(1).split():
            continue
        if any(re.search(r"\b443\b", item) and re.search(r"\bssl\b", item) for item in listens):
            matches.append((source, close, block))
    if len(matches) != 1:
        return None
    return matches[0]


def inject_include(path, hostname="matrix.hadcloud.srv.br"):
    actual_path = os.path.realpath(path)
    matched = matching_server(actual_path, hostname)
    if not matched:
        raise ValueError("expected exactly one HTTPS server block for " + hostname)
    source, close, block = matched
    marker_count = block.count(MARKER)
    include_count = block.count(INCLUDE)
    if marker_count:
        if marker_count == 1 and include_count == 1:
            return False
        raise ValueError("existing HAD marker/include pair is incomplete or duplicated")
    if include_count:
        raise ValueError("scan include exists without its HAD marker; refusing ambiguous config")
    backup = actual_path + ".had-content-scan.bak"
    if os.path.exists(backup):
        raise ValueError("backup already exists; refusing to overwrite " + backup)
    shutil.copy2(actual_path, backup)
    updated = source[:close] + "\n    " + MARKER + "\n    " + INCLUDE + "\n" + source[close:]
    mode = stat.S_IMODE(os.stat(actual_path).st_mode)
    fd, temporary = tempfile.mkstemp(prefix=".had-sfox-vhost-", dir=os.path.dirname(actual_path))
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(updated)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, actual_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def restore_vhost(path):
    actual_path = os.path.realpath(path)
    backup = actual_path + ".had-content-scan.bak"
    if not os.path.isfile(backup):
        raise ValueError("Nginx rollback snapshot not found: " + backup)
    shutil.copy2(backup, actual_path)
    os.unlink(backup)


def find_enabled_vhost(hostname):
    matches = []
    for path in glob.glob("/etc/nginx/sites-enabled/*"):
        try:
            if matching_server(path, hostname):
                matches.append(path)
        except (OSError, ValueError):
            continue
    if len(matches) != 1:
        raise ValueError("expected exactly one enabled Nginx vhost for " + hostname)
    return matches[0]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", default="matrix.hadcloud.srv.br")
    parser.add_argument("--vhost")
    parser.add_argument("--restore", action="store_true")
    args = parser.parse_args(argv)
    try:
        path = args.vhost or find_enabled_vhost(args.hostname)
        if args.restore:
            restore_vhost(path)
            print("Restored the Nginx vhost from its HAD snapshot.")
            return 0
        changed = inject_include(path, args.hostname)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("Nginx vhost already includes the SFOX scan location." if not changed
          else "Added the SFOX scan location to " + path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
