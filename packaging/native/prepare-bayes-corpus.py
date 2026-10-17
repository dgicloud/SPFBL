#!/usr/bin/env python3
"""Fetch and split the pinned, labelled Rspamd test corpus for offline Bayes checks."""

import argparse
import hashlib
import io
import os
import shutil
import stat
import sys
import urllib.request
import zipfile


SOURCE_URL = (
    "https://github.com/rspamd/rspamd-test-corpus/releases/download/v1.0/"
    "rspamd-test-corpus-20251017.zip"
)
SOURCE_SHA256 = "8caf537986f585a2d100d85ea40e1106921de2708aa87d7f14b899e0860d76fa"
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_MESSAGE_BYTES = 64 * 1024 * 1024
MAX_MESSAGE_BYTES = 5 * 1024 * 1024
LABELS = ("spam", "ham")


def safe_member(name):
    normalized = name.replace("\\", "/")
    return (not normalized.startswith("/")
            and not any(part in ("", ".", "..") for part in normalized.split("/")))


def download_archive():
    request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "SpamFox-Bayes-Corpus/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ValueError("Pinned corpus archive exceeds the 10 MiB limit.")
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA256:
        raise ValueError("Pinned corpus checksum mismatch.")
    return payload


def copy_dataset(payload, target):
    if os.path.lexists(target):
        raise ValueError("Output path already exists; choose a new, empty path.")
    target = os.path.abspath(target)
    os.makedirs(target, mode=0o700)
    counts = {label: {"train": 0, "test": 0} for label in LABELS}
    total_bytes = 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload), "r") as archive:
            grouped = {label: [] for label in LABELS}
            for info in archive.infolist():
                if info.is_dir():
                    continue
                if not safe_member(info.filename):
                    raise ValueError("Unsafe path in the pinned corpus archive.")
                parts = info.filename.replace("\\", "/").split("/")
                if len(parts) < 3 or parts[-3] != "corpus" or parts[-2] not in LABELS:
                    continue
                if not parts[-1].lower().endswith(".eml"):
                    continue
                label = parts[-2]
                if info.file_size <= 0 or info.file_size > MAX_MESSAGE_BYTES:
                    raise ValueError("Corpus message is empty or exceeds the 5 MiB limit.")
                total_bytes += info.file_size
                if total_bytes > MAX_TOTAL_MESSAGE_BYTES:
                    raise ValueError("Extracted corpus exceeds the 64 MiB limit.")
                grouped[label].append(info)

            if len(grouped["spam"]) != 300 or len(grouped["ham"]) != 700:
                raise ValueError("Pinned v1.0 corpus label counts do not match 300 SPAM / 700 HAM.")

            for label in LABELS:
                entries = sorted(grouped[label], key=lambda item: item.filename.lower())
                for index, info in enumerate(entries):
                    split = "test" if index % 5 == 0 else "train"
                    destination_dir = os.path.join(target, split, label)
                    os.makedirs(destination_dir, mode=0o700, exist_ok=True)
                    name = "rsp-" + os.path.basename(info.filename)
                    destination = os.path.join(destination_dir, name)
                    with archive.open(info, "r") as source, open(destination, "xb") as output:
                        shutil.copyfileobj(source, output, length=64 * 1024)
                    os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
                    counts[label][split] += 1

        if counts["spam"]["train"] < 25 or counts["ham"]["train"] < 25:
            raise ValueError("Prepared training set does not satisfy both class minimums.")
        manifest = [
            "Source: " + SOURCE_URL,
            "SHA-256: " + SOURCE_SHA256,
            "Labels: 300 SPAM / 700 HAM; sorted filenames, every fifth message held out.",
            "This directory contains public labelled EML examples, not an Rspamd model database.",
            "No messages from private mailboxes are included.",
            "",
        ]
        manifest_path = os.path.join(target, "SOURCE.txt")
        with open(manifest_path, "x", encoding="utf-8") as output:
            output.write("\n".join(manifest))
        os.chmod(manifest_path, stat.S_IRUSR | stat.S_IWUSR)
        return counts, total_bytes
    except Exception:
        shutil.rmtree(target)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New path for train/ and test/ folders")
    parser.add_argument("--archive", help="Use a locally downloaded archive instead of HTTPS")
    args = parser.parse_args(argv)
    try:
        if args.archive:
            with open(args.archive, "rb") as source:
                payload = source.read(MAX_ARCHIVE_BYTES + 1)
            if len(payload) > MAX_ARCHIVE_BYTES:
                raise ValueError("Corpus archive exceeds the 10 MiB limit.")
            if hashlib.sha256(payload).hexdigest() != SOURCE_SHA256:
                raise ValueError("Pinned corpus checksum mismatch.")
        else:
            payload = download_archive()
        counts, total_bytes = copy_dataset(payload, args.output)
    except (OSError, ValueError, zipfile.BadZipFile) as ex:
        print("ERROR: " + str(ex), file=sys.stderr)
        return 1
    print("Prepared offline corpus: {0}".format(os.path.abspath(args.output)))
    print("TRAIN SPAM={0} HAM={1}".format(counts["spam"]["train"], counts["ham"]["train"]))
    print("TEST SPAM={0} HAM={1}".format(counts["spam"]["test"], counts["ham"]["test"]))
    print("BYTES={0}".format(total_bytes))
    print("Model remains untouched; BAYES ENABLE is not run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
