#!/usr/bin/env python3
"""Prepare a pinned, spam-only cw-l/email-corpus split for offline Bayes checks."""

import argparse
import hashlib
import io
import os
import shutil
import stat
import sys
import tarfile


COMMIT = "75b488148d5560109d6fb0c6646d417d7271f66a"
SOURCE_URL = "https://codeload.github.com/cw-l/email-corpus/tar.gz/" + COMMIT
SOURCE_SHA256 = "98b7cdd390037d22b91aa6842f1133007bb105da3638493d74da274c7751d1a8"
EXPECTED_CONTRIBUTORS = {
    "b037056b02c300ba": 229,
    "cd73657af8d9165a": 1200,
}
EXPECTED_MESSAGES = sum(EXPECTED_CONTRIBUTORS.values())
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_TOTAL_MESSAGE_BYTES = 64 * 1024 * 1024
MAX_MESSAGE_BYTES = 5 * 1024 * 1024


def safe_member(name):
    normalized = name.replace("\\", "/")
    return (not normalized.startswith("/")
            and not any(part in ("", ".", "..") for part in normalized.split("/")))


def read_archive(path):
    if path:
        with open(path, "rb") as source:
            payload = source.read(MAX_ARCHIVE_BYTES + 1)
    else:
        from urllib.request import Request, urlopen
        request = Request(SOURCE_URL, headers={"User-Agent": "SpamFox-Bayes-Corpus/1.0"})
        with urlopen(request, timeout=30) as response:
            payload = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise ValueError("Pinned cw-l archive exceeds the 20 MiB limit.")
    if hashlib.sha256(payload).hexdigest() != SOURCE_SHA256:
        raise ValueError("Pinned cw-l archive checksum mismatch.")
    return payload


def prepare(payload, output):
    if os.path.lexists(output):
        raise ValueError("Output path already exists; choose a new, empty path.")
    output = os.path.abspath(output)
    os.makedirs(output, mode=0o700)
    counts = {"train": 0, "test": 0}
    total_bytes = 0
    prefix = "email-corpus-" + COMMIT + "/submissions/"
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            grouped = {contributor: [] for contributor in EXPECTED_CONTRIBUTORS}
            for member in archive.getmembers():
                if not safe_member(member.name):
                    raise ValueError("Unsafe path in the pinned cw-l archive.")
                normalized = member.name.replace("\\", "/")
                if not normalized.startswith(prefix) or not normalized.lower().endswith(".eml"):
                    continue
                parts = normalized.split("/")
                if (len(parts) != 6 or parts[2] not in grouped
                        or parts[3] != "1.0.0" or parts[4] != "emails"):
                    continue
                if not member.isfile() or "/" in normalized.rsplit("/", 1)[-1]:
                    raise ValueError("Unexpected file type or path in the cw-l corpus.")
                if not normalized.rsplit("/", 1)[-1].lower().endswith(".eml"):
                    raise ValueError("Unexpected sample name in the cw-l corpus.")
                grouped[parts[2]].append(member)

            for contributor, expected in EXPECTED_CONTRIBUTORS.items():
                if len(grouped[contributor]) != expected:
                    raise ValueError("Pinned cw-l sample count mismatch for contributor {0}: expected {1}."
                                     .format(contributor, expected))
            if sum(len(items) for items in grouped.values()) != EXPECTED_MESSAGES:
                raise ValueError("Pinned cw-l total sample count mismatch: expected {0} SPAM EMLs."
                                 .format(EXPECTED_MESSAGES))

            for contributor, members in grouped.items():
                members.sort(key=lambda member: member.name.lower())
                for index, member in enumerate(members):
                    if member.size <= 0 or member.size > MAX_MESSAGE_BYTES:
                        raise ValueError("A cw-l message is empty or exceeds the 5 MiB limit.")
                    total_bytes += member.size
                    if total_bytes > MAX_TOTAL_MESSAGE_BYTES:
                        raise ValueError("Extracted cw-l corpus exceeds the 64 MiB limit.")
                    split = "test" if index % 5 == 0 else "train"
                    destination_dir = os.path.join(output, split, "spam")
                    os.makedirs(destination_dir, mode=0o700, exist_ok=True)
                    name = "cwl-{0}-{1}".format(contributor, normalized_basename(member.name))
                    destination = os.path.join(destination_dir, name)
                    source = archive.extractfile(member)
                    if source is None:
                        raise ValueError("Could not read a sample from the cw-l corpus.")
                    with source, open(destination, "xb") as target:
                        shutil.copyfileobj(source, target, length=64 * 1024)
                    os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
                    counts[split] += 1

        manifest = [
            "Source: https://github.com/cw-l/email-corpus",
            "Pinned commit: " + COMMIT,
            "Archive SHA-256: " + SOURCE_SHA256,
            "Source paths: submissions/{0}/1.0.0/emails/ and submissions/{1}/1.0.0/emails/"
            .format(*sorted(EXPECTED_CONTRIBUTORS)),
            "Labels: 1429 SPAM samples from two contributors; every fifth per contributor held out.",
            "This source has no HAM class; combine only with trusted, separate HAM data.",
            "Samples are not included in the product bundle or model automatically.",
            "Repository license: MIT; source samples remain under their source terms.",
            "",
        ]
        manifest_path = os.path.join(output, "SOURCE.txt")
        with open(manifest_path, "x", encoding="utf-8") as target:
            target.write("\n".join(manifest))
        os.chmod(manifest_path, stat.S_IRUSR | stat.S_IWUSR)
        return counts, total_bytes
    except Exception:
        shutil.rmtree(output)
        raise


def normalized_basename(name):
    return name.replace("\\", "/").rsplit("/", 1)[-1]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="New path for train/spam and test/spam")
    parser.add_argument("--archive", help="Use a local copy of the pinned GitHub archive")
    args = parser.parse_args(argv)
    try:
        counts, total_bytes = prepare(read_archive(args.archive), args.output)
    except (OSError, ValueError, tarfile.TarError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    print("Prepared pinned cw-l SPAM corpus: " + os.path.abspath(args.output))
    print("TRAIN SPAM={0}".format(counts["train"]))
    print("TEST SPAM={0}".format(counts["test"]))
    print("BYTES={0}".format(total_bytes))
    print("No HAM samples exist in this source; model remains untouched.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
