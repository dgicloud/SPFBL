#!/usr/bin/env python3
"""Exercise native Bayes ADMIN commands against an isolated running core."""

import socket
import os
import sys
from glob import glob


def command(host, port, value, timeout=10):
    with socket.create_connection((host, port), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall((value + "\n").encode("ascii"))
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("utf-8", "replace")


def require(actual, expected, operation):
    if actual != expected:
        raise RuntimeError("%s returned %r, expected %r" % (operation, actual, expected))


def parse_counts(response):
    counts = {}
    for line in response.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                counts[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return counts


def train_and_validate(host, port):
    spam = command(host, port, "BAYES LEARN SPAM", timeout=120)
    ham = command(host, port, "BAYES LEARN HAM", timeout=120)
    spam_counts = parse_counts(spam)
    ham_counts = parse_counts(ham)
    spam_expected = len(glob("/work/learn/spam/*.eml"))
    ham_expected = len(glob("/work/learn/ham/*.eml"))
    statuses = ("ADDED", "DUPLICATE", "LABEL_CONFLICT", "TOO_SMALL", "INVALID", "SKIPPED_LIMIT")
    for label, counts, expected, response in (
            ("SPAM", spam_counts, spam_expected, spam),
            ("HAM", ham_counts, ham_expected, ham)):
        if sum(counts.get(status, 0) for status in statuses) != expected:
            raise RuntimeError("%s corpus training totals differ from its files: %r" % (label, response))
        if counts.get("ADDED", 0) <= 0 or counts.get("INVALID", 0) or counts.get("LABEL_CONFLICT", 0):
            raise RuntimeError("%s corpus did not train cleanly: %r" % (label, response))
        if counts.get("SKIPPED_LIMIT", 0):
            raise RuntimeError("%s corpus exceeded the configured model limits: %r" % (label, response))
    stats = command(host, port, "BAYES STATS")
    model_counts = parse_counts(stats)
    if (model_counts.get("SPAM_DOCUMENTS") != spam_counts.get("ADDED")
            or model_counts.get("HAM_DOCUMENTS") != ham_counts.get("ADDED")):
        raise RuntimeError("core model counts do not match learned labels: %r" % stats)
    require(command(host, port, "BAYES ENABLE"), "ENABLED\n", "BAYES ENABLE after corpus training")
    model_mode = os.stat("/work/data/content-bayes.db").st_mode & 0o777
    if model_mode != 0o600:
        raise RuntimeError("Bayes model file permissions are not owner-only: %o" % model_mode)
    if glob("/work/data/**/*.eml", recursive=True):
        raise RuntimeError("raw EML files were persisted under the core data directory")

    test_root = "/work/learn/test"
    spam_detected = 0
    ham_false_positive = 0
    spam_total = 0
    ham_total = 0
    confident_ham_on_spam = 0
    confident_ham_on_ham = 0
    inconclusive = 0
    spamd_candidate = None
    for name in sorted(os.listdir(test_root)):
        if not name.lower().endswith(".eml"):
            continue
        expected_spam = name.startswith("spam-")
        result = command(host, port, "BAYES TEST " + name)
        if expected_spam:
            spam_total += 1
            if result.startswith("SPAM PROBABILITY "):
                spam_detected += 1
                if spamd_candidate is None:
                    spamd_candidate = name
            elif result.startswith("INCONCLUSIVE"):
                inconclusive += 1
            elif result.startswith("HAM PROBABILITY "):
                confident_ham_on_spam += 1
            else:
                raise RuntimeError("unexpected SPAM validation result for %s: %r" % (name, result))
        else:
            ham_total += 1
            if result.startswith("SPAM PROBABILITY "):
                ham_false_positive += 1
            elif result.startswith("INCONCLUSIVE"):
                inconclusive += 1
            elif result.startswith("HAM PROBABILITY "):
                confident_ham_on_ham += 1
            else:
                raise RuntimeError("unexpected HAM validation result for %s: %r" % (name, result))
    if spam_total == 0 or ham_total == 0:
        raise RuntimeError("held-out corpus must contain both labelled classes")
    if spamd_candidate is None:
        raise RuntimeError("held-out corpus had no SPAM message suitable for SPAMD protocol verification")
    print("CORE_HOLDOUT SPAM_DETECTED=%d/%d SPAM_AS_HAM=%d HAM_FALSE_POSITIVE=%d/%d HAM_AS_HAM=%d INCONCLUSIVE=%d" %
          (spam_detected, spam_total, confident_ham_on_spam,
           ham_false_positive, ham_total, confident_ham_on_ham, inconclusive))
    return spamd_candidate


def prepare_spamd_client(host, port):
    user_email = "bayes-audit@example.com"
    cidr = "198.18.250.2/32"
    user = command(host, port, "USER ADD " + user_email + " BayesSmoke")
    if "ADDED " not in user and "ALREADY EXISTS" not in user:
        raise RuntimeError("could not create isolated SPAMD test user: %r" % user)
    client = command(host, port, "CLIENT ADD " + cidr + " audit.example.com SPFBL " + user_email)
    if "ADDED " not in client and "ALREADY EXISTS" not in client:
        raise RuntimeError("could not create isolated SPAMD test client: %r" % client)
    # Legacy clients may intentionally FLAG reputation-only signals. A
    # separately opted-in, high-confidence Bayes result must still reject.
    action = command(host, port, "CLIENT SET " + cidr + " ACTION RED FLAG")
    if not action.startswith(("UPDATED ", "ALREADY THIS VALUE")):
        raise RuntimeError("could not configure isolated Bayes test with RED=FLAG: %r" % action)
    require(command(host, port, "BAYES CLIENT ADD " + cidr), "ADDED\n", "enroll isolated SPAMD test client")
    require(command(host, port, "BAYES DECISION ADD " + cidr), "ADDED\n",
            "explicitly opt isolated SPAMD test client into decisions")


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9875
    if "--cleanup" in sys.argv[3:]:
        cidr = "198.18.250.2/32"
        command(host, port, "BAYES CLIENT DROP " + cidr)
        command(host, port, "CLIENT DROP " + cidr)
        command(host, port, "USER DROP bayes-audit@example.com")
        require(command(host, port, "BAYES DISABLE"), "DISABLED\n", "BAYES DISABLE after SPAMD test")
        stats = command(host, port, "BAYES STATS")
        if ("ENABLED false\n" not in stats or "ALLOWED_CLIENTS 0\n" not in stats
                or "DECISION_CLIENTS 0\n" not in stats):
            raise RuntimeError("isolated SPAMD client cleanup failed: %r" % stats)
        print("PASS: temporary SPAMD client removed and Bayes disabled.")
        return
    stats = command(host, port, "BAYES STATS")
    if ("ENABLED false\n" not in stats or "ALLOWED_CLIENTS 0\n" not in stats
            or "DECISION_CLIENTS 0\n" not in stats):
        raise RuntimeError("fresh core did not start with Bayes disabled and no enrolled clients: %r" % stats)
    require(command(host, port, "BAYES CLIENT SHOW"), "EMPTY\n", "BAYES CLIENT SHOW")
    require(command(host, port, "BAYES DECISION SHOW"), "EMPTY\n", "BAYES DECISION SHOW")
    require(command(host, port, "BAYES CLIENT ADD invalid"), "INVALID PARAMETERS\n", "invalid CIDR")
    require(command(host, port, "BAYES CLIENT ADD 198.18.250.11/32"), "ADDED\n", "BAYES CLIENT ADD")
    require(command(host, port, "BAYES CLIENT SHOW"), "198.18.250.11/32\n", "BAYES CLIENT SHOW after ADD")
    require(command(host, port, "BAYES DECISION ADD 198.18.250.12/32"),
            "NOT ENROLLED\n", "require passive enrollment before decision enrollment")
    require(command(host, port, "BAYES DECISION ADD 198.18.250.11/32"), "ADDED\n",
            "BAYES DECISION ADD")
    require(command(host, port, "BAYES DECISION SHOW"), "198.18.250.11/32\n",
            "BAYES DECISION SHOW after ADD")
    require(command(host, port, "BAYES CLIENT DROP 198.18.250.11/32"), "DROPPED\n", "BAYES CLIENT DROP")
    require(command(host, port, "BAYES CLIENT SHOW"), "EMPTY\n", "BAYES CLIENT SHOW after DROP")
    require(command(host, port, "BAYES DECISION SHOW"), "EMPTY\n",
            "BAYES CLIENT DROP also clears decision enrollment")
    if "--train-corpus" in sys.argv[3:]:
        candidate = train_and_validate(host, port)
        prepare_spamd_client(host, port)
        print("SPAMD_CANDIDATE=" + candidate)
        print("PASS: Bayes ADMIN training and per-client scope prepared for SPAMD E2E.")
        return
    else:
        require(command(host, port, "BAYES ENABLE"), "INSUFFICIENT_TRAINING_DATA\n", "BAYES ENABLE without corpus")
    stats = command(host, port, "BAYES STATS")
    if "ENABLED false\n" not in stats:
        raise RuntimeError("Bayes was enabled without training data")
    print("PASS: Bayes ADMIN protocol, explicit CIDR scope, and disabled-by-default behavior.")


if __name__ == "__main__":
    main()
