#!/usr/bin/env python3
"""Keep Exim content classification ahead of result-based accept shortcuts."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ACL_FILES = (
    ROOT / "client" / "spfbl_begin_check_message_pre",
    ROOT / "client" / "directadmin.acl_check_message.pre.conf",
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check_acl(path):
    text = path.read_text(encoding="utf-8")
    scan = text.find("spam = $message_exim_id:true / tmo=10s")
    require(scan >= 0, "%s has no Exim SPAMD invocation" % path.name)
    before_scan = text[:scan]
    after_scan = text[scan:]
    require("accept\n    condition = ${if def:acl_c_spfblticketset {false}{true}}" in before_scan,
            "%s must retain the no-ticket fail-open path" % path.name)
    require("authenticated = *" in before_scan,
            "%s must retain the authenticated-mail bypass" % path.name)
    require("condition = ${if eq {$acl_c_spfbl_result}{7}{true}{false}}" not in before_scan[-240:],
            "%s still gates SPAMD on the HOLD status" % path.name)
    spam_deny = after_scan.find("condition = ${if eq {$spam_score}{2.0}{true}{false}}")
    require(spam_deny >= 0, "%s has no rejection for confident Bayes SPAM" % path.name)
    for status in ("17", "6"):
        accepted = after_scan.find(
            "condition = ${if eq {$acl_c_spfbl_result}{%s}{true}{false}}" % status
        )
        require(accepted > spam_deny,
                "%s accepts SPFBL result %s before the Bayes reject check" % (path.name, status))
    require("condition = ${if eq {$spam_score}{4.0}{true}{false}}" in text,
            "%s lost the existing malware handling" % path.name)


def main():
    for path in ACL_FILES:
        check_acl(path)
    print("PASS: cPanel and DirectAdmin run content Bayes before status-based accepts.")


if __name__ == "__main__":
    main()
