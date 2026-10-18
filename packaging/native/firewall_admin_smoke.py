#!/usr/bin/env python3
"""Real nftables CRUD test; execute only through test-firewall-admin.sh."""

import os
from pathlib import Path
import tempfile
import firewall
from firewall_admin import Manager, FirewallAdminError


def main():
    if (os.environ.get("SPAMFOX_ISOLATED_FIREWALL_TEST") != "1"
            or not os.environ.get("SPAMFOX_PARENT_NETNS")
            or os.readlink("/proc/self/ns/net") == os.environ["SPAMFOX_PARENT_NETNS"]):
        raise SystemExit("Refusing to test the host firewall: use test-firewall-admin.sh")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        path = root / "allowed-cpanels.txt"
        path.write_text("192.0.2.10/32 # Initial MTA\n", encoding="utf-8")
        manager = Manager(path, root / "backups")
        firewall.apply(str(path))

        def change(action, **fields):
            request = {"action": action, "actor": "admin@example.test",
                       "revision": manager.snapshot()["revision"]}
            request.update(fields)
            assert manager.request(request)["ok"]
            assert manager.snapshot()["synchronized"]

        assert manager.snapshot()["synchronized"]
        old_revision = manager.snapshot()["revision"]
        change("add", cidr="2001:db8::1", description="IPv6 MTA")
        assert len(manager.snapshot()["entries"]) == 2
        change("update", original="192.0.2.10", cidr="192.0.2.0/28", description="MTA network")
        assert "192.0.2.0/28" in firewall._existing_table()
        try:
            manager.request({"action": "delete", "original": "192.0.2.0/28",
                             "actor": "admin@example.test", "revision": old_revision})
            raise AssertionError("stale revision accepted")
        except FirewallAdminError as error:
            assert error.code == "conflict"
        change("delete", original="2001:db8::1")
        change("delete", original="192.0.2.0/28")
        assert manager.snapshot()["entries"] == []
        change("apply")
        rules = firewall._existing_table()
        assert "saddr" not in rules
        for port in (9877, 9875, 8080):
            assert "tcp dport %d drop" % port in rules
        assert len(list((root / "backups").glob("allowlist-*.txt"))) == 4
    print("PASS: real nftables CRUD, IPv4/IPv6, revision checks and deny-all empty list in an isolated network namespace.")


if __name__ == "__main__":
    main()
