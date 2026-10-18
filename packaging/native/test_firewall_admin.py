import importlib.util
from pathlib import Path
import tempfile
import io
import json
import os
import socket
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("spamfox_firewall_admin", Path(__file__).with_name("firewall_admin.py"))
admin = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(admin)


class FirewallAdminTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.path = root / "allowed-cpanels.txt"
        self.path.write_bytes(b"# Existing note\n192.0.2.10 # Original MTA\n")
        self.applied = []
        self.manager = admin.Manager(self.path, root / "backups",
                                     applier=lambda path: self.applied.append(Path(path).read_text(encoding="utf-8")),
                                     status=lambda entries: {"active": True, "synchronized": True})

    def change(self, action, **fields):
        request = {"action": action, "actor": "admin@example.com",
                   "revision": self.manager.snapshot()["revision"]}
        request.update(fields)
        return self.manager.request(request)

    def test_crud_normalizes_addresses_preserves_notes_and_backups(self):
        before = self.path.read_bytes()
        self.change("add", cidr="2001:db8::1", description="Secondary MTA")
        self.assertIn("2001:db8::1/128", self.path.read_text())
        self.change("update", original="192.0.2.10", cidr="192.0.2.0/28", description="MTA network")
        state = self.manager.snapshot()
        self.assertEqual("192.0.2.0/28", state["entries"][0]["cidr"])
        self.change("delete", original="2001:db8::1")
        self.assertEqual(1, len(self.manager.snapshot()["entries"]))
        self.assertTrue(self.path.read_text().startswith("# Existing note\n"))
        self.assertIn(before, [p.read_bytes() for p in self.manager.backups.glob("*.txt")])
        self.assertEqual(3, len(self.applied))

    def test_stale_revision_duplicate_unknown_action_and_injections_are_rejected(self):
        stale = self.manager.snapshot()["revision"]
        self.change("add", cidr="192.0.2.11")
        with self.assertRaisesRegex(admin.FirewallAdminError, "lista mudou"):
            self.manager.request({"action": "delete", "original": "192.0.2.10",
                                  "actor": "admin@example.com", "revision": stale})
        for fields in ({"action": "add", "cidr": "192.0.2.10/32"},
                       {"action": "add", "cidr": "0.0.0.0/0"},
                       {"action": "add", "cidr": "192.0.2.12; reboot"},
                       {"action": "add", "cidr": "192.0.2.12", "description": "note\n0.0.0.0/0"},
                       {"action": "command", "cidr": "192.0.2.12"}):
            with self.assertRaises(admin.FirewallAdminError):
                self.change(**fields)
        self.assertEqual(1, len(self.applied))

    def test_failed_atomic_nft_apply_preserves_original_file(self):
        before = self.path.read_bytes()
        self.manager.applier = mock.Mock(side_effect=RuntimeError("nft failed"))
        with self.assertRaisesRegex(admin.FirewallAdminError, "configuração anterior"):
            self.change("add", cidr="192.0.2.12")
        self.assertEqual(before, self.path.read_bytes())
        self.assertFalse(list(self.path.parent.glob(".firewall-*")))
        self.assertEqual(1, len(list(self.manager.backups.glob("*.txt"))))

    def test_failed_file_commit_reapplies_original_rules(self):
        before = self.path.read_bytes()
        with mock.patch.object(admin.os, "replace", side_effect=OSError("disk failure")):
            with self.assertRaisesRegex(admin.FirewallAdminError, "configuração anterior"):
                self.change("add", cidr="192.0.2.12")
        self.assertEqual(before, self.path.read_bytes())
        self.assertEqual(2, len(self.applied))
        self.assertEqual(before.decode(), self.applied[-1])

    def test_external_edit_during_apply_is_preserved_and_reapplied(self):
        external = "192.0.2.99/32 # Edited from terminal\n"

        def apply(path):
            self.applied.append(Path(path).read_text())
            if len(self.applied) == 1:
                self.path.write_text(external)

        self.manager.applier = apply
        with self.assertRaisesRegex(admin.FirewallAdminError, "lista mudou"):
            self.change("add", cidr="192.0.2.12")
        self.assertEqual(external, self.path.read_text())
        self.assertEqual(external, self.applied[-1])

    def test_delete_last_network_and_apply_empty_list_remain_fail_closed(self):
        self.change("delete", original="192.0.2.10")
        self.assertEqual([], self.manager.snapshot()["entries"])
        self.change("apply")
        import firewall
        rules = firewall.render_rules(firewall.load_networks(str(self.path), allow_empty=True))
        self.assertNotIn("saddr", rules)
        for port in (9877, 9875, 8080):
            self.assertIn("tcp dport %s drop" % port, rules)

    def test_status_detects_drift_and_absent_table(self):
        import firewall
        entries = [{"cidr": "192.0.2.10/32", "description": "MTA"}]
        table = firewall.render_rules([firewall.ipaddress.ip_network("192.0.2.10/32")])
        with mock.patch.object(firewall, "_existing_table", return_value=table):
            self.assertEqual({"active": True, "synchronized": True}, admin.kernel_status(entries))
            self.assertFalse(admin.kernel_status([])["synchronized"])
        with mock.patch.object(firewall, "_existing_table", return_value=None):
            self.assertFalse(admin.kernel_status(entries)["active"])

    @unittest.skipUnless(hasattr(socket, "SO_PEERCRED") and admin.fcntl is not None, "Linux Unix socket credentials required")
    def test_local_rpc_round_trip_and_denied_peer_never_mutates(self):
        # Keep the socket under /tmp, including on WSL where the repository may use drvfs.
        with tempfile.TemporaryDirectory() as root:
            path = str(Path(root) / "control.sock")
            server = admin.create_server(self.manager, os.geteuid(), path, str(Path(root) / "manager.lock"))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                def rpc(request):
                    raw = (json.dumps(request) + "\n").encode()
                    with mock.patch.object(admin, "SOCKET", path), mock.patch.object(admin.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(raw))):
                        return admin.client()

                self.assertTrue(rpc({"action": "list"})["ok"])
                request = {"action": "add", "actor": "admin@example.com", "cidr": "192.0.2.12",
                           "revision": self.manager.snapshot()["revision"]}
                self.assertTrue(rpc(request)["ok"])
                self.assertEqual(2, len(self.manager.snapshot()["entries"]))
                with mock.patch.object(admin, "peer_allowed", return_value=False), mock.patch.object(self.manager, "request") as manager_call:
                    self.assertFalse(rpc(request)["ok"])
                    manager_call.assert_not_called()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
