import importlib.util
import os
import tempfile
import unittest
from unittest import mock


MODULE_PATH = os.path.join(os.path.dirname(__file__), "firewall.py")
SPEC = importlib.util.spec_from_file_location("had_firewall", MODULE_PATH)
firewall = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(firewall)


class FirewallTests(unittest.TestCase):
    def test_parses_ipv4_and_ipv6_prefixes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "allowed-cpanels.txt")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("# comment\n177.39.18.160\n2001:db8::/48\n")
            networks = firewall.load_networks(path)
        self.assertEqual(["177.39.18.160/32", "2001:db8::/48"], [str(n) for n in networks])

    def test_rejects_empty_or_invalid_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "allowed-cpanels.txt")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("# no clients yet\n")
            with self.assertRaisesRegex(firewall.FirewallError, "allowlist_is_empty"):
                firewall.load_networks(path)
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("177.39.18.999/32\n")
            with self.assertRaisesRegex(firewall.FirewallError, "invalid_allowlist_line_1"):
                firewall.load_networks(path)

    def test_rules_allow_only_configured_query_sources_and_keep_admin_and_http_private(self):
        rendered = firewall.render_rules([firewall.ipaddress.ip_network("177.39.18.160/32")])
        self.assertIn("ip saddr 177.39.18.160/32 tcp dport 9877 accept", rendered)
        self.assertIn("tcp dport 9877 drop", rendered)
        self.assertIn("tcp dport 9875 drop", rendered)
        self.assertIn("tcp dport 8080 drop", rendered)
        self.assertIn("iifname lo accept", rendered)

    def test_update_is_submitted_as_one_atomic_nft_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "allowed-cpanels.txt")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("177.39.18.160/32\n")
            calls = []
            with mock.patch.object(firewall, "_existing_table", return_value="managed"):
                with mock.patch.object(firewall, "_run", side_effect=lambda cmd, **kw: calls.append((cmd, kw))):
                    firewall.apply(path)
        self.assertEqual(2, len(calls))
        self.assertTrue(calls[0][0][1:3] == ["-c", "-f"])
        self.assertEqual(calls[0][1]["input_text"], calls[1][1]["input_text"])
        self.assertTrue(calls[1][1]["input_text"].startswith("delete table inet had_antispam\n"))


if __name__ == "__main__":
    unittest.main()
