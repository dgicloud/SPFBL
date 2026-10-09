import re
import shlex
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class ContentScanFilterTests(unittest.TestCase):
    def test_filter_uses_static_command_and_transport_supplies_metadata_via_environment(self):
        installer = (ROOT / "integrations/cpanel/install-content-scan.sh").read_text()
        filter_text = (ROOT / "integrations/cpanel/exim/sysfilter-content-scan.conf").read_text()
        transport_text = (ROOT / "integrations/cpanel/exim/transport-content-scan.conf").read_text()
        constants = dict(re.findall(r"^(CLIENT_LINK|CLIENT_CONFIG|LOCK)=(.+)$", installer, re.M))
        pipe_lines = [line.strip() for line in filter_text.splitlines()
                      if line.strip().startswith("unseen pipe ")]

        self.assertEqual(1, len(pipe_lines))
        quoted_command = shlex.split(pipe_lines[0][len("unseen pipe "):])
        self.assertEqual(1, len(quoted_command), "Exim filter pipe command must be quoted as one value")
        command = shlex.split(quoted_command[0])
        self.assertEqual([constants["CLIENT_LINK"]], command)
        self.assertNotIn("$sender_address", filter_text)
        self.assertNotIn("$recipients", filter_text)
        self.assertNotIn("$received_port is 25", filter_text,
                         "MONITOR must keep analyzing all eligible traffic; the gateway gates only learning")

        for name, variable in (
            ("HAD_SFOX_QUEUE_ID_B64", "$message_exim_id"),
            ("HAD_SFOX_SENDER_B64", "$sender_address"),
            ("HAD_SFOX_RECIPIENTS_B64", "$recipients"),
            ("HAD_SFOX_CLIENT_IP_B64", "$sender_host_address"),
            ("HAD_SFOX_HELO_B64", "$sender_helo_name"),
            ("HAD_SFOX_RECEIVED_PORT_B64", "$received_port"),
        ):
            self.assertIn(name + "=${base64:" + variable + "}", transport_text)
        self.assertIn("driver = pipe", transport_text)
        self.assertIn("message_prefix =", transport_text)
        self.assertIn("message_suffix =", transport_text)
        self.assertIn("HAD_SFOX_BSMTP=1", transport_text)
        self.assertIn("use_bsmtp = true", transport_text)
        self.assertIn("HAD_SFOX_BSMTP=1", installer)
        self.assertIn("use_bsmtp", installer)

        client = (ROOT / "integrations/content_scan/scan_client.py").read_text()
        self.assertIn(
            'default="/etc/had-content-scan/client.json"',
            client,
        )
        self.assertIn(
            'default="/run/lock/had-content-scan.lock"',
            client,
        )
        self.assertIn(constants["CLIENT_CONFIG"], client)
        self.assertIn(constants["LOCK"], client)
        for name in ("HAD_SFOX_QUEUE_ID_B64", "HAD_SFOX_SENDER_B64",
                     "HAD_SFOX_RECIPIENTS_B64", "HAD_SFOX_CLIENT_IP_B64",
                     "HAD_SFOX_HELO_B64", "HAD_SFOX_RECEIVED_PORT_B64"):
            self.assertIn(name, client)

    def test_data_hook_forwards_only_a_native_single_recipient_inbound_ticket(self):
        acl = (ROOT / "integrations/cpanel/exim/acl-data-header-monitor.conf").read_text()
        self.assertIn("remove_header = Received-SPFBL : X-HAD-AntiSpam-Ticket", acl)
        self.assertIn("add_header = Received-SPFBL: $acl_c_spfbl", acl)
        self.assertIn("condition = ${if eq{$recipients_count}{1}{true}{false}}", acl)
        self.assertIn("!authenticated = *", acl)
        self.assertIn("!hosts = +recent_authed_mail_ips", acl)
        ticket_pattern = (
            r"^(?:PASS|WHITE|FLAG|HOLD|SOFTFAIL|NEUTRAL|NONE|FAIL) "
            r"https?://matrix\.hadcloud\.srv\.br(?::8080)?/"
            r"(?:pt/|en/)?[A-Za-z0-9_-]{44,512}$"
        )
        self.assertIn(
            r"https?://matrix\.hadcloud\.srv\.br(?::8080)?/"
            r"(?:pt/|en/)?[A-Za-z0-9_-]{44,512}",
            acl,
        )
        accepted_ticket_urls = (
            "PASS https://matrix.hadcloud.srv.br/" + "A" * 48,
            "PASS https://matrix.hadcloud.srv.br/pt/" + "B" * 48,
            "FLAG http://matrix.hadcloud.srv.br:8080/pt/" + "C" * 64,
            "NONE https://matrix.hadcloud.srv.br/en/" + "D" * 48,
            "FAIL https://matrix.hadcloud.srv.br/pt/" + "F" * 48,
        )
        for value in accepted_ticket_urls:
            self.assertRegex(value, ticket_pattern)
        self.assertNotRegex(
            "PASS https://matrix.spfbl.net/pt/" + "E" * 48,
            ticket_pattern,
        )
        self.assertNotRegex(
            "PASS https://matrix.hadcloud.srv.br:9877/pt/" + "F" * 48,
            ticket_pattern,
        )
        self.assertIn("condition = ${if eq{$acl_c_spfblticketset}{$acl_c_spfblticket;}{true}{false}}", acl)
        self.assertNotIn("$acl_c_spfblticketset logwrite", acl)


if __name__ == "__main__":
    unittest.main()
