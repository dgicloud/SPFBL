import os
import shutil
import tempfile
import unittest

from manage_postfix import (
    END,
    BEGIN,
    ManagerError,
    Paths,
    _top_level_items,
    add_policy_restriction,
    install,
    uninstall,
)


class FakePostfix(object):
    def __init__(self, paths):
        self.paths = paths
        self.effective = "permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, permit"
        self.calls = []
        self.smoke_input = None
        self.fail_check_once = False
        self.fail_reload_once = False

    def __call__(self, command, timeout=30, input_data=None):
        self.calls.append((command, input_data))
        if command[0] == self.paths.postconf:
            if command[1:] == ["mail_version"]:
                return "mail_version = 3.8.6\n"
            if command[1:3] == ["-h", "smtpd_recipient_restrictions"]:
                return self.effective + "\n"
            if command[1:3] == ["-h", "smtpd_relay_restrictions"]:
                return "permit_mynetworks, permit_sasl_authenticated, defer_unauth_destination\n"
            if command[1:2] == ["-e"]:
                self.effective = command[2].split("=", 1)[1].strip()
                with open(self.paths.main, "ab") as stream:
                    stream.write(("\n# postconf wrote restriction\n" + command[2] + "\n").encode("utf-8"))
                return ""
        if command == [self.paths.postfix, "check"]:
            if self.fail_check_once:
                self.fail_check_once = False
                raise ManagerError("simulated postfix check failure")
            return "postfix check passed\n"
        if command[0] == self.paths.python and command[1] == self.paths.policy:
            self.smoke_input = input_data
            return 'action=DUNNO\n{"decision":"LAN"}\n'
        if command == [self.paths.postfix, "reload"]:
            if self.fail_reload_once:
                self.fail_reload_once = False
                raise ManagerError("simulated reload failure")
            return "reload passed\n"
        raise AssertionError("unexpected command: {0}".format(command))


class PostfixManagerTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="had-postfix-")
        self.paths = Paths(self.root)
        for path, data in (
            (self.paths.main, b"# main.cf baseline\nsmtpd_recipient_restrictions = baseline\n"),
            (self.paths.master, b"# master.cf baseline\nsmtp inet n - n - - smtpd\n"),
        ):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as stream:
                stream.write(data)
        self.main_before = self.read(self.paths.main)
        self.master_before = self.read(self.paths.master)
        self.runner = FakePostfix(self.paths)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    @staticmethod
    def read(path):
        if not os.path.exists(path):
            return None
        with open(path, "rb") as stream:
            return stream.read()

    def test_inserts_after_relay_guard_and_preserves_existing_order(self):
        current = "permit_mynetworks, reject_unauth_destination, check_sender_access hash:/etc/postfix/senders, permit"
        candidate, changed = add_policy_restriction(current)
        self.assertTrue(changed)
        self.assertEqual(
            "permit_mynetworks, reject_unauth_destination, {0}, check_sender_access hash:/etc/postfix/senders, permit".format(
                "check_policy_service { unix:private/had-antispam-policy, timeout=1s, default_action=DUNNO, request_limit=1 }"
            ),
            candidate,
        )

    def test_preserves_nested_policy_commas(self):
        value = "reject_unauth_destination, check_policy_service { inet:policy:1000, timeout=2s }, permit"
        candidate, changed = add_policy_restriction(value)
        self.assertTrue(changed)
        self.assertIn("inet:policy:1000, timeout=2s", candidate)
        self.assertEqual(4, len(_top_level_items(candidate)))

    def test_refuses_configuration_without_relay_guard(self):
        with self.assertRaises(ManagerError):
            add_policy_restriction("permit_mynetworks, permit")

    def test_accepts_separate_relay_guard_and_inserts_before_final_permit(self):
        value = "check_recipient_access hash:/etc/postfix/recipients, permit"
        relay = "permit_mynetworks, defer_unauth_destination"
        candidate, changed = add_policy_restriction(value, relay)
        self.assertTrue(changed)
        self.assertTrue(candidate.endswith("}, permit"))
        self.assertEqual(3, len(_top_level_items(candidate)))

    def test_install_and_uninstall_restore_config_exactly(self):
        result = install(self.paths, server="127.0.0.1", port=19877,
                         runner=self.runner, preflight=False)
        self.assertIn("MONITOR/DUNNO", result)
        self.assertIn(b"HAD-ANTISPAM-MONITOR", self.read(self.paths.master))
        self.assertTrue(os.path.isfile(self.paths.policy))
        self.assertTrue(os.path.isfile(self.paths.client))
        self.assertIn(b"SERVER=127.0.0.1\nPORT=19877", self.read(self.paths.client_conf))
        self.assertIn(b"client_address=192.0.2.25", self.runner.smoke_input)

        result = uninstall(self.paths, runner=self.runner, preflight=False)
        self.assertIn("removed-exactly", result)
        self.assertEqual(self.main_before, self.read(self.paths.main))
        self.assertEqual(self.master_before, self.read(self.paths.master))
        self.assertIsNone(self.read(self.paths.client_conf))
        self.assertIsNone(self.read(self.paths.policy))
        self.assertIsNone(self.read(self.paths.client))
        self.assertFalse(os.path.exists(self.paths.lib_dir))
        self.assertFalse(os.path.exists(os.path.dirname(self.paths.client_conf)))

    def test_failed_postfix_check_rolls_back_all_files(self):
        self.runner.fail_check_once = True
        with self.assertRaises(ManagerError):
            install(self.paths, server="127.0.0.1", port=19877,
                    runner=self.runner, preflight=False)
        self.assertEqual(self.main_before, self.read(self.paths.main))
        self.assertEqual(self.master_before, self.read(self.paths.master))
        self.assertIsNone(self.read(self.paths.client_conf))
        self.assertFalse(os.path.exists(self.paths.state))

    def test_reload_failure_restores_and_reloads_original_configuration(self):
        self.runner.fail_reload_once = True
        with self.assertRaises(ManagerError):
            install(self.paths, server="127.0.0.1", port=19877,
                    runner=self.runner, reload_postfix=True, preflight=False)
        reload_calls = [call for call in self.runner.calls if call[0] == [self.paths.postfix, "reload"]]
        self.assertEqual(2, len(reload_calls))
        self.assertEqual(self.main_before, self.read(self.paths.main))
        self.assertEqual(self.master_before, self.read(self.paths.master))

    def test_uninstall_refuses_to_clobber_admin_changes(self):
        install(self.paths, server="127.0.0.1", port=19877,
                runner=self.runner, preflight=False)
        with open(self.paths.main, "ab") as stream:
            stream.write(b"# administrator edit\n")
        with self.assertRaises(ManagerError):
            uninstall(self.paths, runner=self.runner, preflight=False)
        self.assertIn(b"# administrator edit", self.read(self.paths.main))


if __name__ == "__main__":
    unittest.main()
