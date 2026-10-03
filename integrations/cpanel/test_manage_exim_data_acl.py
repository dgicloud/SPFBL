import os
import shutil
import tempfile
import unittest

from manage_exim_acl import BEGIN as RCPT_BEGIN, END as RCPT_END, Paths as RcptPaths
from manage_exim_acl import ManagerError
from manage_exim_data_acl import (
    BEGIN,
    END,
    DataPaths,
    install,
    uninstall,
    validate,
)


class FakeDataCpanel(object):
    def __init__(self, paths):
        self.paths = paths
        self.rcpt_paths = RcptPaths(paths.root)
        self.commands = []
        self.inputs = []
        self.fail_dry = False
        self.fail_smoke = False

    def __call__(self, command, timeout=120, input_data=None):
        self.commands.append(command)
        self.inputs.append(input_data)
        if command[0] == self.paths.builder and "--acl_dry_run" in command:
            if self.fail_dry:
                raise ManagerError("fake DATA dry-run failure")
            return "Dry Run ok\n"
        if command[0] == self.paths.builder:
            rcpt = self._read(self.rcpt_paths.hook) or b""
            data = self._read(self.paths.hook) or b""
            with open(self.paths.exim, "wb") as stream:
                stream.write(b"BASELINE\n" + rcpt + data)
            return "Configuration file passes test!\n"
        if command[0] == self.paths.exim_bin:
            if "-bh" in command:
                if self.fail_smoke:
                    return "550 existing policy\n"
                return "LOG: HAD AntiSpam MONITOR DATA CONTINUE|header|no_ticket|0\n"
            return "Configuration file passes test!\n"
        if command[0] == self.paths.restart_exim:
            return "restart fake success\n"
        raise AssertionError("Unexpected command: {0}".format(command))

    @staticmethod
    def _read(path):
        if not os.path.exists(path):
            return None
        with open(path, "rb") as stream:
            return stream.read()


class EximDataAclManagerTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="had-cpanel-data-acl-")
        self.paths = DataPaths(self.root)
        self.rcpt_paths = RcptPaths(self.root)
        for path in (
            self.paths.hook,
            self.rcpt_paths.hook,
            self.paths.exim_local,
            self.paths.exim_localopts,
        ):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as stream:
                stream.write(b"")
        with open(self.paths.exim, "wb") as stream:
            stream.write(b"BASELINE\n")
        self.baseline = self.read_file(self.paths.exim)
        self.runner = FakeDataCpanel(self.paths)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    @staticmethod
    def read_file(path):
        with open(path, "rb") as stream:
            return stream.read()

    def test_validate_restores_data_hook_byte_for_byte(self):
        before = self.read_file(self.paths.hook)
        validate(self.paths, runner=self.runner, preflight=False)
        self.assertEqual(self.read_file(self.paths.hook), before)
        self.assertEqual(self.read_file(self.paths.exim), self.baseline)
        self.assertEqual(self.runner.commands, [[self.paths.builder, "--acl_dry_run"]])

    def test_install_then_uninstall_preserves_existing_rcpt_hook(self):
        rcpt = (
            RCPT_BEGIN + b"\n  warn\n    logwrite = existing RCPT monitor\n" + RCPT_END + b"\n"
        )
        with open(self.rcpt_paths.hook, "wb") as stream:
            stream.write(rcpt)
        with open(self.paths.exim, "wb") as stream:
            stream.write(b"BASELINE\n" + rcpt)
        rcpt_baseline = self.read_file(self.paths.exim)

        self.assertEqual(install(self.paths, runner=self.runner, preflight=False,
                                 test_recipient="postmaster@example.com"), "installed")
        generated = self.read_file(self.paths.exim)
        self.assertIn(RCPT_BEGIN, generated)
        self.assertIn(BEGIN, generated)
        self.assertEqual(self.runner.inputs[-1].splitlines()[0], b"EHLO had-data-smoke.invalid")
        self.assertEqual(self.runner.inputs[-1].splitlines()[2],
                         b"RCPT TO:<postmaster@example.com>")

        self.assertEqual(uninstall(self.paths, runner=self.runner, preflight=False), "removed-exactly")
        self.assertEqual(self.read_file(self.paths.hook), b"")
        self.assertEqual(self.read_file(self.paths.exim), rcpt_baseline)
        self.assertIn(RCPT_BEGIN, self.read_file(self.rcpt_paths.hook))

    def test_failed_dry_run_restores_hook_and_does_not_build(self):
        before = self.read_file(self.paths.hook)
        self.runner.fail_dry = True
        with self.assertRaises(ManagerError):
            install(self.paths, runner=self.runner, preflight=False,
                    test_recipient="postmaster@example.com")
        self.assertEqual(self.read_file(self.paths.hook), before)
        self.assertEqual(self.read_file(self.paths.exim), self.baseline)
        self.assertFalse(os.path.exists(self.paths.state))

    def test_failed_fake_data_smoke_rolls_back_generated_config_and_hook(self):
        before = self.read_file(self.paths.hook)
        self.runner.fail_smoke = True
        with self.assertRaisesRegex(ManagerError, "cancelada e revertida"):
            install(self.paths, runner=self.runner, preflight=False,
                    test_recipient="postmaster@example.com")
        self.assertEqual(self.read_file(self.paths.hook), before)
        self.assertEqual(self.read_file(self.paths.exim), self.baseline)
        self.assertFalse(os.path.exists(self.paths.state))
        self.assertEqual(self.runner.commands.count([self.paths.restart_exim]), 0)

    def test_changed_data_block_is_not_overwritten_on_rollback(self):
        self.assertEqual(install(self.paths, runner=self.runner, preflight=False,
                                 test_recipient="postmaster@example.com"), "installed")
        with open(self.paths.hook, "rb") as stream:
            altered = stream.read().replace(b"MONITOR DATA", b"ALTERED DATA")
        with open(self.paths.hook, "wb") as stream:
            stream.write(altered)
        with self.assertRaisesRegex(ManagerError, "mudou"):
            uninstall(self.paths, runner=self.runner, preflight=False)
        self.assertEqual(self.read_file(self.paths.hook), altered)
        self.assertTrue(os.path.isfile(os.path.join(self.paths.state, "manifest.json")))

    def test_install_rejects_invalid_test_recipient_before_mutating(self):
        with self.assertRaisesRegex(ManagerError, "test-recipient"):
            install(self.paths, runner=self.runner, preflight=False,
                    test_recipient="bad@example.com\nDATA")
        self.assertEqual(self.read_file(self.paths.hook), b"")
        self.assertEqual(self.read_file(self.paths.exim), self.baseline)
        self.assertEqual(self.runner.commands, [])

    def test_duplicate_or_misordered_data_markers_are_rejected(self):
        malformed = BEGIN + b"\n" + END + b"\n" + BEGIN + b"\n" + END
        with open(self.paths.hook, "wb") as stream:
            stream.write(malformed)
        with self.assertRaisesRegex(ManagerError, "duplicados"):
            install(self.paths, runner=self.runner, preflight=False,
                    test_recipient="postmaster@example.com")


if __name__ == "__main__":
    unittest.main()
