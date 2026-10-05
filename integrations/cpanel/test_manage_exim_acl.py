import os
import shutil
import sys
import tempfile
import unittest

from manage_exim_acl import (
    DEFAULT_LOCALOPTS_KEY,
    ManagerError,
    Paths,
    install,
    run_command,
    uninstall,
    validate,
)


class FakeCpanel(object):
    def __init__(self, paths):
        self.paths = paths
        self.fail_full = False
        self.fail_dry = False
        self.fail_restart_once = False
        self.commands = []
        self.inputs = []
        self.dry_option_values = []

    def hook_contents(self):
        if not os.path.exists(self.paths.hook):
            return b""
        with open(self.paths.hook, "rb") as stream:
            return stream.read()

    def option_value(self):
        with open(self.paths.exim_localopts, "rb") as stream:
            for line in stream:
                if line.startswith(DEFAULT_LOCALOPTS_KEY.encode("ascii") + b"="):
                    return line.split(b"=", 1)[1].strip().decode("ascii")
        return None

    def __call__(self, command, timeout=120, input_data=None):
        self.commands.append(command)
        self.inputs.append(input_data)
        if command[0] == self.paths.builder and "--acl_dry_run" in command:
            if self.fail_dry:
                raise ManagerError("dry-run fake failure")
            self.dry_option_values.append(self.option_value() or "0")
            content = self.hook_contents().decode("utf-8")
            return "Dry Run ok\n" + content
        if command[0] == self.paths.builder:
            if self.fail_full:
                self.fail_full = False
                raise ManagerError("full-build fake failure")
            hook = self.hook_contents()
            with open(self.paths.exim, "wb") as stream:
                stream.write(b"BASELINE\n" + (hook if self.option_value() == "1" else b""))
            return "Configuration file passes test! New configuration file was installed.\n"
        if command[0] == self.paths.exim_bin:
            if "-bh" in command:
                return "LOG: SFOX MONITOR RCPT CONTINUE|decision|LAN|1\n550 existing Exim policy\n"
            return "Configuration file passes test!\n"
        if command[0] == self.paths.restart_exim:
            if self.fail_restart_once:
                self.fail_restart_once = False
                raise ManagerError("restart fake failure")
            return "restart fake success\n"
        raise AssertionError("Unexpected command: {0}".format(command))


class EximAclManagerTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="had-cpanel-acl-")
        self.paths = Paths(self.root)
        for path in (self.paths.hook, self.paths.exim_local, self.paths.exim_localopts):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as stream:
                stream.write(b"")
        with open(self.paths.exim_localopts, "wb") as stream:
            stream.write(DEFAULT_LOCALOPTS_KEY.encode("ascii") + b"=0\nkeep_this_option=1\n")
        self.localopts_baseline = self.read_file(self.paths.exim_localopts)
        with open(self.paths.exim, "wb") as stream:
            stream.write(b"BASELINE\n")
        self.baseline = self.read_file(self.paths.exim)
        self.runner = FakeCpanel(self.paths)

    @staticmethod
    def read_file(path):
        with open(path, "rb") as stream:
            return stream.read()

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def hook_bytes(self):
        if not os.path.exists(self.paths.hook):
            return None
        with open(self.paths.hook, "rb") as stream:
            return stream.read()

    def test_command_timeout_includes_partial_output(self):
        command = [sys.executable, "-c",
                   "import sys,time; print('exim diagnostic marker', flush=True); time.sleep(5)"]
        with self.assertRaises(ManagerError) as caught:
            run_command(command, timeout=0.1)
        self.assertIn("timeout", str(caught.exception).lower())
        self.assertIn("exim diagnostic marker", str(caught.exception))

    def test_validate_restores_hook_without_building_active_config(self):
        before = self.hook_bytes()
        validate(self.paths, runner=self.runner, preflight=False)
        self.assertEqual(before, self.hook_bytes())
        self.assertEqual(self.localopts_baseline, self.read_file(self.paths.exim_localopts))
        self.assertEqual(["1"], self.runner.dry_option_values)
        self.assertEqual(self.baseline, self.read_file(self.paths.exim))
        self.assertEqual(1, len(self.runner.commands))
        self.assertIn("--acl_dry_run", self.runner.commands[0])

    def test_exim_manager_does_not_consult_firewall_services(self):
        """ACL validation is an Exim operation and must not depend on nftables."""
        validate(self.paths, runner=self.runner, preflight=False)
        self.assertEqual([[self.paths.builder, "--acl_dry_run"]], self.runner.commands)

    def test_install_then_uninstall_rebuilds_and_restores_exact_hook(self):
        before = self.hook_bytes()
        self.assertEqual("installed", install(self.paths, runner=self.runner, preflight=False))
        self.assertIn(DEFAULT_LOCALOPTS_KEY.encode("ascii") + b"=1\n",
                      self.read_file(self.paths.exim_localopts))
        self.assertIn(b"keep_this_option=1\n", self.read_file(self.paths.exim_localopts))
        self.assertIn(b"# BEGIN HAD-ANTISPAM-MONITOR", self.hook_bytes())
        self.assertIn(b"# BEGIN HAD-ANTISPAM-MONITOR", self.read_file(self.paths.exim))
        self.assertEqual("removed-exactly", uninstall(self.paths, runner=self.runner, preflight=False))
        self.assertEqual(before, self.hook_bytes())
        self.assertEqual(self.localopts_baseline, self.read_file(self.paths.exim_localopts))
        self.assertEqual(self.baseline, self.read_file(self.paths.exim))

    def test_install_is_idempotent(self):
        self.assertEqual("installed", install(self.paths, runner=self.runner, preflight=False))
        current = self.hook_bytes()
        self.assertEqual("already-installed", install(self.paths, runner=self.runner, preflight=False))
        self.assertEqual(current, self.hook_bytes())
        self.assertEqual(1, current.count(b"# BEGIN HAD-ANTISPAM-MONITOR"))

    def test_preserves_previously_enabled_cpanel_custom_acl_option(self):
        enabled = DEFAULT_LOCALOPTS_KEY.encode("ascii") + b"=1\nkeep_this_option=1\n"
        with open(self.paths.exim_localopts, "wb") as stream:
            stream.write(enabled)
        with open(self.paths.exim, "wb") as stream:
            stream.write(b"BASELINE\n")
        self.assertEqual("installed", install(self.paths, runner=self.runner, preflight=False))
        self.assertEqual("removed-exactly", uninstall(self.paths, runner=self.runner, preflight=False))
        self.assertEqual(enabled, self.read_file(self.paths.exim_localopts))

    def test_missing_option_is_temporarily_enabled_and_validation_restores_exact_bytes(self):
        original = b"keep_this_option=1"
        with open(self.paths.exim_localopts, "wb") as stream:
            stream.write(original)
        validate(self.paths, runner=self.runner, preflight=False)
        self.assertEqual(original, self.read_file(self.paths.exim_localopts))
        self.assertEqual(["1"], self.runner.dry_option_values)

    def test_install_and_uninstall_restore_missing_option_and_unterminated_file(self):
        original = b"keep_this_option=1"
        with open(self.paths.exim_localopts, "wb") as stream:
            stream.write(original)
        self.assertEqual("installed", install(self.paths, runner=self.runner, preflight=False))
        self.assertEqual("1", self.runner.option_value())
        self.assertEqual("removed-exactly", uninstall(self.paths, runner=self.runner, preflight=False))
        self.assertEqual(original, self.read_file(self.paths.exim_localopts))

    def test_dry_run_failure_restores_hook_and_removes_snapshot(self):
        before = self.hook_bytes()
        self.runner.fail_dry = True
        with self.assertRaises(ManagerError):
            install(self.paths, runner=self.runner, preflight=False)
        self.assertEqual(before, self.hook_bytes())
        self.assertEqual(self.localopts_baseline, self.read_file(self.paths.exim_localopts))
        self.assertFalse(os.path.exists(self.paths.state))
        self.assertEqual(self.baseline, self.read_file(self.paths.exim))

    def test_full_build_failure_rolls_back_hook_and_keeps_exim_baseline(self):
        before = self.hook_bytes()
        self.runner.fail_full = True
        with self.assertRaises(ManagerError):
            install(self.paths, runner=self.runner, preflight=False)
        self.assertEqual(before, self.hook_bytes())
        self.assertEqual(self.localopts_baseline, self.read_file(self.paths.exim_localopts))
        self.assertFalse(os.path.exists(self.paths.state))
        self.assertEqual(self.baseline, self.read_file(self.paths.exim))

    def test_install_runs_fake_smtp_and_preserves_existing_rejection(self):
        self.assertEqual("installed", install(self.paths, runner=self.runner, preflight=False,
                                               reload_exim=True))
        smoke_index = next(index for index, command in enumerate(self.runner.commands)
                           if "-bh" in command)
        reload_index = next(index for index, command in enumerate(self.runner.commands)
                            if command == [self.paths.restart_exim])
        self.assertLess(smoke_index, reload_index)
        self.assertIn(b"MAIL FROM:<>\n", self.runner.inputs[smoke_index])

    def test_smoke_failure_rolls_back_before_any_reload(self):
        def failing_smoke(command, timeout=120, input_data=None):
            if "-bh" in command:
                raise ManagerError("fake SMTP failed")
            return self.runner(command, timeout=timeout, input_data=input_data)

        with self.assertRaises(ManagerError):
            install(self.paths, runner=failing_smoke, preflight=False, reload_exim=True)
        self.assertEqual(b"", self.hook_bytes())
        self.assertEqual(self.localopts_baseline, self.read_file(self.paths.exim_localopts))
        self.assertEqual(self.baseline, self.read_file(self.paths.exim))
        self.assertFalse(os.path.exists(self.paths.state))
        self.assertEqual(0, self.runner.commands.count([self.paths.restart_exim]))

    def test_failed_reload_rebuilds_and_reloads_restored_configuration(self):
        self.runner.fail_restart_once = True
        with self.assertRaises(ManagerError):
            install(self.paths, runner=self.runner, preflight=False, reload_exim=True)
        self.assertEqual(b"", self.hook_bytes())
        self.assertEqual(self.baseline, self.read_file(self.paths.exim))
        self.assertEqual(2, self.runner.commands.count([self.paths.restart_exim]))

    def test_absent_original_hook_is_removed_again_on_uninstall(self):
        os.unlink(self.paths.hook)
        self.assertEqual("installed", install(self.paths, runner=self.runner, preflight=False))
        self.assertEqual("removed-exactly", uninstall(self.paths, runner=self.runner, preflight=False))
        self.assertIsNone(self.hook_bytes())

    def test_changes_outside_managed_block_survive_uninstall(self):
        self.assertEqual("installed", install(self.paths, runner=self.runner, preflight=False))
        with open(self.paths.hook, "ab") as stream:
            stream.write(b"# Independent cPanel addition\n")
        result = uninstall(self.paths, runner=self.runner, preflight=False)
        self.assertEqual("removed-exactly", result)
        self.assertEqual(b"# Independent cPanel addition\n", self.hook_bytes())

    def test_changed_managed_block_is_not_overwritten(self):
        self.assertEqual("installed", install(self.paths, runner=self.runner, preflight=False))
        current = self.hook_bytes().replace(b"MONITOR RCPT", b"ALTERED RCPT")
        with open(self.paths.hook, "wb") as stream:
            stream.write(current)
        with self.assertRaises(ManagerError):
            uninstall(self.paths, runner=self.runner, preflight=False)
        self.assertEqual(current, self.hook_bytes())


if __name__ == "__main__":
    unittest.main()
