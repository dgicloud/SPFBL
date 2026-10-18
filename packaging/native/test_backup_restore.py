import hashlib
import importlib.util
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


MODULE_PATH = os.path.join(os.path.dirname(__file__), "backup_restore.py")
SPEC = importlib.util.spec_from_file_location("spamfox_backup_restore", MODULE_PATH)
backup_restore = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup_restore)


class FakeService(object):
    def __init__(self, active=True, start_failures=0):
        self.is_running = active
        self.start_failures = start_failures
        self.events = []

    def pause_maintenance(self):
        self.events.append("pause")
        return True

    def resume_maintenance(self, was_active):
        self.events.append("resume")

    def active(self):
        return self.is_running

    def stop(self):
        self.events.append("stop")
        self.is_running = False

    def start(self):
        self.events.append("start")
        if self.start_failures:
            self.start_failures -= 1
            raise RuntimeError("synthetic systemd start failure")
        self.is_running = True

    def wait_ready(self):
        self.events.append("ready")
        if not self.is_running:
            raise RuntimeError("service is not active")


class BackupRestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.layout = self.make_layout(self.root, "release-1")
        self.service = FakeService(active=True)
        self.manager = backup_restore.BackupRestore(
            self.layout, self.service, owner_normalizer=lambda etc, state: None,
        )

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def make_layout(root, version):
        app = root / "opt" / "spfbl"
        current = app / "current"
        (current / "release").mkdir(parents=True)
        (current / "release" / "version").write_text(version, encoding="utf-8")
        etc = root / "etc" / "spamfox"
        state = root / "var" / "lib" / "spamfox"
        (etc).mkdir(parents=True)
        (state / "data").mkdir(parents=True)
        (state / "history").mkdir(parents=True)
        (state / ".junique").mkdir()
        (etc / "spfbl.conf").write_text("admin_port=9875\ndnsbl_port=53\n", encoding="utf-8")
        (etc / "allowed-cpanels.txt").write_text("192.0.2.10/32\n", encoding="ascii")
        (state / "data" / "server.key").write_bytes(b"synthetic-ticket-key\n")
        (state / "data" / "client.map").write_bytes(b"synthetic-client-state\n")
        (state / "data" / "peer.map").write_bytes(b"synthetic-peer-state\n")
        (state / "data" / "block.txt").write_bytes(b"BLOCKED 192.0.2.25\n")
        (state / "history" / "query.data").write_bytes(b"synthetic-query-history\n")
        (state / ".junique" / "global.lock").write_bytes(b"")
        return backup_restore.Layout(app=app, etc=etc, state=state, backups=root / "backups")

    def _backup_without_service_cycle(self, manager=None):
        manager = manager or self.manager
        return backup_restore.create_archive(manager.layout, manager.layout.backups)

    def test_backup_is_consistent_versioned_and_excludes_runtime_locks(self):
        archive, digest, manifest = self.manager.backup()
        verified = self.manager.verify(archive)

        self.assertEqual(self.service.events, ["pause", "stop", "start", "ready", "resume"])
        self.assertTrue(self.service.is_running)
        self.assertEqual(manifest["source_version"], "release-1")
        self.assertEqual(verified["sha256"], digest)
        self.assertTrue(Path(str(archive) + ".sha256").is_file())
        with tarfile.open(str(archive), "r:gz") as tar:
            names = set(tar.getnames())
        self.assertIn("var/lib/spamfox/data/server.key", names)
        self.assertIn("var/lib/spamfox/data/peer.map", names)
        self.assertIn("var/lib/spamfox/history/query.data", names)
        self.assertIn("etc/spamfox/spfbl.conf", names)
        self.assertNotIn("var/lib/spamfox/.junique/global.lock", names)

    def test_restore_applies_verified_snapshot_and_creates_pre_restore_copy(self):
        archive, _, _ = self._backup_without_service_cycle()
        (self.layout.state / "data" / "client.map").write_bytes(b"newer-state")
        (self.layout.etc / "spfbl.conf").write_text("changed=true\n", encoding="utf-8")

        result = self.manager.restore(archive, confirm=True)

        self.assertEqual((self.layout.state / "data" / "client.map").read_bytes(), b"synthetic-client-state\n")
        self.assertIn("dnsbl_port=53", (self.layout.etc / "spfbl.conf").read_text(encoding="utf-8"))
        self.assertTrue(Path(result["safety_archive"]).is_file())
        self.assertEqual(self.service.events, ["pause", "stop", "start", "ready", "resume"])
        self.assertTrue(self.service.is_running)

    def test_restore_accepts_legacy_config_root(self):
        with mock.patch.object(backup_restore, "ETC_ARCHIVE", backup_restore.LEGACY_ETC_ARCHIVE):
            archive, _, _ = self._backup_without_service_cycle()
        (self.layout.etc / "spfbl.conf").write_text("changed=true\n", encoding="utf-8")

        self.manager.restore(archive, confirm=True)

        self.assertIn("dnsbl_port=53", (self.layout.etc / "spfbl.conf").read_text(encoding="utf-8"))
        with tarfile.open(str(archive), "r:gz") as tar:
            self.assertIn("etc/had-antispam/spfbl.conf", tar.getnames())

    def test_restore_accepts_legacy_had_antispam_state_root(self):
        with mock.patch.object(backup_restore, "STATE_ARCHIVE", backup_restore.LEGACY_STATE_ARCHIVE):
            archive, _, _ = self._backup_without_service_cycle()
        (self.layout.state / "data" / "client.map").write_bytes(b"changed-state")

        self.manager.restore(archive, confirm=True)

        self.assertEqual((self.layout.state / "data" / "client.map").read_bytes(), b"synthetic-client-state\n")
        with tarfile.open(str(archive), "r:gz") as tar:
            self.assertIn("var/lib/had-antispam/data/server.key", tar.getnames())

    def test_dry_run_validates_without_stopping_or_changing_live_files(self):
        archive, _, _ = self._backup_without_service_cycle()
        before = (self.layout.state / "data" / "client.map").read_bytes()

        result = self.manager.restore(archive, dry_run=True)

        self.assertTrue(result["dry_run"])
        self.assertEqual((self.layout.state / "data" / "client.map").read_bytes(), before)
        self.assertEqual(self.service.events, [])

    def test_restore_requires_confirmation_and_rejects_release_mismatch(self):
        archive, _, _ = self._backup_without_service_cycle()
        with self.assertRaisesRegex(backup_restore.BackupError, "--yes"):
            self.manager.restore(archive)

        other = self.root / "other"
        other.mkdir()
        other_layout = self.make_layout(other, "release-2")
        other_manager = backup_restore.BackupRestore(
            other_layout, FakeService(active=False), owner_normalizer=lambda etc, state: None,
        )
        with self.assertRaisesRegex(backup_restore.BackupError, "incompatível"):
            other_manager.restore(archive, confirm=True)

    def test_tampered_archive_is_rejected_before_mutation(self):
        archive, _, _ = self._backup_without_service_cycle()
        with open(archive, "ab") as stream:
            stream.write(b"tamper")
        before = (self.layout.state / "data" / "client.map").read_bytes()

        with self.assertRaisesRegex(backup_restore.BackupError, "SHA-256"):
            self.manager.restore(archive, confirm=True)
        self.assertEqual((self.layout.state / "data" / "client.map").read_bytes(), before)
        self.assertEqual(self.service.events, [])

    def test_archive_path_traversal_is_rejected(self):
        archive = self.layout.backups / "malicious.tar.gz"
        archive.parent.mkdir(parents=True)
        with tarfile.open(str(archive), "w:gz") as tar:
            info = tarfile.TarInfo("../../outside")
            payload = b"nope"
            info.size = len(payload)
            import io
            tar.addfile(info, io.BytesIO(payload))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        Path(str(archive) + ".sha256").write_text(digest + "  malicious.tar.gz\n", encoding="ascii")

        with self.assertRaisesRegex(backup_restore.BackupError, "inseguro"):
            self.manager.verify(archive)

    def test_failed_new_core_start_rolls_back_files_and_restarts_old_state(self):
        archive, _, _ = self._backup_without_service_cycle()
        (self.layout.state / "data" / "client.map").write_bytes(b"pre-restore-state")
        self.service.start_failures = 1

        with self.assertRaisesRegex(RuntimeError, "start failure"):
            self.manager.restore(archive, confirm=True)

        self.assertEqual((self.layout.state / "data" / "client.map").read_bytes(), b"pre-restore-state")
        self.assertTrue(self.service.is_running)
        self.assertEqual(self.service.events, ["pause", "stop", "start", "start", "ready", "resume"])

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
                         "POSIX ownership test requires root")
    def test_restore_permissions_are_private_and_owned_by_service_identity(self):
        if backup_restore.pwd is None or backup_restore.grp is None:
            self.skipTest("POSIX account modules unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            etc = root / "etc"
            state = root / "state"
            (state / "data").mkdir(parents=True)
            (state / "history").mkdir()
            etc.mkdir()
            data_file = state / "data" / "server.key"
            config_file = etc / "spfbl.conf"
            data_file.write_text("synthetic-key", encoding="ascii")
            config_file.write_text("admin_port=9875", encoding="ascii")
            os.chmod(str(data_file), 0o666)
            os.chmod(str(config_file), 0o666)
            with mock.patch.object(backup_restore.pwd, "getpwnam", return_value=SimpleNamespace(pw_uid=1001)) as get_user:
                with mock.patch.object(backup_restore.grp, "getgrnam", return_value=SimpleNamespace(gr_gid=1002)) as get_group:
                    backup_restore._normalize_ownership(etc, state)
            get_user.assert_called_once_with("spamfox")
            get_group.assert_called_once_with("spamfox")
            self.assertEqual(os.stat(str(data_file)).st_uid, 1001)
            self.assertEqual(os.stat(str(data_file)).st_gid, 1002)
            self.assertEqual(os.stat(str(config_file)).st_uid, 0)
            self.assertEqual(os.stat(str(config_file)).st_gid, 1002)
            self.assertEqual(stat.S_IMODE(os.stat(str(data_file)).st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(os.stat(str(config_file)).st_mode), 0o640)
            self.assertEqual(stat.S_IMODE(os.stat(str(state)).st_mode), 0o750)


if __name__ == "__main__":
    unittest.main()
