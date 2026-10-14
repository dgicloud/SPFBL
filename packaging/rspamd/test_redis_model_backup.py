import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import redis_model_backup as backup


class RedisModelBackupTests(unittest.TestCase):
    def test_parse_info_ignores_comments_and_splits_only_once(self):
        self.assertEqual(
            backup.parse_info("# Persistence\nrdb_last_bgsave_status:ok\nmessage:a:b\n"),
            {"rdb_last_bgsave_status": "ok", "message": "a:b"},
        )

    def test_parse_keyspace_info_counts_only_database_key_totals(self):
        self.assertEqual(
            backup.parse_keyspace_info("# Keyspace\ndb0:keys=12,expires=3,avg_ttl=100\ndb2:keys=4,expires=0\n"),
            {"db0": 12, "db2": 4},
        )

    def test_backup_writes_private_rdb_and_manifest_without_message_fields(self):
        with tempfile.TemporaryDirectory() as temp_name:
            base = Path(temp_name)
            redis_dir = base / "redis-live"
            redis_dir.mkdir()
            live_rdb = redis_dir / "dump.rdb"
            live_rdb.write_bytes(b"synthetic-rdb-snapshot")
            root = base / "backups"

            def fake_cli(args, *, socket_path=None):
                if args == ["INFO", "server"]:
                    return "# Server\nredis_version:7.2.4\n"
                self.fail(f"unexpected Redis CLI call: {args}")

            with patch.object(backup, "_read_config_pair", side_effect=[str(redis_dir), "dump.rdb"]), patch.object(
                backup, "_run_redis_cli", side_effect=fake_cli
            ):
                result = backup.create_backup(
                    root,
                    now=datetime(2026, 10, 4, 12, 30, tzinfo=timezone.utc),
                    trigger_save=lambda path: self.assertEqual(path, live_rdb),
                )

            self.assertEqual(result.name, "redis-20261004T123000Z")
            self.assertEqual((result / "dump.rdb").read_bytes(), live_rdb.read_bytes())
            if os.name == "posix":
                self.assertEqual((result / "dump.rdb").stat().st_mode & 0o777, 0o600)
                self.assertEqual(result.stat().st_mode & 0o777, 0o700)
            manifest = json.loads((result / "manifest.json").read_text())
            self.assertEqual(manifest["rdb_sha256"], backup.sha256_file(result / "dump.rdb"))
            self.assertNotIn("message", json.dumps(manifest).lower())

    def test_backup_refuses_symlink_destination(self):
        with tempfile.TemporaryDirectory() as temp_name:
            base = Path(temp_name)
            root = base / "backup-root"
            root.mkdir()
            with patch.object(Path, "is_symlink", return_value=True):
                with self.assertRaises(backup.BackupError):
                    backup._prepare_backup_root(root)

    def test_validation_rejects_changed_rdb(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            snapshot = root / "redis-20261004T123000Z"
            snapshot.mkdir()
            (snapshot / "dump.rdb").write_bytes(b"original")
            manifest = {
                "format_version": 1,
                "rdb_file": "dump.rdb",
                "rdb_size": 8,
                "rdb_sha256": backup.sha256_file(snapshot / "dump.rdb"),
            }
            (snapshot / "manifest.json").write_text(json.dumps(manifest))
            (snapshot / "dump.rdb").write_bytes(b"tampered")
            with self.assertRaises(backup.BackupError):
                backup._validated_backup(snapshot, root)

    def test_validation_refuses_backup_outside_configured_root(self):
        with tempfile.TemporaryDirectory() as temp_name:
            base = Path(temp_name)
            root = base / "root"
            root.mkdir()
            outside = base / "redis-20261004T123000Z"
            outside.mkdir()
            with self.assertRaises(backup.BackupError):
                backup._validated_backup(outside, root)

    def test_retention_removes_only_expired_managed_snapshots(self):
        with tempfile.TemporaryDirectory() as temp_name:
            root = Path(temp_name)
            old = root / "redis-20260801T000000Z"
            recent = root / "redis-20261001T000000Z"
            unknown = root / "not-a-managed-snapshot"
            for folder in (old, recent, unknown):
                folder.mkdir()
            old_manifest = {"created_at": "2026-08-01T00:00:00+00:00"}
            recent_manifest = {"created_at": "2026-10-01T00:00:00+00:00"}
            (old / "manifest.json").write_text(json.dumps(old_manifest))
            (recent / "manifest.json").write_text(json.dumps(recent_manifest))
            removed = backup._prune_old_backups(
                root,
                30,
                datetime(2026, 10, 4, tzinfo=timezone.utc),
            )
            self.assertEqual(removed, 1)
            self.assertFalse(old.exists())
            self.assertTrue(recent.exists())
            self.assertTrue(unknown.exists())


if __name__ == "__main__":
    unittest.main()
