import unittest

from retire_legacy_content_pipe import CleanupError, remove_legacy_pipe


class RetireLegacyContentPipeTests(unittest.TestCase):
    def setUp(self):
        self.config = (
            b"@CONFIG@\n"
            b"system_filter_pipe_transport = sfox_content_pipe\n"
            b"spamd_address = matrix.example.net 9877 retry=30s tmo=3m\n"
            b"@TRANSPORTMIDDLE@\n"
            b"sfox_content_pipe:\n"
            b"  driver = pipe\n"
            b"  environment = SFOX_BSMTP=1:SFOX_QUEUE_ID_B64=${base64:$message_exim_id}\n"
            b"  message_prefix =\n"
            b"  message_suffix =\n"
            b"  use_bsmtp = true\n"
            b"  return_output\n"
            b"@TRANSPORTEND@\n"
            b".include /etc/rspamd/ie-exim-trans.conf\n"
        )

    def test_removes_only_the_retired_upload_transport(self):
        candidate, changed = remove_legacy_pipe(self.config)
        self.assertTrue(changed)
        self.assertIn(b"spamd_address = matrix.example.net 9877", candidate)
        self.assertIn(b".include /etc/rspamd/ie-exim-trans.conf", candidate)
        self.assertNotIn(b"SFOX_BSMTP", candidate)
        self.assertNotIn(b"system_filter_pipe_transport", candidate)

    def test_noop_when_no_retired_transport_exists(self):
        candidate, changed = remove_legacy_pipe(b"@CONFIG@\nspamd_address = matrix.example.net 9877\n")
        self.assertFalse(changed)
        self.assertEqual(candidate, b"@CONFIG@\nspamd_address = matrix.example.net 9877\n")

    def test_refuses_executable_or_ambiguous_pipe(self):
        executable = self.config.replace(b"  return_output", b"  command = /tmp/scan\n  return_output")
        with self.assertRaises(CleanupError):
            remove_legacy_pipe(executable)
        with self.assertRaises(CleanupError):
            remove_legacy_pipe(self.config + b"sfox_content_pipe:\n")


if __name__ == "__main__":
    unittest.main()
