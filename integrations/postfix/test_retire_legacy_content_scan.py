import unittest

from retire_legacy_content_scan import RetireError, transform


class RetireLegacyContentScanTests(unittest.TestCase):
    def setUp(self):
        self.main = (
            b"smtpd_milters = inet:localhost:11332 unix:opendkim/opendkim.sock\n"
            b"# BEGIN SFOX-CONTENT-SCAN SETTINGS\n"
            b"sfox-content-scan_destination_recipient_limit = 1\n"
            b"# END SFOX-CONTENT-SCAN SETTINGS\n"
        )
        self.master = (
            b"# BEGIN SFOX-CONTENT-SCAN TRANSPORT\n"
            b"sfox-content-scan unix - n n - 2 pipe\n"
            b"  argv=/usr/bin/python3 /usr/local/libexec/sfox-content-scan/postfix_content_filter.py\n"
            b"# END SFOX-CONTENT-SCAN TRANSPORT\n"
            b"smtp inet n - n - - smtpd\n"
        )

    def test_removes_only_retired_blocks(self):
        main, master, changed = transform(self.main, self.master)
        self.assertTrue(changed)
        self.assertIn(b"smtpd_milters = inet:localhost:11332", main)
        self.assertIn(b"smtp inet n - n - - smtpd", master)
        self.assertNotIn(b"SFOX-CONTENT-SCAN", main + master)

    def test_noop_without_retired_blocks(self):
        main, master, changed = transform(b"smtpd_milters = opendkim\n", b"smtp inet n - n - - smtpd\n")
        self.assertFalse(changed)
        self.assertEqual(main, b"smtpd_milters = opendkim\n")
        self.assertEqual(master, b"smtp inet n - n - - smtpd\n")

    def test_partial_or_modified_blocks_fail_closed(self):
        with self.assertRaises(RetireError):
            transform(self.main, b"smtp inet n - n - - smtpd\n")
        altered = self.master.replace(b"postfix_content_filter.py", b"custom_filter.py")
        with self.assertRaises(RetireError):
            transform(self.main, altered)


if __name__ == "__main__":
    unittest.main()
