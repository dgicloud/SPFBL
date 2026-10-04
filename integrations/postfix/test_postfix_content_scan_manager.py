import unittest

from postfix_content_scan_manager import (
    CONFIG,
    SERVICE_BLOCK,
    SMTP_OVERRIDE,
    UPLOAD_LOCK,
    UPLOAD_LOCK_SECONDARY,
    Paths,
    ContentScanManagerError,
    _assert_clean_targets,
    _assert_no_global_filter,
    config_bytes,
    transform_master_cf,
)


BASE_MASTER = (
    b"# Postfix master services\n"
    b"smtp      inet  n       -       n       -       -       smtpd\n"
    b"  -o smtpd_sasl_auth_enable=yes\n"
    b"submission inet n       -       n       -       -       smtpd\n"
    b"  -o smtpd_tls_security_level=encrypt\n"
    b"pickup    unix  n       -       n       60      1       pickup\n"
)


class PostfixContentScanManagerTests(unittest.TestCase):
    def test_transport_uses_the_paths_created_by_the_installer(self):
        self.assertIn(b"--config=" + CONFIG.encode("ascii"), SERVICE_BLOCK)
        self.assertIn(b"--lock=" + UPLOAD_LOCK.encode("ascii"), SERVICE_BLOCK)
        self.assertIn(b"null_sender=\n", SERVICE_BLOCK)
        self.assertEqual(UPLOAD_LOCK_SECONDARY, UPLOAD_LOCK + ".1")

    def test_installer_preserves_an_existing_secondary_upload_lock(self):
        import os
        import tempfile

        with tempfile.TemporaryDirectory() as root:
            paths = Paths(root)
            os.makedirs(os.path.dirname(paths.upload_lock_secondary))
            with open(paths.upload_lock_secondary, "wb"):
                pass
            with self.assertRaisesRegex(ContentScanManagerError,
                                        "Arquivo-alvo já existe e foi preservado"):
                _assert_clean_targets(paths)

    def test_adds_after_queue_transport_only_to_port_25_smtp_service(self):
        updated, changed = transform_master_cf(BASE_MASTER)

        self.assertTrue(changed)
        self.assertEqual(updated.count(SMTP_OVERRIDE), 1)
        self.assertIn(SERVICE_BLOCK, updated)
        smtp_service = updated.split(b"submission", 1)[0]
        self.assertIn(SMTP_OVERRIDE, smtp_service)
        self.assertIn(b"smtpd_sasl_auth_enable=yes", smtp_service)
        submission_service = updated.split(b"submission", 1)[1].split(b"pickup", 1)[0]
        self.assertNotIn(SMTP_OVERRIDE, submission_service)

    def test_is_idempotent_only_for_exact_managed_configuration(self):
        updated, changed = transform_master_cf(BASE_MASTER)
        self.assertTrue(changed)

        same, changed = transform_master_cf(updated)

        self.assertFalse(changed)
        self.assertEqual(same, updated)

    def test_refuses_an_existing_service_content_filter(self):
        master = BASE_MASTER.replace(
            b"  -o smtpd_sasl_auth_enable=yes\n",
            b"  -o content_filter=existing:dummy\n")

        with self.assertRaisesRegex(ContentScanManagerError, "já possui"):
            transform_master_cf(master)

    def test_global_filter_check_ignores_postconf_warnings_from_master(self):
        class FakePaths:
            postconf = "/usr/sbin/postconf"

        output = (
            "/usr/sbin/postconf: warning: /etc/postfix/master.cf: undefined parameter: mua_client_restrictions\n"
            "postconf: warning: /etc/postfix/master.cf: undefined parameter: mua_sender_restrictions\n"
        )
        _assert_no_global_filter(FakePaths(), lambda command: output)

    def test_global_filter_check_still_rejects_value_after_warnings(self):
        class FakePaths:
            postconf = "/usr/sbin/postconf"

        output = (
            "postconf: warning: /etc/postfix/master.cf: undefined parameter: mua_helo_restrictions\n"
            "scan:dummy\n"
        )
        with self.assertRaisesRegex(ContentScanManagerError, "content_filter=scan:dummy"):
            _assert_no_global_filter(FakePaths(), lambda command: output)

    def test_refuses_an_unmanaged_service_with_our_name(self):
        master = BASE_MASTER + b"\nhad-content-scan unix - n n - 2 pipe\n"

        with self.assertRaisesRegex(ContentScanManagerError, "fora dos marcadores"):
            transform_master_cf(master)

    def test_requires_exactly_one_inbound_smtp_service(self):
        with self.assertRaisesRegex(ContentScanManagerError, "exatamente um"):
            transform_master_cf(b"pickup unix n - n 60 1 pickup\n")

        duplicated = BASE_MASTER + b"smtp inet n - n - - smtpd\n"
        with self.assertRaisesRegex(ContentScanManagerError, "encontrados 2"):
            transform_master_cf(duplicated)

    def test_accepts_address_specific_smtp_listener(self):
        master = BASE_MASTER.replace(b"smtp      inet", b"192.0.2.10:smtp inet")
        updated, changed = transform_master_cf(master)

        self.assertTrue(changed)
        self.assertEqual(updated.count(SMTP_OVERRIDE), 1)

    def test_config_binds_fixed_https_endpoint_and_rejects_bad_inputs(self):
        config = config_bytes("mx-one", "t" * 48)
        self.assertIn(b"https://matrix.hadcloud.srv.br/internal/sfox/scan", config)
        self.assertIn(b'"client_id":"mx-one"', config)
        self.assertNotIn(b"example.invalid", config)

        for client_id in ("UPPER", "-starts-wrong", "x" * 65):
            with self.subTest(client_id=client_id):
                with self.assertRaises(ContentScanManagerError):
                    config_bytes(client_id, "t" * 48)
        with self.assertRaises(ContentScanManagerError):
            config_bytes("mx-one", "short")


if __name__ == "__main__":
    unittest.main()
