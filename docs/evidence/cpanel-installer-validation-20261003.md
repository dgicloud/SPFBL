# New cPanel installer validation — 2026-10-03

Artifact: `had-antispam-cpanel-1.2.1-had-20261003-signals.tar.gz`.
SHA-256: `3ec0137cc51f1554ba1960e4fd8b37f5ad0dbbe828a0a20a4568a825504dbb13`.

New root launcher invokes the dedicated cPanel installer with explicit local test recipient, numerical core endpoint default 151.242.41.35:9877 and both RCPT/DATA monitor hooks. Preflight validates requirements, VERSION and Exim routing; `--check` avoids installation. Existing direct client installations are refused, not silently upgraded.

Bundle extracted in a disposable staging directory on Group Guedes; checksum verified, bash syntax and help passed, Python modules compiled with server Python 3.6.8, scripts have LF endings. An installation attempt on the already-installed server was refused before changing state. The existing staged integration suite ran 86 tests successfully on that cPanel; Exim and adapter remained active. Locally 81 passed and 5 platform-specific skips. Existing validated transactional install/managers are reused; no fresh installation on a new cPanel was performed in this turn.

Package contains no core binaries, production configuration or provider credentials. Metadata collection remains local and monitor-only; continuous centralized Jev forwarding and confidence calibration are not implemented by this installer. Existing upstream enforcement rules are preserved.
