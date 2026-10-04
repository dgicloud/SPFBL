# HAD-ANTISPAM-RSPAMD-MANAGED
# Controller writes must use the root-only enable_password, even from loopback.
secure_ip = [];
# Do not let HTTP clients make Rspamd read client-selected files or shared memory.
allow_file_and_shm_inputs = false;
