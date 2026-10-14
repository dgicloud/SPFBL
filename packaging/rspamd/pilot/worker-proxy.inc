# Candidate additional private proxy; don't replace the existing worker-proxy.
# Include in a worker "rspamd_proxy" block with duplicate=append.
bind_socket = "127.0.0.1:11336";
count = 1;
milter = true;
timeout = 12s;
discard_on_reject = false;
quarantine_on_reject = true;
allow_file_and_shm_inputs = false;
upstream "spamfox_pilot" {
  default = true;
  hosts = "127.0.0.1:11333";
  settings_id = "spamfox_mark";
  timeout = 12s;
}
