# Append these named settings to local.d/settings.conf after quality approval.
# Named profiles are selected by the private proxy, never by email MIME headers.
spamfox_mark {
  id = "spamfox_mark";
  apply { spamfox_pilot_mode = "mark"; }
}
spamfox_quarantine {
  id = "spamfox_quarantine";
  apply { spamfox_pilot_mode = "quarantine"; }
}
