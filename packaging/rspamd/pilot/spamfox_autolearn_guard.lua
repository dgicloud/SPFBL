-- # HAD-ANTISPAM-RSPAMD-MANAGED
-- Only authenticated content-monitor requests with a dedicated Settings-ID
-- may invoke the native Bayes autolearn policy.
local bayes_learn = require "lua_bayes_learn"

bayes_learn.register_autolearn_guard("spamfox_content_monitor_only", function(ctx)
  local task = ctx.task
  local settings = task:get_settings()

  if type(settings) ~= "table" or settings.spamfox_content_monitor_autolearn ~= true then
    return { ok = false, reason = "not an enrolled SpamFox content-monitor scan" }
  end

  local queue_id = task:get_queue_id()
  if not queue_id or queue_id == "" then
    return { ok = false, reason = "MTA queue id is missing" }
  end

  local sender = task:get_from("smtp")
  if not sender or not sender[1] or not sender[1].addr or sender[1].addr == "" then
    return { ok = false, reason = "SMTP envelope sender is missing" }
  end

  local auth_user = task:get_user()
  if auth_user and auth_user ~= "" then
    return { ok = false, reason = "authenticated SMTP is excluded" }
  end

  return true
end, { priority = 1000 })
