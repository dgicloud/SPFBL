-- Optional native Rspamd extension for a dedicated, private pilot proxy only.
-- No class/core changes and no learning calls; opt-in named settings only.
local allowed_actions = {
  ['no action'] = true, ['add header'] = true, ['rewrite subject'] = true,
  ['reject'] = true, ['quarantine'] = true, ['discard'] = true,
  ['soft reject'] = true, ['greylist'] = true,
}
local marked = {
  ['add header'] = true, ['rewrite subject'] = true,
  ['reject'] = true, ['quarantine'] = true, ['discard'] = true,
}
local held = {['reject'] = true, ['quarantine'] = true, ['discard'] = true}
local options = rspamd_config:get_all_opt('spamfox_pilot') or {}
local recipients = {}
for _, address in ipairs(options.recipients or {}) do
  recipients[string.lower(address)] = true
end

rspamd_config:register_symbol({
  name = 'SPAMFOX_PILOT_DISPOSITION',
  type = 'postfilter',
  priority = -1000,
  flags = 'ignore_passthrough',
  callback = function(task)
    local settings = task:get_settings() or {}
    local mode = settings.spamfox_pilot_mode
    -- Ordinary normal-worker copies and existing MTAs don't select this profile.
    if mode == nil then return false end
    local user = task:get_user()
    local authenticated = type(user) == 'string' and user ~= ''
    local rcpts = task:get_recipients('smtp') or {}
    local single_external_recipient = #rcpts == 1 and not authenticated
    local canary = single_external_recipient
      and recipients[string.lower(rcpts[1].addr or '')]
    -- In mark mode every inbound, single-recipient transaction must be
    -- accepted after being annotated.  That preserves the after-queue copy,
    -- including its native SPFBL ticket, so a high-confidence Rspamd verdict
    -- can be reported once to the core.  Quarantine remains strictly canary
    -- scoped because it changes message availability.
    local eligible = ((mode == 'mark') and single_external_recipient)
      or ((mode == 'quarantine') and canary)
    local proposed = task:get_metric_action() or 'unknown'
    if not allowed_actions[proposed] then proposed = 'unknown' end
    local actual = 'no action'
    if eligible and (mode == 'mark' or mode == 'quarantine') then
      if mode == 'quarantine' and held[proposed] then
        actual = 'quarantine'
      elseif marked[proposed] then
        actual = 'add header'
      end
      local values = task:get_metric_score() or {}
      local score = tonumber(values[1]) or 0
      if score ~= score or score == math.huge or score == -math.huge then score = 0 end
      task:set_milter_reply({
        remove_headers = {
          ['X-SpamFox-Result'] = 0, ['X-SpamFox-Score'] = 0,
          ['X-SpamFox-Engine'] = 0, ['X-SpamFox-Mode'] = 0, ['X-SpamFox-Status'] = 0,
        },
        add_headers = {
          ['X-SpamFox-Result'] = proposed,
          ['X-SpamFox-Score'] = string.format('%.2f', score),
          ['X-SpamFox-Engine'] = 'Rspamd',
          ['X-SpamFox-Mode'] = mode,
          ['X-SpamFox-Status'] = marked[proposed] and 'spam' or 'unmarked',
        },
      })
      if options.log_decisions then
        -- The production logger runs at `notice`; info-level entries would
        -- be silently suppressed and leave the pilot without review data.
        require('rspamd_logger').messagex(task,
          'SpamFox MVP mode=%s result=%s action=%s score=%s',
          mode, proposed, actual, string.format('%.2f', score))
      end
      -- A mark-mode decision is deliberately non-terminal.  The original
      -- verdict remains in X-SpamFox-Result; the after-queue collector then
      -- evaluates the same message and may send one native SPAM <ticket>
      -- complaint only when all gateway safety gates pass.
      task:set_pre_result(actual, 'SpamFox supervised pilot',
                          'spamfox_pilot', nil, 100000)
    end
    return false
  end,
})
