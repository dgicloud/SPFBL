-- Run with native rspamadm lua -b FILE; mock only the task/config surface.
local callback
local canary = 'pilot@example.invalid'
rspamd_config = {
  get_all_opt = function() return {recipients = {canary}} end,
  register_symbol = function(_, rule)
    assert(rule.flags == 'ignore_passthrough')
    callback = rule.callback
  end,
}
local base = assert(os.getenv('SPAMFOX_PILOT_TEST_DIR'))
dofile(base .. '/spamfox_pilot.lua')
local actions = {'no action', 'add header', 'rewrite subject', 'reject', 'quarantine', 'discard', 'greylist', 'soft reject', 'unknown'}
local checked = 0
for _, mode in ipairs({'mark', 'quarantine', 'invalid'}) do
  for _, action in ipairs(actions) do
    for _, scope in ipairs({'canary', 'other', 'multiple', 'authenticated'}) do
      local result, reply
      local rcpts = {{addr = scope == 'other' and 'other@example.invalid' or canary}}
      if scope == 'multiple' then rcpts[2] = {addr = canary} end
      local task = {
        get_settings = function() return {spamfox_pilot_mode = mode} end,
        get_user = function() return scope == 'authenticated' and 'pilot-user' or nil end,
        get_recipients = function() return rcpts end,
        get_metric_action = function() return action end,
        get_metric_score = function() return {100, 15} end,
        set_milter_reply = function(_, r) reply = r end,
        set_pre_result = function(_, disposition, _, _, _, priority)
          assert(priority == 100000)
          result = disposition
        end,
      }
      callback(task)
      if mode == 'invalid' or scope == 'multiple' or scope == 'authenticated' then
        assert(result == nil and reply == nil)
      elseif mode == 'mark' then
        local expected = ({['add header'] = true, ['rewrite subject'] = true,
          ['reject'] = true, ['quarantine'] = true, ['discard'] = true})[action]
          and 'add header' or 'no action'
        assert(result == expected and reply ~= nil)
        assert(reply.add_headers['X-SpamFox-Result'] == action)
      elseif scope == 'canary' then
        local expected = ({['reject'] = true, ['quarantine'] = true,
          ['discard'] = true})[action] and 'quarantine'
          or (({['add header'] = true, ['rewrite subject'] = true})[action]
              and 'add header' or 'no action')
        assert(result == expected and reply ~= nil)
      else
        assert(result == nil and reply == nil)
      end
      checked = checked + 1
    end
  end
end
callback({get_settings = function() return {} end})
print('SPAMFOX_PILOT_TEST cases=' .. checked .. ' ordinary_profile_untouched=true')
