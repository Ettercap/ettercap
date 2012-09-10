local coroutine = require "coroutine";
local create = coroutine.create;
local resume = coroutine.resume;
local status = coroutine.status;
local yield = coroutine.yield;
local wrap = coroutine.wrap;

local ETTERCAP_SCRIPT_RULES = {
  match_rule = "match_rule",
};


Script = {}

do
  local required_fields = {
    description = "string",
    action = "function",
--    categories = "table",
--    dependencies = "table",
  };

  function Script.new (filename, arguments)
    local script_params = arguments or {};  
    local full_path = ETTERCAP_LUA_SCRIPT_PATH .. "/" .. filename .. ".lua";
    local file_closure = assert(loadfile(full_path));

    local env = {
      SCRIPT_PATH = full_path,
      SCRIPT_NAME = filename,
      dependencies = {},
    };

    -- No idea what this does.
    setmetatable(env, {__index = _G});
    setfenv(file_closure, env);

    local co = create(file_closure); -- Create a garbage thread
    local status, e = resume(co); -- Get the globals it loads in env

    if not status then
      printf("Failed to load %s:\n%s", filename, traceback(co, e));
      --error("could not load script");
      return nil
    end

    for required_field_name in pairs(required_fields) do
      local required_type = required_fields[required_field_name];
      local raw_field = rawget(env, required_field_name)
      local actual_type = type(raw_field);
      assert(actual_type == required_type, 
             "Incorrect of missing field: '" .. required_field_name .. "'." ..
             " Must be of type: '" .. required_type .. "'" ..
             " got type: '" .. actual_type .. "'"
      );
    end

    -- Check our rules....
    local rules = {};
    for rule in pairs(ETTERCAP_SCRIPT_RULES) do
      local rulef = rawget(env, rule);
      assert(type(rulef) == "function" or rulef == nil,
          rule.." must be a function!");
      rules[rule] = rulef;
    end
    local action = env["action"];

    -- Make sure we have a hook_point!
    local hook_point = rawget(env, "hook_point")
    assert(type(hook_point) == "number", "hook_point must be a number!")
 
    local script = {
      filename = filename,
      action = action,
      rules = rules,
      hook_point = hook_point,
      env = env,
      file_closure = file_closure,
      script_params = script_params
    };
    
    return setmetatable(script, {__index = Script, __metatable = Script});
  end
end

return(Script)

