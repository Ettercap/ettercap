---
-- Note: I've put all of Ettercap's LUA core into one big script because 
--  I'm a complete LUA newb and I have no idea what I'm doing. This is despite
--  my instinct toward smaller, more managable files. 
-- 


-- All of our core stuff will reside in the "ettercap" namespace.
ettercap = {}

---------------
-- We use luajit's FFI implementation to gain access to a few datastructures 
-- and functions that already exist within Ettercap. This provides a 
-- convenient way to prototype functionality, with the idea that we'd produce
-- a more solid C implementation for access, in the future.
--
---------------

ettercap.ffi = require("ettercap_ffi")

---------------
-- Script interface
--
-- All Ettercap LUA scripts are initialized using a common interface. We've 
-- modeled this interface very closely after that of NMAP's NSE script 
-- interface. Our hope is that the community's familiarity with NSE will 
-- lower the barrier for entry for those looking to write Ettercap LUA 
-- scripts.
--
--
--  Data structures:
--    packet_object - Access to the Ettercap "packet_object" (originally 
--                    defined in include/ec_packet.h) is provided via a 
--                    light luajit FFI wrapper. Details on interacting with 
--                    data-types via luajit FFI can be found here:
--                    http://luajit.org/ext_ffi_semantics.html. 
--
--                    Generally, script implementations should avoid direct
--                    modifications to packet_object, or any FFI wrapped 
--                    structure, instead favoring modification through 
--                    defined ettercap.* interfaces.
--
--                    NOTE: Careful consideration must be taken to when 
--                    interacting with FFI-wrapped data-structures! Data 
--                    originating from outside of the LUA VM must have their
--                    memory managed *manually*! See the section of luajit's
--                    FFI Semantics on "Garbage Collection of cdata Objects"
--                    for details. 
--                    
--
--  Script requirements:
--
--    description - (string) Like that of NSE, each script must have a 
--                  description of the its functionality.
--
--    action      - (function (packet_object)) The action of a script operates
--                  on a FFI-wrapped packet_object. 
--
--  Optional:
--
--    match_rule  - (function (packet_object)) If implemented, then this 
--                  function must return true for a given packet_object 
--                  before that packet_object is passed to the script's action.
--
---------------
Script = {}

local coroutine = require "coroutine";
local debug = require "debug";
local traceback = debug.traceback;

local ETTERCAP_SCRIPT_RULES = {
  match_rule = "match_rule",
};



do
  -- These are the components of a script that are required. 
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

    local co = coroutine.create(file_closure); -- Create a garbage thread
    local status, e = coroutine.resume(co); -- Get the globals it loads in env

    if not status then
      ettercap.log("Failed to load %s:\n%s", filename, traceback(co, e));
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

-----------

ettercap.ec_hooks = {}
ettercap.scripts = {}

local ettercap_c = require("ettercap_c")
local eclib = require("eclib")

--- Log's a message using ettercap's ui_msg function.
-- @see string.format
-- @param fmt The format string
-- @param ... Variable arguments to pass in
ettercap.log = function(fmt, ...) 
  -- We don't want any format string "accidents" on the C side of things.. 
  -- so, we will let lua handle it.
  ettercap.ffi.C.ui_msg("%s", string.format(fmt, ...))
end

--- Called during ettercap's shutdown
ettercap.cleanup = function() 
end

-- Adds a hook
local hook_add = function (point, func)
  ettercap_c.hook_add(point)
  table.insert(ettercap.ec_hooks, {point, func})
end


--- Dispatches a packet at to those registered for the given hook_point
-- @param point (integer) The hook point
-- @param packet_object_ptr (lightuserdata) A pointer to the packet_object_ptr.
--  This is intended to be cast as packet_object pointer using FFI.
ettercap.dispatch_hook = function (point, packet_object_ptr)
  -- We cast the packet into the struct that we want, and then hand it off.
  local packet_object = ettercap.ffi.cast("struct packet_object *", packet_object_ptr);
  for key, hook in pairs(ettercap.ec_hooks) do
    if hook[1] == point then
      hook[2](packet_object)
    end
  end
end

-- Processes all the --lua-script arguments into a single list of script
-- names. 
--
-- @param scripts An array of script cli arguments
-- @return A table containing all the split arguments
local cli_split_scripts = function (scripts)
  -- This keeps track of what script names have already been encountered. 
  -- This prevents us from loading the same script more than once.
  local loaded_scripts = {}

  local ret = {}
  for v = 1, #scripts do
    local s = scripts[v]
    local script_list = eclib.split(s, ",")
    for i = 1, #script_list do 
      if (loaded_scripts[script_list[i]] == nil) then
        -- We haven't loaded this script, yet, so add it it our list.
        table.insert(ret, script_list[i])
        loaded_scripts[script_list[i]] = 1
      end
    end 
  end

  return ret
end

-- Processes all the --lua-args arguments into a single list of args
-- names. 
--
-- @param args An array of args cli arguments
-- @return A table containing all the split arguments
local cli_split_args = function (args)
  local ret = {}
  for v = 1, #args do
    local s = args[v]
    local arglist = eclib.split(s, ",")
    for i = 1, #arglist do 
      -- We haven't loaded this args, yet, so add it it our list.
      local temp = eclib.split(arglist[i],"=")
      ret[temp[1]] = temp[2]
    end 
  end

  return ret
end

-- Loads a script.
--
-- @param name (string) The name of the script we want to load.
-- @param args (table) A table of key,value tuples
ettercap.load_script = function (name, args)
  local script = Script.new(name, args)
  -- Adds a hook. Will only run the action if the match rule is nil or 
  -- return true.
  hook_add(script.hook_point, function(po) 
    match_rule = script.rules["match_rule"]
    if (not(match_rule == nil)) then
      if not(match_rule(po) == true) then
        return false
      end
    end
    script.action(po)
  end);
end

--- Primary entry point for ettercap lua environment
-- @param lua_scripts Array of CLI script strings
-- @param lua_args Array of CLI argument strings
ettercap.main = function (lua_scripts, lua_args)
  local scripts = cli_split_scripts(lua_scripts)
  local args = cli_split_args(lua_args)
  for i = 1, #scripts do
    ettercap.load_script(scripts[i], args)
  end

end

-- Is this even nescessary? Nobody should be requiring this except for 
-- init.lua... However, I'll act like this is required.
return ettercap
