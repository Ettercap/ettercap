---
-- Basic ettercap functionality!
--
-- Created by Ryan Linn and Mike Ryan
-- Copyright (C) 2012 Trustwave Holdings, Inc.
-- 


-- All of our core stuff will reside in the "ettercap" namespace.
ettercap = {}

local ffi = require("ettercap_ffi")
local ettercap_c = require("ettercap_c")
local eclib = require("eclib")
ettercap.reg = require("ettercap_reg")

--- Log's a message using ettercap's ui_msg function.
-- @see string.format
-- @param fmt The format string
-- @param ... Variable arguments to pass in
log = function(fmt, ...) 
  -- We don't want any format string "accidents" on the C side of things.. 
  -- so, we will let lua handle it.
  ettercap_c.log(string.format(fmt, ...))
end

require('dumper')

--- Dumps data structure(s) to log
-- @param ... The data to dump!
dump = function (...)
  log(DataDumper(...), "\n---")
end


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
--    packetrule  - (function (packet_object)) If implemented, then this 
--                  function must return true for a given packet_object 
--                  before that packet_object is passed to the script's action.
--

local Script = {}

do
  local coroutine = require "coroutine";
  local debug = require "debug";
  local traceback = debug.traceback;

  local ETTERCAP_SCRIPT_RULES = {
    packetrule = "packetrule",
  };

  -- These are the components of a script that are required. 
  local REQUIRED_FIELDS = {
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
      log("Failed to load %s:\n%s", filename, traceback(co, e));
      --error("could not load script");
      return nil
    end

    for required_field_name in pairs(REQUIRED_FIELDS) do
      local required_type = REQUIRED_FIELDS[required_field_name];
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

-- Stores hook mappings.
--- Called during ettercap's shutdown
local ettercap_cleanup = function() 
end

local packet_object_ctype = ffi.typeof("struct packet_object *")
local ffi_cast = ffi.cast

local create_hook = function(script)
  local packetrule = script.rules["packetrule"]
  local hook_func = function(packet_object_ptr) 
    local packet_object = ffi_cast(packet_object_ctype, packet_object_ptr);
    if (not(packetrule == nil)) then
      if not(packetrule(packet_object) == true) then
        return false
      end
    end
    script.action(packet_object)
  end
  return(hook_func)
end

-- Adds a hook
local hook_add = function (hook_point, func)
  ettercap_c.hook_add(hook_point, func)
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
local ettercap_load_script = function (name, args)
  local script = Script.new(name, args)
  hook_add(script.hook_point, create_hook(script))
end

-- Primary entry point for ettercap lua environment
-- @param lua_scripts Array of CLI script strings
-- @param lua_args Array of CLI argument strings
local ettercap_main = function (lua_scripts, lua_args)
  local scripts = cli_split_scripts(lua_scripts)
  local args = cli_split_args(lua_args)
  for i = 1, #scripts do
    ettercap_load_script(scripts[i], args)
  end
end

-- C -> LUA api functions. These should never be called from scripts!
ettercap.main = ettercap_main
ettercap.cleanup = ettercap_cleanup

-- Global functions

ettercap.log = log
ettercap.dump = dump

-- Is this even nescessary? Nobody should be requiring this except for 
-- init.lua... However, I'll act like this is required.
return ettercap
