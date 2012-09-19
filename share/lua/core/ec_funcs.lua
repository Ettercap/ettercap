module('ec_funcs', package.seeall)
Ettercap.ec_hooks = {}
Ettercap.scripts = {}

local ettercap = require("ettercap")
local Script = require("ec_script")
local eclib = require("eclib")

-- Simple logging function that maps directly to ui_msg
Ettercap.log = function(str) 
  Ettercap.ffi.C.ui_msg(str)
end

-- This is the cleanup function that gets called.
Ettercap.cleanup = function() 
end

Ettercap.hook_add = function (point, func)
  ettercap.hook_add(point)
  table.insert(Ettercap.ec_hooks, {point, func})
end

Ettercap.dispatch_hook = function (point, po)
  -- We cast the packet into the struct that we want, and then hand it off.
  local s_po = Ettercap.ffi.cast("struct packet_object *", po);
  for key, hook in pairs(Ettercap.ec_hooks) do
    if hook[1] == point then
      hook[2](s_po)
    end
  end
end

-- Processes all the --lua-script arguments into a single list of script
-- names. 
--
-- @param scripts An array of script cli arguments
-- @return A table containing all the split arguments
Ettercap.cli_split_scripts = function (scripts)
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
Ettercap.cli_split_args = function (args)
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

Ettercap.load_script = function (name, args)
  Ettercap.log("loading script: " .. name .. "\n")
  local script = Script.new(name, args)
  -- Adds a hook. Will only run the action if the match rule is nil or 
  -- return true.
  Ettercap.hook_add(script.hook_point, function(po) 
    Ettercap.log(name .. " hook type " .. script.hook_point .. "\n")
    match_rule = script.rules["match_rule"]
    if (not(match_rule == nil)) then
      if not(match_rule(po) == true) then
        return false
      end
    end
    script.action(po)
  end);
  Ettercap.log("loaded script: " .. name .. "\n")
end

Ettercap.main = function (lua_scripts, lua_args)
  local scripts = Ettercap.cli_split_scripts(lua_scripts)
  local args = Ettercap.cli_split_args(lua_args)
  for i = 1, #scripts do
    Ettercap.load_script(scripts[i], args)
  end

end
