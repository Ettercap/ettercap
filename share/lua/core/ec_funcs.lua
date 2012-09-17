module('ec_funcs', package.seeall)
Ettercap.ec_hooks = {}
Ettercap.scripts = {}

local Script = require("ec_script")
local eclib = require("eclib")

-- Simple logging function that maps directly to ui_msg
Ettercap.log = function(str) 
  Ettercap.ffi.C.ui_msg(str)
end

-- This is the cleanup function that gets called.
Ettercap.cleanup = function() 
  Ettercap.log("Cleaning up lua hooks!!\n")
  for key, hook in pairs(Ettercap.ec_hooks) do
    Ettercap.log("Cleaning up a lua hook...\n")
    Ettercap.ffi.C.hook_del(hook[1], hook[2])
    -- Free the callback ?
  end
end

Ettercap.hook_add = function (point, func)
  Ettercap.log("1")
  func_cb = Ettercap.ffi.cast("hook_cb_func", func)
  Ettercap.log("2")
  Ettercap.ffi.C.hook_add(point, func_cb)
  Ettercap.log("3")
  table.insert(Ettercap.ec_hooks, {point, func_cb})
  Ettercap.log("4")
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

Ettercap.main = function (scripts,lua_args)
    Ettercap.lua_args = {}
    arglist = eclib.split(lua_args,",")
    for i = 1, #arglist do 
        temp = eclib.split(arglist[i],"=")
        Ettercap.lua_args[temp[1]] = temp[2]
    end 

    for i = 1, #scripts  do
      Ettercap.load_script(scripts[i],Ettercap.lua_args)
    end
     
end
