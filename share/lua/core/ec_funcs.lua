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
