package.path = package.path .. ";/opt/ettercap/share/ettercap/lib/?.lua"
local bit = require('bit')
require('ec_base')


function split_http(str)
  start,finish,header,body = string.find(str, '(.-\r?\n\r?\n)(.*)')

  return header, body
end

function shrink_http_body(body)
  local modified_body = string.gsub(body, '>%s*<','><')
  return modified_body
end

Ettercap.log("LUA: We are inside ec_helpers.lua!\n")

http_injector = function(po) 
  Ettercap.log("I got the tcp!!!!!\n")
  if (po.DATA.len > 7) then
    local buf = Ettercap.ffi.string(po.DATA.data, 7)
    if (buf == "HTTP/1.") then
      -- Get the full buffer....
      buf = Ettercap.ffi.string(po.DATA.data, po.DATA.len)
      -- Split the header/body up so we can manipulate things.
      header, body = split_http(buf)
      --start,finish,header,body = string.find(buf, '(.-\r?\n\r?\n)(.*)')
      if (not (start == nil)) then
        -- We've got a proper split.
        local orig_body_len = string.len(body)
        Ettercap.log("LUA: Orig body length: " .. orig_body_len .. "\n")
        local modified_body = shrink_http_body(body)
        local delta = orig_body_len - string.len(modified_body)
        -- We've tweaked things, so let's update the data.
        if (delta > 0) then
          Ettercap.log("LUA: We modified the HTTP response!\n")
          modified_body = string.rep(' ', delta) .. modified_body
          local modified_data = header .. modified_body
          Ettercap.ffi.copy(po.DATA.data, modified_data, string.len(modified_data))
          po.flags = bit.bor(po.flags,Ettercap.ffi.C.PO_MODIFIED)
        end
      end
    end
  end
end


Ettercap.log("LUA: Defining a TCP packet hook...\n")
Ettercap.hook_packet_tcp(http_injector)
Ettercap.log("LUA: hooked!\n")

Ettercap.log("LUA: We are at the end of ec_helpers.lua. Though the script " ..
    "will now exit, ettercap will be able to callback into Lua through FFI!\n")
