--- Packet manipulation functions
--
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


local ffi = require("ettercap_ffi")
local bit = require('bit')

local addr_buffer_type = ffi.typeof("char[46]")
function ip_to_str(ip_addr)
  local addr_buffer = addr_buffer_type()
  return(ffi.string(ffi.C.ip_addr_ntoa(ip_addr, addr_buffer)))
end

--- Gets the src ip, if any, from the packet.
-- @param packet_object
-- @return string version of IP, or nil
src_ip = function(packet_object)
  local L3 = packet_object.L3
  if L3 and L3.src then
    return ip_to_str(L3.src)
  end
  return nil
end

--- Gets the dst ip, if any, from the packet.
-- @param packet_object
-- @return string version of IP, or nil
dst_ip = function(packet_object)
  local L3 = packet_object.L3
  if L3 and L3.dst then
    return ip_to_str(L3.dst)
  end
  return nil
end

src_port = function(packet_object)
  local L4 = packet_object.L4
  if L4 and L4.src then
    return ffi.C.ntohs(L4.src)
  end
  return nil
end

dst_port = function(packet_object)
  local L4 = packet_object.L4
  if L4 and L4.dst then
    return ffi.C.ntohs(L4.dst)
  end
  return nil
end

--- Returns up to length bytes of the decoded packet DATA section
-- @param packet_object
-- @param length If specified, will return up to that many bytes of the packet
--  data
-- @return string
read_data = function(packet_object, length)
  -- Default to the length of the bytes.
  if (length == nil) then
    length = packet_object.DATA.len
  end
  -- Ensure that we don't read too much data.
  if (length > packet_object.DATA.len) then
    length = packet_object.DATA.len
  end
  return ffi.string(packet_object.DATA.data, length)
end

--- Flags the packet as having been modified.
-- @param packet_object
-- @param integer
set_flag = function(po, flag) po.flags = bit.bor(po.flags, flag) end

set_dropped = function(po) set_flag(po, ffi.C.PO_DROPPED) end
set_modified = function(po) set_flag(po, ffi.C.PO_MODIFIED) end

is_dropped =     function(po) return bit.band(po.flags, ffi.C.PO_DROPPED) end
is_forwardable = function(po) return bit.band(po.flags, ffi.C.PO_FORWARDABLE) end
is_forwarded =   function(po) return bit.band(po.flags, ffi.C.PO_FORWARDED) end
is_from_ssl =    function(po) return bit.band(po.flags, ffi.C.PO_FROMSSL) end
is_modified =    function(po) return bit.band(po.flags, ffi.C.PO_MODIFIED) end
is_ssl_start =   function(po) return bit.band(po.flags, ffi.C.PO_SSLSTART) end

--- Sets the packet data to data, as well as flags the packet as modified.
-- @param packet_object
-- @param data (string) The new data
set_data = function(packet_object, data)
  local len = string.len(data)
  if len > packet_object.DATA.len then
    len = packet_object.DATA.len
  end
  ffi.copy(packet_object.DATA.data, data, string.len(data))
  set_modified(packet_object)
end

--- Inspects the packet to see if it is TCP.
-- @param packet_object
-- @return true or false
is_tcp = function(packet_object)
  return (packet_object.L4 and packet_object.L4.proto == 6)
end

--- Inspects the packet to see if it is UDP.
-- @param packet_object
-- @return true or false
is_udp = function(packet_object)
  return (packet_object.L4 and packet_object.L4.proto == 17)
end

--- Shortcut for telling us if the packet has data (or not)
-- @param packet_object
-- @return true or false
has_data = function(packet_object)
  return (not (packet_object.DATA == nil) and packet_object.DATA.len > 0)
end

-- @return string  like "1.2.3.4:1234 -> 8.8.8.8:53"
l4_summary = function(po)
  return string.format("%s:%s -> %s:%s",
      packet.src_ip(po),
      packet.src_port(po), 
      packet.dst_ip(po), 
      packet.dst_port(po))
end

-- Define all the fun little methods.
local packet = {
  read_data = read_data,
  set_data = set_data,
  is_tcp = is_tcp,
  is_udp = is_udp,

  l4_summary = l4_summary,

  set_dropped = set_dropped,
  set_modified = set_modified,

  is_dropped = is_dropped,
  is_forwardable = is_forwardable,
  is_forwarded = is_forwarded,
  is_from_ssl = is_from_ssl,
  is_modified = is_modified,
  is_ssl_start = is_ssl_start,

  has_data = has_data,
  src_ip = src_ip,
  dst_ip = dst_ip,
  src_port = src_port,
  dst_port = dst_port
}

return packet
