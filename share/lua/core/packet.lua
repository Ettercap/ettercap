--- Packet manipulation functions

local ffi = require("ettercap_ffi")
local bit = require('bit')

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
set_modified = function(packet_object)
  packet_object.flags = bit.bor(packet_object.flags, ffi.C.PO_MODIFIED)
end

--- Sets the packet data to data, as well as flags the packet as modified.
-- @param packet_object
-- @param data (string) The new data
set_data = function(packet_object, data)
  ffi.copy(packet_object.DATA.data, data, string.len(data))
  set_modified(packet_object)
end

--- Inspects the packet to see if it is TCP.
-- @param packet_object
-- @return true or false
is_tcp = function(packet_object)
  if not packet_object.L3 then
    return false
  end
  if not packet_object.L3.proto == 6 then
    return false
  end
  return true
end


-- Define all the fun little methods.
local packet = {
  read_data = read_data,
  set_modified = set_modified,
  set_data = set_data,
  is_tcp = is_tcp
}

return packet
