--- 
-- Like that of shortport in the nselib, shortpacket is designed to provide a 
-- way to easily generate packetrules.

local packet = require("packet")

--- Inspects packet_object.DATA.data to see if it begins with the specified string.
-- @param str (string) 
-- @return function(packet_object)
data_starts_with = function(str)
  len = string.len(str)
  return(function(packet_object)
    return(packet.read_data(packet_object, len) == str)
  end)
end

local shortpacket = {}

shortpacket.data_starts_with = data_starts_with

return shortpacket
