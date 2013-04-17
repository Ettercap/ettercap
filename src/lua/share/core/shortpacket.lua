--- 
-- Like that of shortport in the nselib, shortpacket is designed to provide a 
-- way to easily generate packetrules.
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
