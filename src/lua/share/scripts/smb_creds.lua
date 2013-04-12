---
--
-- Created by Ryan Linn and Mike Ryan
-- Copyright (C) 2012 Trustwave Holdings, Inc.

description = "Script to show SMB creds";

local packet = require("packet")
local hook_points = require("hook_points")

hook_point = hook_points.ip

packetrule = function(packet_object)

   -- If this isn't a tcp packet, it's not really a HTTP request
   -- since we're hooked in the HTTP dissector, we can assume that this
   -- should never fail, but it's a good sanity check

  return true 


end



-- Here's your action.
action = function(packet_object) 
   local p = packet_object
   
   local data = packet.read_data(p)
   ettercap.log("DATA: %s\n",data)
         -- Log the request/response with the redirect
         --ettercap.log("HTTP_CREDS: %s:%d -> %s:%d %s %s [User:Pass = %s]\n",
            --packet.src_ip(p),
            --packet.src_port(p), 
            --packet.dst_ip(p), 
            --packet.dst_port(p), 
            --hobj.verb ,hobj.url, hobj.creds)
end
