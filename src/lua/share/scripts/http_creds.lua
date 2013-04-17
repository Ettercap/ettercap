---
--
-- Created by Ryan Linn and Mike Ryan
-- Copyright (C) 2012 Trustwave Holdings, Inc.

description = "Script to show HTTP requsts";

local http = require("http")
local packet = require("packet")

hook_point = http.hook 

packetrule = function(packet_object)

   -- If this isn't a tcp packet, it's not really a HTTP request
   -- since we're hooked in the HTTP dissector, we can assume that this
   -- should never fail, but it's a good sanity check
  if packet.is_tcp(packet_object) == false then
    return false
  end

  return true
end



-- Here's your action.
action = function(packet_object) 
   local p = packet_object
   
   -- Parse the http data into an HTTP object
   local hobj = http.parse_http(p)

   -- If there's no http object, get out
   if hobj == nil then
      return
   end

   -- If it's a request, save the request to the registry
   -- We'll need this for the response
   if hobj.request then 
      if hobj.creds then
       
         -- Log the request/response with the redirect
         ettercap.log("HTTP_CREDS: %s:%d -> %s:%d %s %s [User:Pass = %s]\n",
            packet.src_ip(p),
            packet.src_port(p), 
            packet.dst_ip(p), 
            packet.dst_port(p), 
            hobj.verb ,hobj.url, hobj.creds)
      end

   end
end
