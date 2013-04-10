---
--
-- Created by Ryan Linn and Mike Ryan
-- Copyright (C) 2012 Trustwave Holdings, Inc.

description = "Script to show HTTP requsts";

local http = require("http")
local packet = require("packet")
local bin = require("bit")

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

   -- Get out session key for tracking req->reply pairs
   local session_id = http.session_id(p,hobj)

   -- If we can't track sessions, this won't work, get out
   if session_id == nil then
      return
   end

   -- We have a session, lets get our registry space
   local reg = ettercap.reg.create_namespace(session_id)

   -- If it's a request, save the request to the registry
   -- We'll need this for the response
   if hobj.request then 
      reg.request = hobj
   
   -- we have a response object, let't put the log together
   elseif hobj.response then

      -- If we haven't seen the request, we don't have anything to share
      if not reg.request then
         return
      end

      -- Get the status code
      local code = hobj.status_code

      -- Build the request URL

      -- If we have a 2XX or 4XX or 5XX code, we won't need to log redirect
      -- so just log the request and code
      if code >= 200 and code < 300 or code >= 400 then
         ettercap.log("HTTP_REQ: %s:%d -> %s:%d %s %s %d (%s)\n",
            packet.dst_ip(p),
            packet.dst_port(p), 
            packet.src_ip(p), 
            packet.src_port(p), 
            reg.request.verb ,reg.request.url , hobj.status_code, hobj.status_msg)

      -- These codes require redirect, so log the redirect as well 
      elseif code >= 300 and code <= 303 then
         local redir = ""

         -- Get the redirect location
         if hobj.headers["Location"] then
            redir = hobj.headers["Location"]
         end

         -- Log the request/response with the redirect
         ettercap.log("HTTP_REQ: %s:%d -> %s:%d %s %s -> %s  %d (%s)\n",
            packet.dst_ip(p),
            packet.dst_port(p), 
            packet.src_ip(p), 
            packet.src_port(p), 
            reg.request.verb ,reg.request.url, redir, hobj.status_code, hobj.status_msg)
      end

   end
end
