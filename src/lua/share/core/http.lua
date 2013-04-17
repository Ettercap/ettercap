--- 
-- Parser and functions for HTTP requests/respnoses
--
-- Created by Ryan Linn and Mike Ryan
-- Copyright (C) 2012 Trustwave Holdings, Inc.

local packet = require("packet")
local hook_points = require("hook_points")
require("ec_string")
require("base64")

local ports = { 80, 443, 8080 }

-- http object that we'll bind all public things to
http = {}
http.hook = hook_points.http

-- parse_post
-- Use: split POST data into k/v pieces and put in a table
-- Args: POST body
-- Out: table of k:v post vars
local function parse_args(argstr)

   if not argstr or argstr == "" then
      return nil
   end
   local args = {}
   kv = split(argstr,'&') 
   for i,val in ipairs(kv) do
      
      local start,finish,k,v = string.find(val, '^(.-)=(.*)')
      if k and v then
         args[k] = v
      end
   end
   return args
end

-- parse_headers 
-- Use: parses the headers into k:v format
-- Args: headers raw string
-- Out: table of k:v headers

local function parse_headers(headers)
   if headers == nil then
      return nil
   end

   local h = {}
   
   for hline in string.gmatch(headers,"(.-)\r?\n") do 

      local spos,epos,k,v = string.find(hline,"^(%S-): (.*)")

      if spos and spos > 0 then
         h[k] = v
      end

   end
   return h
end

http.get_prefix = function (port)
   if port == 80 then
      return "http://"
   elseif port == 443 then
      return "https://"
   elseif port == 8080 then
      return "proxy://"
   else
      return "unknown://"
   end
end

local function parse_auth(auth)
   if not auth  or auth == "" then
      return nil
   end

   local start,finish,auth_type, auth_str = string.find(auth, '^(%S+) (.*)')
   if auth_type == "Basic" then
      return from_base64(auth_str)
   end
   return nil
   
end



-- parse_http 
-- Use: parses a http packet into components
-- Args: raw packet
-- Out: nil if not a request or response
--    table with the following fields:
--       - reqest or response set
--       - for request
--          - verb
--          - url
--          - httpver
--          - post_data (TABLE IF a POST REQUEST)
--          - get_data ( TABLE IF a GET REQUEST)
--       - for post
--          - status_code
--          - status_msg
--          - http_ver
--          
--       - headers
--       - body

http.parse_http = function (pkt)
   local http_body = packet.read_data(pkt)
   local p = {}

   if (http_body == nil) then
      return nil
   end
   local start,finish,header,body = string.find(http_body, '^(.-)\r?\n\r?\n(.*)')


   if (header == nil or body == nil or header == "") then
      return nil
   end
   
   if (starts_with(header,"^GET ") > 0  or starts_with(header,"^HEAD ") > 0  or starts_with(header,"^POST ") > 0  or starts_with(header,"^CONNECT ") > 0 ) then
      local spos,epos, verb, url, httpver = string.find(header,'^(%S+) (.-) HTTP/(%d.%d)')
      p.request= 1
      p.verb = verb
      p.httpver = httpver
      p.headers = parse_headers(header)
      p.body = body
      if p.headers["Host"] then
         p.url = http.get_prefix(packet.dst_port(pkt)) .. p.headers["Host"] .. url
      else
         p.url = http.get_prefix(packet.dst_port(pkt)) .. packet.dst_ip(pkt) .. url
      end

      if p.verb == 'POST' then
         p.post_data = parse_args(body)
      end
     
      local spos,epos,baseurl,args = string.find(p.url,'^(.-)?(.*)')
      if baseurl and args then
         p.baseurl = baseurl
         p.get_data = parse_args(args)
      end 

      if p.headers['Authorization'] then
         p.creds = parse_auth(p.headers['Authorization'])
      end
      
   elseif (starts_with(header,"^HTTP/%d.%d") > 0 ) then
      p.response = 1
      local spos,epos,httpver, code, msg = string.find(header,'^HTTP/(%d.%d) (%d+) (.-)\r?\n')
      p.httpver = httpver
      p.status_code = tonumber(code)
      p.status_msg = msg
      p.headers = parse_headers(header)
      p.body = body
      
   else
      return nil
   end
   return p

end

http.session_id = function (p,msg)
   local session_id = nil

   if msg.request then
      session_id = string.format("%s%d%s%d",packet.src_ip(p),packet.src_port(p),packet.dst_ip(p),packet.dst_port(p))
   elseif msg.response then
      session_id = string.format("%s%d%s%d",packet.dst_ip(p),packet.dst_port(p),packet.src_ip(p),packet.src_port(p))
   end

   return session_id
end

return http
