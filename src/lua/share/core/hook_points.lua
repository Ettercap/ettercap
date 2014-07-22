---
-- Provides hook point values for those setting up ettercap lua scripts.
--
-- These values are defined in include/ec_hook.h, so this module will need
-- to be updated if that file ever changes!
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

--
-- @module hook_points

--- @usage
local usage = [[
...
hook_point = ettercap.hook_points.tcp
...
]]


local ffi = require("ettercap_ffi")

local hook_points = {}

--- All raw packets, prior to any dissecting.
-- <br/>Defined in include/ec_hook.h as HOOK_RECEIVED
hook_points.packet_received  = ffi.C.HOOK_RECEIVED

--- All packets, after protocol dissecting has been done.
-- <br/>Defined in include/ec_hook.h as HOOK_DECODED
hook_points.protocol_decoded = ffi.C.HOOK_DECODED

--- Packets, just prior to being forwarded (if it has to be forwarded).
-- <br/>Defined in include/ec_hook.h as HOOK_PRE_FORWARD
hook_points.pre_forward      = ffi.C.HOOK_PRE_FORWARD

--- Packets at the top of the stack, but before the decision of PO_INGORE.
-- <br/>Defined in include/ec_hook.h as HOOK_HANDLED
hook_points.handled          = ffi.C.HOOK_HANDLED

--- All packets at the content filtering point.
-- <br/>Defined in include/ec_hook.h as HOOK_FILTER
hook_points.filter           = ffi.C.HOOK_FILTER

--- Packets in the TOP HALF (the packet is a copy).
-- <br/>Defined in include/ec_hook.h as HOOK_DISPATCHER
hook_points.dispatcher       = ffi.C.HOOK_DISPATCHER


--- Any ethernet packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ETH
hook_points.eth           = ffi.C.HOOK_PACKET_ETH

--- Any FDDI packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_FDDI
hook_points.fddi          = ffi.C.HOOK_PACKET_FDDI

--- Any token ring packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_TR
hook_points.token_ring    = ffi.C.HOOK_PACKET_TR

--- Any wifi packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_WIFI
hook_points.wifi          = ffi.C.HOOK_PACKET_WIFI

--- Any ARP packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ARP
hook_points.arp           = ffi.C.HOOK_PACKET_ARP

--- ARP requests.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ARP_RQ
hook_points.arp_request   = ffi.C.HOOK_PACKET_ARP_RQ

--- ARP replies.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ARP_RP
hook_points.arp_reply     = ffi.C.HOOK_PACKET_ARP_RP

--- Any IP packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_IP
hook_points.ip            = ffi.C.HOOK_PACKET_IP

--- Any IPv6 packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_IP6
hook_points.ipv6          = ffi.C.HOOK_PACKET_IP6

--- Any VLAN packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_VLAN
hook_points.vlan          = ffi.C.HOOK_PACKET_VLAN

--- Any UDP packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_UDP
hook_points.udp           = ffi.C.HOOK_PACKET_UDP

--- Any TCP packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_TCP
hook_points.tcp           = ffi.C.HOOK_PACKET_TCP

--- Any ICMP packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ICMP
hook_points.icmp          = ffi.C.HOOK_PACKET_ICMP

--- Any GRE packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_GRE
hook_points.gre           = ffi.C.HOOK_PACKET_GRE

--- Any ICMP6 packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ICMP6
hook_points.icmp6         = ffi.C.HOOK_PACKET_ICMP6

--- ICMP6 Neighbor Discovery packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ICMP6_NSOL
hook_points.icmp6_nsol    = ffi.C.HOOK_PACKET_ICMP6_NSOL

--- ICMP6 Nieghbor Advertisement packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ICMP6_NADV
hook_points.icmp6_nadv    = ffi.C.HOOK_PACKET_ICMP6_NADV

--- PPP link control protocol packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_LCP
hook_points.lcp           = ffi.C.HOOK_PACKET_LCP

--- PPP encryption control protocol packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_ECP
hook_points.ecp           = ffi.C.HOOK_PACKET_ECP

--- PPP IP control protocol packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_IPCP
hook_points.ipcp          = ffi.C.HOOK_PACKET_IPCP

--- Any PPP packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PACKET_PPP
hook_points.ppp           = ffi.C.HOOK_PACKET_PPP

--- Any ESP packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_ESP
hook_points.esp          = ffi.C.HOOK_PACKET_ESP

--- Any SMB packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_SMB
hook_points.smb           = ffi.C.HOOK_PROTO_SMB

--- SMB challenge packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_SMB_CHL
hook_points.smb_challenge = ffi.C.HOOK_PROTO_SMB_CHL

--- SMB negotiation complete.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_SMB_CMPLT
hook_points.smb_complete  = ffi.C.HOOK_PROTO_SMB_CMPLT

--- DHCP request packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_DHCP_REQUEST
hook_points.dhcp_request  = ffi.C.HOOK_PROTO_DHCP_REQUEST

--- DHCP discovery packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_DHCP_DISCOVER
hook_points.dhcp_discover = ffi.C.HOOK_PROTO_DHCP_DISCOVER

--- Any DNS packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_DNS
hook_points.dns           = ffi.C.HOOK_PROTO_DNS

--- Any NBNS packet.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_NBNS
hook_points.nbns          = ffi.C.HOOK_PROTO_NBNS

--- *Some* HTTP packets.
-- <br/>Defined in include/ec_hook.h as HOOK_PROTO_HTTP
-- See src/dissectors/ec_http.c.
hook_points.http          = ffi.C.HOOK_PROTO_HTTP

-- Commented out.. Unsure if this should ever be exposed to LUA...
-- dhcp_profile = ffi.C.HOOK_PROTO_DHCP_PROFILE, -- DHCP profile ?

return hook_points
