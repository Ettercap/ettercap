module('ec_funcs', package.seeall)
Ettercap.ec_hooks = {}

-- Simple logging function that maps directly to ui_msg
Ettercap.log = function(str) 
  Ettercap.ffi.C.ui_msg(str)
end

-- This is the cleanup function that gets called.
Ettercap.cleanup = function() 
  Ettercap.log("Cleaning up lua hooks!!\n")
  for key, hook in pairs(Ettercap.ec_hooks) do
    Ettercap.log("Cleaning up a lua hook...\n")
    Ettercap.ffi.C.hook_del(hook[1], hook[2])
    -- Free the callback ?
  end
end

Ettercap.hook_add = function (point, func)
  Ettercap.log("1")
  func_cb = Ettercap.ffi.cast("hook_cb_func", func)
  Ettercap.log("2")
  Ettercap.ffi.C.hook_add(point, func_cb)
  Ettercap.log("3")
  table.insert(Ettercap.ec_hooks, {point, func_cb})
  Ettercap.log("4")
end

Ettercap.hook_packet_eth = 
  function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ETH, func) end
Ettercap.hook_packet_fddi = 
  function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_FDDI, func) end
Ettercap.hook_packet_tr = 
  function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_TR, func) end
Ettercap.hook_packet_wifi = 
  function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_WIFI, func) end
Ettercap.hook_packet_arp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ARP, func) end
Ettercap.hook_packet_arp_rq =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ARP_RQ, func) end
Ettercap.hook_packet_arp_rp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ARP_RP, func) end
Ettercap.hook_packet_ip =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_IP, func) end
Ettercap.hook_packet_ip6 =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_IP6, func) end
Ettercap.hook_packet_udp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_UDP, func) end
Ettercap.hook_packet_tcp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_TCP, func) end
Ettercap.hook_packet_icmp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ICMP, func) end
Ettercap.hook_packet_lcp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_LCP, func) end
Ettercap.hook_packet_ecp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ECP, func) end
Ettercap.hook_packet_ipcp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_IPCP, func) end
Ettercap.hook_packet_ppp =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_PPP, func) end
Ettercap.hook_packet_gre =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_GRE, func) end
Ettercap.hook_packet_vlan =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_VLAN, func) end
Ettercap.hook_packet_icmp6 =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ICMP6, func) end
Ettercap.hook_packet_icmp6_nsol =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ICMP6_NSOL, func) end
Ettercap.hook_packet_icmp6_nadv =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PACKET_ICMP6_NADV, func) end
Ettercap.hook_proto_smb =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_SMB, func) end
Ettercap.hook_proto_smb_chl =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_SMB_CHL, func) end
Ettercap.hook_proto_smb_cmplt =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_SMB_CMPLT, func) end
Ettercap.hook_proto_dhcp_request =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_DHCP_REQUEST, func) end
Ettercap.hook_proto_dhcp_discover =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_DHCP_DISCOVER, func) end
Ettercap.hook_proto_dhcp_profile =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_DHCP_PROFILE, func) end
Ettercap.hook_proto_dns =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_DNS, func) end
Ettercap.hook_proto_nbns =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_NBNS, func) end
Ettercap.hook_proto_http =
   function(func) Ettercap.hook_add(Ettercap.ffi.C.HOOK_PROTO_HTTP, func) end


function split_http(str)
  start,finish,header,body = string.find(str, '(.-\r?\n\r?\n)(.*)')

  return header, body
end

function shrink_http_body(body)
  local modified_body = string.gsub(body, '>%s*<','><')
  return modified_body
end
