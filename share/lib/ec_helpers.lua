
local bit = require('bit')

Ettercap = {}
Ettercap.ffi = require("ffi")
Ettercap.ffi.cdef[[
typedef unsigned char u_int8_t;
typedef unsigned char u_char;
typedef unsigned short int u_int16_t;
typedef unsigned int u_int32_t;
typedef unsigned long int u_int64_t;

typedef char int8_t;
typedef short int int16_t;
typedef int int32_t;
typedef long int int64_t;

typedef int8_t    int8;
typedef int16_t   int16;
typedef int32_t   int32;
typedef int64_t   int64;

typedef u_int8_t   u_int8;
typedef u_int16_t  u_int16;
typedef u_int32_t  u_int32;
typedef u_int64_t  u_int64;

struct ip_addr {
   u_int16 addr_type;
   u_int16 addr_len;
   /* this must be aligned in memory */
   u_int8 addr[16];
};

struct passive_info {
   char fingerprint[29];
   char flags;
};

struct dissector_info {
   char *user;
   char *pass;
   char *info;
   char *banner;
   char failed;
};

struct timeval {
  long int tv_sec;
  long int tv_usec;
};

struct packet_object {
 
   /* timestamp of the packet */
   struct timeval ts;
   
   struct L2 {
      u_int8 proto;
      u_char * header;
      size_t len;
      u_int8 src[6];
      u_int8 dst[6];
   } L2;
   
   struct L3 {
      u_int16 proto;
      u_char * header;
      u_char * options;
      size_t len;
      size_t payload_len;
      size_t optlen;
      struct ip_addr src;
      struct ip_addr dst;
      u_int8 ttl;
   } L3;
   
   struct L4 {
      u_int8 proto;
      u_int8 flags;
      u_char * header;
      u_char * options;
      size_t len;
      size_t optlen;
      u_int16 src;
      u_int16 dst;
      u_int32 seq;
      u_int32 ack;
   } L4;
   
   struct data {
      u_char * data;
      size_t len;
      /* 
       * buffer containing the data to be displayed.
       * some dissector decripts the traffic, but the packet must be forwarded as
       * is, so the decripted data must be placed in a different buffer. 
       * this is that bufffer and it is malloced by tcp or udp dissector.
       */
      size_t disp_len;
      u_char * disp_data;
      /* for modified packet this is the delta for the lenght */
      int delta;  
      size_t inject_len;      /* len of the injection */
      u_char *inject;         /* the fuffer used for injection */

   } DATA;

   size_t fwd_len;         /* lenght of the packet to be forwarded */
   u_char * fwd_packet;    /* the pointer to the buffer to be forwarded */
   
   size_t len;             /* total lenght of the packet */
   u_char * packet;        /* the buffer containing the real packet */

   /* Trace current session for injector chain */
   struct ec_session *session;  
    
   
   u_int16 flags;                       /* flags relative to the packet */
   
   /* 
    * here are stored the user and pass collected by dissectors 
    * the "char *" are malloc(ed) by dissectors
    */
   struct dissector_info DISSECTOR;
  
   /* the struct for passive identification */
   struct passive_info PASSIVE;
   
};

enum {
   HOOK_PACKET_BASE  = 50,
   HOOK_PACKET_ETH,
   HOOK_PACKET_FDDI,      
   HOOK_PACKET_TR,
   HOOK_PACKET_WIFI,
   HOOK_PACKET_ARP,
   HOOK_PACKET_ARP_RQ,
   HOOK_PACKET_ARP_RP,
   HOOK_PACKET_IP,
   HOOK_PACKET_IP6,
   HOOK_PACKET_UDP,
   HOOK_PACKET_TCP,
   HOOK_PACKET_ICMP,
   HOOK_PACKET_LCP,
   HOOK_PACKET_ECP,
   HOOK_PACKET_IPCP,
   HOOK_PACKET_PPP,
   HOOK_PACKET_GRE,
   HOOK_PACKET_VLAN,
   HOOK_PACKET_ICMP6,
   HOOK_PACKET_ICMP6_NSOL,
   HOOK_PACKET_ICMP6_NADV,

   /* high level protocol hooks */
   HOOK_PROTO_BASE   = 100,
   HOOK_PROTO_SMB,
   HOOK_PROTO_SMB_CHL,
   HOOK_PROTO_SMB_CMPLT,
   HOOK_PROTO_DHCP_REQUEST,
   HOOK_PROTO_DHCP_DISCOVER,
   HOOK_PROTO_DHCP_PROFILE,
   HOOK_PROTO_DNS,
   HOOK_PROTO_NBNS,
   HOOK_PROTO_HTTP,
};


static const u_int16 PO_IGNORE      = 1;        /* this packet should not be processed (e.g. sniffing TARGETS didn't match it) */
static const u_int16 PO_DONT_DISSECT= 1<<1;     /* this packet should not be processed by dissector (used during the arp scan) */
static const u_int16 PO_FORWARDABLE = 1<<2;     /* the packet has our MAC address, by the IP is not ours */
static const u_int16 PO_FORWARDED   = 1<<3;     /* the packet was forwarded by us */
static const u_int16 PO_FROMIFACE   = 1<<4;    /* this packet comes from the primary interface */
static const u_int16 PO_FROMBRIDGE  = 1<<5;    /* this packet comes form the bridged interface */
static const u_int16 PO_MODIFIED    = 1<<6;    /* it needs checksum recalculation before forwarding */
static const u_int16 PO_DROPPED     = 1<<7;    /* the packet has to be dropped */
static const u_int16 PO_DUP         = 1<<8;    /* the packet is a duplicate we have to free the buffer on destroy */
static const u_int16 PO_FORGED      = 1<<9;    /* the packet is created by ourselves */
static const u_int16 PO_EOF         = 1<<10;     /* we are reading from a file and this is the last packet */
static const u_int16 PO_FROMSSL     = 1<<11;    /* the packet is coming from a ssl wrapper */
static const u_int16 PO_SSLSTART    = 1<<12;   /* ssl wrapper has to enter SSL state */

void ui_msg(const char *fmt, ...);
typedef void (__stdcall *hook_cb_func)(struct packet_object *po);
void hook_add(int point, hook_cb_func);
int hook_del(int point, hook_cb_func );
]]


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
  func_cb = Ettercap.ffi.cast("hook_cb_func", func)
  Ettercap.ffi.C.hook_add(point, func_cb)
  table.insert(Ettercap.ec_hooks, {point, func_cb})
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

Ettercap.log("LUA: We are inside ec_helpers.lua!\n")

http_injector = function(po) 
  Ettercap.log("I got the tcp!!!!!\n")
  if (po.DATA.len > 7) then
    local buf = Ettercap.ffi.string(po.DATA.data, 7)
    if (buf == "HTTP/1.") then
      -- Get the full buffer....
      buf = Ettercap.ffi.string(po.DATA.data, po.DATA.len)
      -- Split the header/body up so we can manipulate things.
      header, body = split_http(buf)
      --start,finish,header,body = string.find(buf, '(.-\r?\n\r?\n)(.*)')
      if (not (start == nil)) then
        -- We've got a proper split.
        local orig_body_len = string.len(body)
        Ettercap.log("LUA: Orig body length: " .. orig_body_len .. "\n")
        local modified_body = shrink_http_body(body)
        local delta = orig_body_len - string.len(modified_body)
        -- We've tweaked things, so let's update the data.
        if (delta > 0) then
          Ettercap.log("LUA: We modified the HTTP response!\n")
          modified_body = string.rep(' ', delta) .. modified_body
          local modified_data = header .. modified_body
          Ettercap.ffi.copy(po.DATA.data, modified_data, string.len(modified_data))
          po.flags = bit.bor(po.flags,Ettercap.ffi.C.PO_MODIFIED)
        end
      end
    end
  end
end


Ettercap.log("LUA: Defining a TCP packet hook...\n")
Ettercap.hook_packet_tcp(http_injector)
Ettercap.log("LUA: hooked!\n")

Ettercap.log("LUA: We are at the end of ec_helpers.lua. Though the script " ..
    "will now exit, ettercap will be able to callback into Lua through FFI!\n")
