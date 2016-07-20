---
-- This is our ettercap FFI interface. Nothing to see, here.
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


local ettercap_ffi = require("ffi")

ettercap_ffi.cdef[[
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

// This is just a hack structure so we can see the first int on the ident
// structures. 
struct ident_magic {
  u_int32 magic;
};

struct ec_session {
   void *ident;
   size_t ident_len;
   void *data;
   size_t data_len;
   int flag;
   /* Used to trace headers for injection */
   struct ec_session *prev_session;
   int (*match)(void *id_sess, void *id);
   void (*free)(void *data, size_t data_len);
};

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
      u_int8 flags;
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
      /* for modified packet this is the delta for the length */
      int delta;  
      size_t inject_len;      /* len of the injection */
      u_char *inject;         /* the fuffer used for injection */

   } DATA;

   size_t fwd_len;         /* length of the packet to be forwarded */
   u_char * fwd_packet;    /* the pointer to the buffer to be forwarded */
   
   size_t len;             /* total length of the packet */
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
   HOOK_RECEIVED     = 0,     /* raw packet, the L* structures are not filled */
   HOOK_DECODED      = 1,     /* all the packet after the protocol stack parsing */
   HOOK_PRE_FORWARD  = 2,     /* right before the forward (if it has to be forwarded) */
   HOOK_HANDLED      = 3,     /* top of the stack but before the decision of PO_INGORE */
   HOOK_FILTER       = 4,     /* the content filtering point */
   HOOK_DISPATCHER   = 5,     /* in the TOP HALF (the packet is a copy) */

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
   HOOK_PACKET_ICMP6_RPLY,
   HOOK_PACKET_ICMP6_PARM,
   HOOK_PACKET_PPPOE,
   HOOK_PACKET_PPP_PAP,
   HOOK_PACKET_MPLS,
   HOOK_PACKET_ERF,
   HOOK_PACKET_ESP,

   /* high level protocol hooks */
   HOOK_PROTO_BASE   = 100,
   HOOK_PROTO_SMB,
   HOOK_PROTO_SMB_CHL,
   HOOK_PROTO_SMB_CMPLT,
   HOOK_PROTO_DHCP_REQUEST,
   HOOK_PROTO_DHCP_DISCOVER,
   HOOK_PROTO_DHCP_PROFILE,
   HOOK_PROTO_DNS,
   HOOK_PROTO_MDNS,
   HOOK_PROTO_NBNS,
   HOOK_PROTO_HTTP,
};

enum {
   E_SUCCESS    = 0,
   E_NOTFOUND   = 1,
   E_NOMATCH    = 2,
   E_NOTHANDLED = 3,
   E_INVALID    = 4,
   E_NOADDRESS  = 5,
   E_DUPLICATE  = 6,
   E_TIMEOUT    = 7,
   E_INITFAIL   = 8,
   E_FOUND      = 128,
   E_BRIDGE     = 129,
   E_VERSION    = 254,
   E_FATAL      = 255,
};

// These are magic constants that ettercap uses to identify the session
// structures.
static const u_int32 IP6_MAGIC =   0x0306e77e;
static const u_int32 IP_MAGIC  =   0x0300e77e;
static const u_int32 TCP_MAGIC =   0x0400e77e;

enum {
  MAX_ASCII_ADDR_LEN = 46
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

char *ip_addr_ntoa(struct ip_addr *sa, char *dst);
uint16_t ntohs(uint16_t netshort);

size_t tcp_create_ident(void **i, struct packet_object *po);            
int tcp_find_direction(void *ids, void *id);
int session_get(struct ec_session **s, void *ident, size_t ident_len);
]]

return ettercap_ffi
