#ifndef EC_PROTO_H
#define EC_PROTO_H

#include <pcap.h>
#include <ec_inet.h>


/* interface layer types */

enum {
   IL_TYPE_ETH  =    DLT_EN10MB,
   IL_TYPE_WIFI =    DLT_IEEE802_11,
};
   
/* link layer types */

enum {
   LL_TYPE_IP   = 0x0800,
   LL_TYPE_IP6  = 0x86DD,
   LL_TYPE_ARP  = 0x0806,
};

/* network layer types */

enum {
   NL_TYPE_ICMP  = 0x01,
   NL_TYPE_ICMP6 = 0x3a,
   NL_TYPE_TCP   = 0x06,
   NL_TYPE_UDP   = 0x11,
};

/* proto layer types */

enum {
   PL_DEFAULT  = 0x0000,
};

/* IPv6 options types */
/* NOTE: they may (but should not) conflict with network layer types!   */
/*       double check new definitions of either types.                  */

enum {
   LO6_TYPE_HBH = 0,   /* Hop-By-Hop */
   LO6_TYPE_RT  = 43,  /* Routing */
   LO6_TYPE_FR  = 44,  /* Fragment */
   LO6_TYPE_DST = 60,  /* Destination */
   LO6_TYPE_NO  = 59,  /* No Next Header */
};

#endif

/* EOF */

// vim:ts=3:expandtab

