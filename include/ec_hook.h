
/* $Id: ec_hook.h,v 1.9 2003/10/16 16:46:48 alor Exp $ */

#ifndef EC_HOOK_H
#define EC_HOOK_H

#include <ec_packet.h>

void hook_point(int point, struct packet_object *po);
   #define HOOK_RECEIVED      0     /* raw packet, the L* structures are not filled */
   #define HOOK_DECODED       1     /* all the packet after the protocol stack parsing */
   #define HOOK_PRE_FORWARD   2     /* right before the forward (if it has to be forwarded) */
   #define HOOK_HANDLED       3     /* top of the stack but before the decision of PO_INGORE */
   #define HOOK_FILTER        4     /* the content filtering point */
   #define HOOK_DISPATCHER    5     /* in the TOP HALF (the packet is a copy) */

   /* these are used the hook received packets */
   #define HOOK_PACKET_BASE      50
   #define HOOK_PACKET_ETH       (HOOK_PACKET_BASE + 1)
   #define HOOK_PACKET_WIFI      (HOOK_PACKET_BASE + 2)
   #define HOOK_PACKET_ARP       (HOOK_PACKET_BASE + 3)
   #define HOOK_PACKET_ARP_RQ    (HOOK_PACKET_BASE + 4)
   #define HOOK_PACKET_ARP_RP    (HOOK_PACKET_BASE + 5)
   #define HOOK_PACKET_IP        (HOOK_PACKET_BASE + 6)
   #define HOOK_PACKET_IP6       (HOOK_PACKET_BASE + 7)
   #define HOOK_PACKET_UDP       (HOOK_PACKET_BASE + 8)
   #define HOOK_PACKET_TCP       (HOOK_PACKET_BASE + 9)
   #define HOOK_PACKET_ICMP      (HOOK_PACKET_BASE + 10)

   /* high level protocol hooks */
   #define HOOK_PROTO_BASE       100
   #define HOOK_PROTO_SMB        (HOOK_PROTO_BASE + 1)		
   #define HOOK_PROTO_SMB_CHL    (HOOK_PROTO_BASE + 2)		
   #define HOOK_PROTO_DHCP       (HOOK_PROTO_BASE + 3)		

void hook_add(int point, void (*func)(struct packet_object *po) );
int hook_del(int point, void (*func)(struct packet_object *po) );

#endif

/* EOF */

// vim:ts=3:expandtab

