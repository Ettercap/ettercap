
/* $Id: ec_hook.h,v 1.6 2003/09/18 22:15:01 alor Exp $ */

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
   #define PACKET_BASE        50
   #define PACKET_ETH         (PACKET_BASE+1)
   #define PACKET_WIFI        (PACKET_BASE+2)
   #define PACKET_ARP         (PACKET_BASE+3)
   #define PACKET_ARP_RQ      (PACKET_BASE+4)
   #define PACKET_ARP_RP      (PACKET_BASE+5)
   #define PACKET_IP          (PACKET_BASE+6)
   #define PACKET_IP6         (PACKET_BASE+7)
   #define PACKET_UDP         (PACKET_BASE+8)
   #define PACKET_TCP         (PACKET_BASE+9)
   #define PACKET_ICMP        (PACKET_BASE+10)

void hook_add(int point, void (*func)(struct packet_object *po) );
int hook_del(int point, void (*func)(struct packet_object *po) );

#endif

/* EOF */

// vim:ts=3:expandtab

