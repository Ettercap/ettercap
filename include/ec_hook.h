
#ifndef EC_HOOK_H
#define EC_HOOK_H

#include <ec_packet.h>

void hook_point(int point, struct packet_object *po);
   #define HOOK_RECEIVED      0     /* raw packet, the L* structures are not filled */
   #define HOOK_DECODED       1     /* all the packet after the protcol stack */
   #define HOOK_PRE_FORWARD   2     /* right before the forward (if it has to be forwarded) */
   #define HOOK_HANDLED       3     /* top of the stack but before the decision of PO_INGORE */
   #define HOOK_FILTER        4     /* the content filtering point */
   #define HOOK_DISPATCHER    5     /* in the TOP HALF (the packet is a copy) */

void hook_add(int point, void (*func)(struct packet_object *po) );
int hook_del(int point, void (*func)(struct packet_object *po) );

#endif

/* EOF */

// vim:ts=3:expandtab

