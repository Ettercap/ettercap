
/* $Id: ec_sniff_bridge.h,v 1.4 2004/03/31 13:03:08 alor Exp $ */

#ifndef EC_SNIFF_BRIDGE_H
#define EC_SNIFF_BRIDGE_H

#include <ec_packet.h>

/* exported functions */

extern void start_bridge_sniff(void);
extern void stop_bridge_sniff(void);
extern void forward_bridge_sniff(struct packet_object *po);
extern void bridge_check_forwarded(struct packet_object *po);
extern void bridge_set_forwardable(struct packet_object *po);

#endif

/* EOF */

// vim:ts=3:expandtab

