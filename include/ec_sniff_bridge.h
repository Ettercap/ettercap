
/* $Id: ec_sniff_bridge.h,v 1.3 2003/12/13 18:41:10 alor Exp $ */

#ifndef EC_SNIFF_BRIDGE_H
#define EC_SNIFF_BRIDGE_H

#include <ec_packet.h>

/* exported functions */

extern void start_bridge_sniff(void);
extern void stop_bridge_sniff(void);
extern void forward_bridge_sniff(struct packet_object *po);


#endif

/* EOF */

// vim:ts=3:expandtab

