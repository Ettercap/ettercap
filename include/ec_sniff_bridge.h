
/* $Id: ec_sniff_bridge.h,v 1.2 2003/09/18 22:15:02 alor Exp $ */

#ifndef EC_SNIFF_BRIDGE_H
#define EC_SNIFF_BRIDGE_H

#include <ec_packet.h>

/* exported functions */

extern void start_bridge_sniff(void);
extern void forward_bridge_sniff(struct packet_object *po);


#endif

/* EOF */

// vim:ts=3:expandtab

