
/* $Id: ec_inject.h,v 1.2 2003/09/18 22:15:01 alor Exp $ */

#ifndef EC_INJECT_H
#define EC_INJECT_H

#include <ec_packet.h>

extern int inject_buffer(struct packet_object *po, u_int8 buf, size_t len);
extern int inject_po(struct packet_object *po);
extern void inject_chain_free(struct packet_object *po);

#endif

/* EOF */

// vim:ts=3:expandtab

