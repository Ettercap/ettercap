
/* $Id: ec_inject.h,v 1.3 2003/09/27 09:53:33 alor Exp $ */

#ifndef EC_INJECT_H
#define EC_INJECT_H

#include <ec_packet.h>

extern int inject_buffer(struct packet_object *po, u_int8 buf, size_t len);
extern int inject_po(struct packet_object *po);

#endif

/* EOF */

// vim:ts=3:expandtab

