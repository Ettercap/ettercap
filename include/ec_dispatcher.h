
/* $Id: ec_dispatcher.h,v 1.2 2003/09/18 22:15:01 alor Exp $ */

#ifndef EC_DISPATCHER_H
#define EC_DISPATCHER_H

#include <ec_threads.h>
#include <ec_packet.h>

extern void top_half_queue_add(struct packet_object *po);
extern EC_THREAD_FUNC(top_half);

#endif

/* EOF */

// vim:ts=3:expandtab

