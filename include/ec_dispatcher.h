#ifndef ETTERCAP_DISPATCHER_H_B5E8A31B628C47F68AE26160289ABB39
#define ETTERCAP_DISPATCHER_H_B5E8A31B628C47F68AE26160289ABB39

#include <ec_threads.h>
#include <ec_packet.h>

EC_API_EXTERN void top_half_queue_add(struct packet_object *po);
EC_API_EXTERN EC_THREAD_FUNC(top_half);

#endif

/* EOF */

// vim:ts=3:expandtab

