
#ifndef EC_SEND_H
#define EC_SEND_H

#include <ec_packet.h>

extern void send_init(void);
extern void send_close(void);
extern int send_to_L2(struct packet_object *po);
extern int send_to_L3(struct packet_object *po);
extern int send_to_bridge(struct packet_object *po);

#endif

/* EOF */

// vim:ts=3:expandtab

