
#ifndef EC_DISSECT_H
#define EC_DISSECT_H

#include <ec_packet.h>
#include <ec_session.h>

/* session identifier */

struct dissect_ident {
   struct ip_addr L3_src;
   struct ip_addr L3_dst;
   u_int8 L4_proto;
   u_int16 L4_src;
   u_int16 L4_dst;
};

/* exported functions */

extern int dissect_match(void *id_sess, void *id_curr);
extern void dissect_create_session(struct session **s, struct packet_object *po); 
extern void dissect_create_ident(void **i, struct packet_object *po); 

#endif

/* EOF */

// vim:ts=3:expandtab

