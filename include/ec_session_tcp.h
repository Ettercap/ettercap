
/* $Id: ec_session_tcp.h,v 1.1 2004/03/03 21:43:19 alor Exp $ */

#ifndef EC_SESSION_TCP_H
#define EC_SESSION_TCP_H

/* Session data structure */
struct tcp_half_status {
   u_int32  last_seq;
   u_int32  last_ack;
   int32    seq_adj;
   u_char   injectable;
#define INJ_FIN 1
#define INJ_FWD 2
};

struct tcp_status {
   struct tcp_half_status way[2];
};


extern size_t tcp_create_ident(void **i, struct packet_object *po);            
extern int tcp_find_direction(void *ids, void *id);


#endif

/* EOF */

// vim:ts=3:expandtab

