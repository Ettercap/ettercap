#ifndef ETTERCAP_SESSION_TCP_H_37E6D2A38D0944B2BD367F7473EC7936
#define ETTERCAP_SESSION_TCP_H_37E6D2A38D0944B2BD367F7473EC7936

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


EC_API_EXTERN size_t tcp_create_ident(void **i, struct packet_object *po);            
EC_API_EXTERN int tcp_find_direction(void *ids, void *id);


#endif

/* EOF */

// vim:ts=3:expandtab

