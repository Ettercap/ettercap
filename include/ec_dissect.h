
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

/*
 * creates the session on the first packet sent from
 * the server (SYN+ACK)
 */

#define CREATE_SESSION_ON_SYN_ACK(port, session) do{ \
      if (ntohs(PACKET->L4.src) == port && PACKET->L4.flags & TH_SYN && PACKET->L4.flags & TH_ACK) { \
         /* create the session */                     \
         dissect_create_session(&session, PACKET);    \
         session_put(session);                        \
         return NULL;                                 \
      }                                               \
   }while(0)

/*
 * helper macros to get the banner of a service if it is the first thing 
 * the server send to the client.
 * the must be used this way:
 *
 * IF_FIRST_PACKET_FROM_SERVER(21, s, i) {
 * 
 *    ... do something with PACKET->DISSECTOR.banner
 *    
 * } ENDIF_FIRST_PACKET_FROM_SERVER(21, s, i)
 *
 */

#define IF_FIRST_PACKET_FROM_SERVER(port, session, ident) \
   if (ntohs(PACKET->L4.src) == port && PACKET->L4.flags & TH_PSH) {  \
      dissect_create_ident(&ident, PACKET);                          \
      /* the session exist */                                        \
      if (session_get(&session, ident) != -ENOTFOUND) {                    \
         /* prevent to delete the session created for the user and pass */ \
         if (session->data == NULL)                                        


#define ENDIF_FIRST_PACKET_FROM_SERVER(port, session, ident)   \
         if (session->data == NULL)                            \
            session_del(ident);                                \
      }                                                        \
      SAFE_FREE(ident);                                        \
      return NULL;                                             \
   }  


#endif

/* EOF */

// vim:ts=3:expandtab

