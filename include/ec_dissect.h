
#ifndef EC_DISSECT_H
#define EC_DISSECT_H

#include <ec_packet.h>
#include <ec_session.h>
#include <ec_decode.h>

/* session identifier */

struct dissect_ident {
   u_int32 magic;
      #define DISSECT_MAGIC  0x0500e77e
   struct ip_addr L3_src;
   struct ip_addr L3_dst;
   u_int8 L4_proto;
   u_int16 L4_src;
   u_int16 L4_dst;
};

/* exported functions */

extern void dissect_add(char *name, u_int8 level, u_int32 port, FUNC_DECODER_PTR(decoder));
extern int dissect_modify(int mode, char *name, u_int32 port);
#define MODE_ADD  0
#define MODE_REP  1

extern int dissect_match(void *id_sess, void *id_curr);
extern void dissect_create_session(struct session **s, struct packet_object *po); 
extern void dissect_wipe_session(struct packet_object *po);
extern void dissect_create_ident(void **i, struct packet_object *po); 

extern int dissect_on_port(char *name, u_int16 port);
   
/*
 * creates the session on the first packet sent from
 * the server (SYN+ACK)
 */

#define CREATE_SESSION_ON_SYN_ACK(name, session) do{        \
      if (dissect_on_port(name, ntohs(PACKET->L4.src)) == ESUCCESS && (PACKET->L4.flags & TH_SYN) && (PACKET->L4.flags & TH_ACK)) { \
         DEBUG_MSG("create_session_on_syn_ack %s", name);   \
         /* create the session */                           \
         dissect_create_session(&session, PACKET);          \
         session_put(session);                              \
         return NULL;                                       \
      }                                                     \
   }while(0)

/*
 * helper macros to get the banner of a service if it is the first thing 
 * the server send to the client.
 * it must be used this way:
 *
 * IF_FIRST_PACKET_FROM_SERVER(21, s, i) {
 * 
 *    ... do something with PACKET->DISSECTOR.banner
 *    
 * } ENDIF_FIRST_PACKET_FROM_SERVER(21, s, i)
 *
 */

#define IF_FIRST_PACKET_FROM_SERVER(name, session, ident)                  \
   if (dissect_on_port(name, ntohs(PACKET->L4.src)) == ESUCCESS && PACKET->L4.flags & TH_PSH) {  \
      dissect_create_ident(&ident, PACKET);                                \
      /* the session exist */                                              \
      if (session_get(&session, ident) != -ENOTFOUND) {                    \
         /* prevent the deletion of session created for the user and pass */ \
         if (session->data == NULL)                                        


#define ENDIF_FIRST_PACKET_FROM_SERVER(session, ident)   \
         if (session->data == NULL)                      \
            session_del(ident);                          \
      }                                                  \
      SAFE_FREE(ident);                                  \
      return NULL;                                       \
   }  


#endif

/* EOF */

// vim:ts=3:expandtab

