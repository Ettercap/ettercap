
/* $Id: ec_conntrack.h,v 1.7 2003/10/27 21:25:44 alor Exp $ */

#ifndef EC_CONNTRACK_H
#define EC_CONNTRACK_H

#include <ec_profiles.h>
#include <ec_connbuf.h>

/* conntrack hook definition */
struct ct_hook_list {
   void (*func)(struct packet_object *po);
   SLIST_ENTRY (ct_hook_list) next;
};

/* conntrack object */
struct conn_object {

   /* last updated (for connection timeout) */
   struct timeval ts;

   /* mac addresses */
   u_int8 L2_addr1[MEDIA_ADDR_LEN];
   u_int8 L2_addr2[MEDIA_ADDR_LEN];
   
   /* ip addresses */
   struct ip_addr L3_addr1;
   struct ip_addr L3_addr2;
   
   /* port numbers */
   u_int16 L4_addr1;
   u_int16 L4_addr2;
   u_int8 L4_proto;

   /* buffered data */
   struct conn_buf data;

   /* byte count since the creation */
   u_int32 xferred;
   
   /* connection status */
   int status;

   /* username and password */
   struct dissector_info DISSECTOR;

   /* hookpoint to receive only packet of this connection */
   SLIST_HEAD(, ct_hook_list) hook_head;
};

enum {
   CONN_IDLE      = 0,
   CONN_OPENING   = 1,
   CONN_OPEN      = 2,
   CONN_ACTIVE    = 3,
   CONN_CLOSING   = 4,
   CONN_CLOSED    = 5,
   CONN_KILLED    = 6,
};

/* exported functions */
extern int conntrack_print(u_int32 spos, u_int32 epos, void (*func)(int n, struct conn_object *co));
extern EC_THREAD_FUNC(conntrack_timeouter); 

extern int conntrack_hook_add(struct packet_object *po, void (*func)(struct packet_object *po));
extern int conntrack_hook_del(struct packet_object *po, void (*func)(struct packet_object *po));

#endif

/* EOF */

// vim:ts=3:expandtab

