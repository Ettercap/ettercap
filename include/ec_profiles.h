
#ifndef EC_PROFILES_H
#define EC_PROFILES_H

#include <ec_fingerprint.h>

struct dissector_info {
   char *user;
   char *pass;
   char *info;
   char *banner;
};


/* the list of users for each port */
struct user {
   char *user;
   char *pass;
   char *info;
   LIST_ENTRY(user) next;
};

/* each port is indentified this way : */

struct open_port {
   u_int16 L4_addr;
   u_int8  L4_proto;
   /* the service banner */
   char *banner;
   
   /* the list of users */
   LIST_HEAD(, user) users_head;
   
   LIST_ENTRY(open_port) next;
};


/* this contains all the info related to an host */

struct host_profile {
   
   u_int8 L2_addr[ETH_ADDR_LEN];

   struct ip_addr L3_addr;

   /* the list of open ports */
   LIST_HEAD(, open_port) open_ports_head;
   
   /* distance in hop (TTL) */
   u_int8 distance;
   /* local or not ? */
   u_int8 type;

   /* OS fingerprint */
   u_char finger[FINGER_LEN+1];

   LIST_ENTRY(host_profile) next;
};

/* forward the declaration */
struct packet_object;

extern int profile_add(struct packet_object *po);


#endif

/* EOF */

// vim:ts=3:expandtab

