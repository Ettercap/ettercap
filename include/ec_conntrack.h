
#ifndef EC_CONNTRACK_H
#define EC_CONNTRACK_H

#include <ec_profiles.h>
#include <ec_connbuf.h>

struct conn_object {

   /* last updated (for connection timeout) */
   struct timeval ts;

   /* mac addresses */
   u_int8 L2_addr1[ETH_ADDR_LEN];
   u_int8 L2_addr2[ETH_ADDR_LEN];
   
   /* ip addresses */
   struct ip_addr L3_addr1;
   struct ip_addr L3_addr2;
   
   /* port numbers */
   u_int16 L4_addr1;
   u_int16 L4_addr2;
   u_int8 L4_proto;

   /* buffered data */
   struct conn_buf data;
   
   /* connection status */
   int status;
      #define CONN_IDLE       0
      #define CONN_OPENING    1
      #define CONN_CLOSING    2
      #define CONN_KILLED     3
      #define CONN_ACTIVE     4
      #define CONN_CLOSED     5

   /* username and password */
   struct dissector_info DISSECTOR;
};


#endif

/* EOF */

// vim:ts=3:expandtab

