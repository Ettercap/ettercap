
/* $Id: ec_inet.h,v 1.8 2003/09/18 22:15:01 alor Exp $ */

#ifndef EC_INET_H
#define EC_INET_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

enum {
   NS_IN6ADDRSZ            = 16,
   NS_INT16SZ              = 2,

   ETH_ADDR_LEN            = 6,
   IP_ADDR_LEN             = 4,
   IP6_ADDR_LEN            = 16,
   MAX_ADDR_LEN            = IP6_ADDR_LEN,

   ETH_ASCII_ADDR_LEN      = sizeof("ff:ff:ff:ff:ff:ff")+1,
   IP_ASCII_ADDR_LEN       = sizeof("255.255.255.255")+1,
   IP6_ASCII_ADDR_LEN      = sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")+1,
   MAX_ASCII_ADDR_LEN      = IP6_ASCII_ADDR_LEN,                  
};

/* this structure is used by ettercap to handle an IP
 * disregarding the version */
struct ip_addr {
   u_int8 type;
   u_int8 addr_size;
   char addr[MAX_ADDR_LEN];
};

extern int ip_addr_init(struct ip_addr *sa, int type, char *addr);
extern int ip_addr_cmp(struct ip_addr *sa, struct ip_addr *sb);

extern char *ip_addr_ntoa(struct ip_addr *sa, char *dst);
extern char *mac_addr_ntoa(u_char *mac, char *dst);
extern int mac_addr_aton(char *str, u_char *mac);

extern int ip_addr_is_local(struct ip_addr *sa);

/*
 * this prototype is implemented in ./os/.../
 * each OS implement its specific function
 */

extern void disable_ip_forward(void);

/********************/

#ifdef WORDS_BIGENDIAN        
   #define ptohs(x) ( (u_int16)                       \
                      ((u_int16)*((u_int8 *)x+1)<<8|  \
                      (u_int16)*((u_int8 *)x+0)<<0)   \
                    )

   #define ptohl(x) ( (u_int32)*((u_int8 *)x+3)<<24|  \
                      (u_int32)*((u_int8 *)x+2)<<16|  \
                      (u_int32)*((u_int8 *)x+1)<<8|   \
                      (u_int32)*((u_int8 *)x+0)<<0    \
                    )

   #define ORDER_ADD_SHORT(a, b)   a = htons(ntohs(a) + b)
   #define ORDER_ADD_LONG(a, b)	  a = htonl(ntohl(a) + b)

#else
   #define ptohs(x) *(u_int16 *)(x)
   #define ptohl(x) *(u_int32 *)(x)
   
   #define ORDER_ADD_SHORT(a, b)   a = a + b
   #define ORDER_ADD_LONG(a, b)	  a = a + b

#endif
      
   
#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))


   
#endif


/* EOF */

// vim:ts=3:expandtab

