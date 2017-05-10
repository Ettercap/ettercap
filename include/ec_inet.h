#ifndef ETTERCAP_INET_H
#define ETTERCAP_INET_H

#include <ec_queue.h>

#ifdef OS_WINDOWS
   #include <winsock2.h>
   #include <ws2tcpip.h>
#else
   #include <netinet/in.h>
   #include <arpa/inet.h>
   #include <sys/socket.h>
#endif

#include <sys/stat.h>

#ifdef OS_CYGWIN
   #ifndef AF_INET6
      /* XXX - ugly hack only to make it compile */
      #define AF_INET6 23
   #endif
#endif

/*
 * define non-standard address family identifier 
 * used in the Null/Loopback encapsulation origined
 * on several BSD derivates
 */
#define AF_INET6_LINUX 10
#define AF_INET6_BSD 24
#define AF_INET6_FREEBSD 28
#define AF_INET6_DARWIN 30

#define	ETH_ADDR_LEN 6
#define	TR_ADDR_LEN 6
#define	FDDI_ADDR_LEN 6
#define	MEDIA_ADDR_LEN 6
   
#define	IP_ADDR_LEN 4
#define	IP6_ADDR_LEN 16
#define	MAX_IP_ADDR_LEN IP6_ADDR_LEN

#define	ETH_ASCII_ADDR_LEN 19 // sizeof("ff:ff:ff:ff:ff:ff")+1
#define	IP_ASCII_ADDR_LEN 17 // sizeof("255.255.255.255")+1
#define	IP6_ASCII_ADDR_LEN 47 // sizeof("ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255")+1
#define	MAX_ASCII_ADDR_LEN IP6_ASCII_ADDR_LEN

/*
 * Some predefined addresses here
 */
#define IP6_ALL_NODES "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
#define IP6_ALL_ROUTERS "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
#define IP6_SOL_NODE "\xff\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\xff\x00\x00\x00"

#define IP6_DSTOPT_UNKN "\x80\x01\x00\x00\x00"
#define LLA_IP6_ALLNODES_MULTICAST "\x33\x33\x00\x00\x00\x01"

/* 
 * this structure is used by ettercap to handle 
 * an IP packet disregarding its version 
 */
struct ip_addr {
   u_int16 addr_type;
   u_int16 addr_len;
   /* this must be aligned in memory */
   union {
      u_int8 addr[MAX_IP_ADDR_LEN];
      u_int16 addr16[MAX_IP_ADDR_LEN/2];
      u_int32 addr32[MAX_IP_ADDR_LEN/4];
   };
};

struct net_list {
   struct ip_addr ip;
   struct ip_addr netmask;
   struct ip_addr network;
   u_int8 prefix;
   LIST_ENTRY(net_list) next;
};

EC_API_EXTERN int ip_addr_init(struct ip_addr *sa, u_int16 type, u_char *addr);
EC_API_EXTERN int ip_addr_cpy(u_char *addr, struct ip_addr *sa);
EC_API_EXTERN int ip_addr_cmp(struct ip_addr *sa, struct ip_addr *sb);
EC_API_EXTERN int ip_addr_null(struct ip_addr *sa);
EC_API_EXTERN int ip_addr_is_zero(struct ip_addr *sa);
EC_API_EXTERN int ip_addr_random(struct ip_addr* ip, u_int16 type);
EC_API_EXTERN int ip_addr_init_sol(struct ip_addr* sn, struct ip_addr* ip, u_int8 *tmac);

EC_API_EXTERN char *ip_addr_ntoa(struct ip_addr *sa, char *dst);
EC_API_EXTERN int ip_addr_pton(char *str, struct ip_addr *addr);
EC_API_EXTERN char *mac_addr_ntoa(u_char *mac, char *dst);
EC_API_EXTERN int mac_addr_aton(char *str, u_char *mac);

EC_API_EXTERN int ip_addr_is_local(struct ip_addr *sa, struct ip_addr *ifaddr);
EC_API_EXTERN int ip_addr_is_global(struct ip_addr *ip);
EC_API_EXTERN int ip_addr_is_multicast(struct ip_addr *ip);
EC_API_EXTERN int ip_addr_is_broadcast(struct ip_addr *sa);
EC_API_EXTERN int ip_addr_is_ours(struct ip_addr *ip);
EC_API_EXTERN int ip_addr_get_network(struct ip_addr*, struct ip_addr*, struct ip_addr*);
EC_API_EXTERN int ip_addr_get_prefix(struct ip_addr* netmask);

/*
 * this prototypes are implemented in ./os/.../
 * each OS implement its specific function
 */

EC_API_EXTERN void disable_ip_forward(void);
EC_API_EXTERN void restore_ip_forward(void);
EC_API_EXTERN u_int16 get_iface_mtu(const char *iface);

#ifdef WITH_IPV6
EC_API_EXTERN void disable_ipv6_forward(void);
EC_API_EXTERN void restore_ipv6_forward(void);
#endif

#ifdef OS_LINUX
EC_API_EXTERN void disable_interface_offload(void);
#endif

#if defined OS_LINUX && defined WITH_IPV6
EC_API_EXTERN void check_tempaddr(const char *iface);
#endif

/********************/

#ifdef WORDS_BIGENDIAN       
   /* BIG ENDIAN */
   #define phtos(x) ( (u_int16)                       \
                      ((u_int16)*((u_int8 *)x+1)<<8|  \
                      (u_int16)*((u_int8 *)x+0)<<0)   \
                    )

   #define phtol(x) ( (u_int32)*((u_int8 *)x+3)<<24|  \
                      (u_int32)*((u_int8 *)x+2)<<16|  \
                      (u_int32)*((u_int8 *)x+1)<<8|   \
                      (u_int32)*((u_int8 *)x+0)<<0    \
                    )

   #define pntos(x) ( (u_int16)                       \
                      ((u_int16)*((u_int8 *)x+1)<<0|  \
                      (u_int16)*((u_int8 *)x+0)<<8)   \
                    )

   #define pntol(x) ( (u_int32)*((u_int8 *)x+3)<<0|   \
                      (u_int32)*((u_int8 *)x+2)<<8|   \
                      (u_int32)*((u_int8 *)x+1)<<16|  \
                      (u_int32)*((u_int8 *)x+0)<<24   \
                    )
   
   /* return little endian */
   #define htons_inv(x) (u_int16)(x << 8) | (x >> 8) 

   #define ORDER_ADD_SHORT(a, b)   a = a + b
   #define ORDER_ADD_LONG(a, b)	  a = a + b

#else
   /* LITTLE ENDIAN */
   #define phtos(x) *(u_int16 *)(x)
   #define phtol(x) *(u_int32 *)(x)

   #define pntos(x) ntohs(*(u_int16 *)(x))
   #define pntol(x) ntohl(*(u_int32 *)(x))
      
   /* return little endian */
   #define htons_inv(x) (u_int16)x
   
   #define ORDER_ADD_SHORT(a, b)   a = htons(ntohs(a) + (int16)b)
   #define ORDER_ADD_LONG(a, b)	  a = htonl(ntohl(a) + (int32)b)

#endif
      
   
#define int_ntoa(x)   inet_ntoa(*((struct in_addr *)&(x)))

  
#endif


/* EOF */

// vim:ts=3:expandtab

