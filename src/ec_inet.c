/*
    ettercap -- IP address management

    Copyright (C) ALoR & NaGA

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <ec.h>
#include <ec_inet.h>
#include <ec_ui.h>

/* prototypes */

static const char *inet_ntop4(const u_char *src, char *dst, size_t size);
static const char *inet_ntop6(const u_char *src, char *dst, size_t size);

/***********************************************************************/

/*
 * creates a structure from a buffer
 */
int ip_addr_init(struct ip_addr *sa, u_int16 type, u_char *addr)
{
   /* the version of the IP packet */
   sa->addr_type = htons(type);
   /* wipe the buffer */
   memset(sa->addr, 0, MAX_IP_ADDR_LEN);
   
   switch (type) {
      case AF_INET:
         sa->addr_len = htons(IP_ADDR_LEN);
         break;
      case AF_INET6:
         sa->addr_len = htons(IP6_ADDR_LEN);
         break;
      default:
         /* wipe the struct */
         memset(sa, 0, sizeof(struct ip_addr));
         BUG("Invalid ip_addr type");
         return -E_INVALID;
   }
   
   memcpy(&sa->addr, addr, ntohs(sa->addr_len));
   
   return E_SUCCESS;
};

/*
 * copy the address in a buffer
 */
int ip_addr_cpy(u_char *addr, struct ip_addr *sa)
{
   memcpy(addr, &sa->addr, ntohs(sa->addr_len));

   return E_SUCCESS;
}

/* 
 * compare two ip_addr structure.
 */
int ip_addr_cmp(struct ip_addr *sa, struct ip_addr *sb)
{
   if (!sa || !sb)
      return -E_INVALID;

   /* different type are incompatible */
   if (sa->addr_type != sb->addr_type)
      return -E_INVALID;

   return memcmp(sa->addr, sb->addr, ntohs(sa->addr_len));
   
}

/*
 * returns 0 if the ip address is IPv4 or IPv6
 */
int ip_addr_null(struct ip_addr *sa)
{
   if (ntohs(sa->addr_type) == AF_INET || ntohs(sa->addr_type) == AF_INET6) 
      return 0;
 
   return 1;
}

/*
 * return true if an ip address is 0.0.0.0 or invalid
 */
int ip_addr_is_zero(struct ip_addr *sa)
{
   switch (ntohs(sa->addr_type)) {
      case AF_INET:
         if (memcmp(sa->addr, "\x00\x00\x00\x00", IP_ADDR_LEN))
            return 0;
         break;
      case AF_INET6:
         if (memcmp(sa->addr, "\x00\x00\x00\x00\x00\x00\x00\x00"
                              "\x00\x00\x00\x00\x00\x00\x00\x00", IP6_ADDR_LEN))
            return 0;
         break;
   };
  
   return 1;
}

/*
 * generates a random link-local ip address
 * returns E_SUCCESS or -E_INVALID if address family is unkown
 */
int ip_addr_random(struct ip_addr* ip, u_int16 type)
{
   /* generate a random 32-bit number */
   srand(time(NULL));
   u_int32 r = rand();
   u_int32 h1 = r | 0x02000000;
   u_int32 h2 = ~r;

   switch (type) {
      case AF_INET:
         ip->addr_type = htons(type);
         ip->addr_len  = IP_ADDR_LEN;
         memset(ip->addr, 0, IP_ADDR_LEN);
         memcpy(ip->addr,     "\xa9\xfe", 2); /* 169.254/16 */
         memcpy(ip->addr + 2, (u_char*)&r, 2);
      break;

      case AF_INET6:
         ip->addr_type = htons(type);
         ip->addr_len  = IP6_ADDR_LEN;
         memset(ip->addr, 0, IP6_ADDR_LEN);
         memcpy(ip->addr,      "\xfe\x80\x00\x00", 4);
         memcpy(ip->addr + 4,  "\x00\x00\x00\x00", 4);
         memcpy(ip->addr + 8,  (u_char*)&h1, 4);
         memcpy(ip->addr + 12, (u_char*)&h2, 4);
         memcpy(ip->addr + 11, "\xff\xfe", 2);
      break;

      default:
         return -E_INVALID;

   }
   return E_SUCCESS;
}

/*
 * initialize a solicited-node IPv6 and link-layer address from a
 * given ip address.
 *
 * returns E_SUCCESS on success or -E_INVALID in case of a unsupported
 * address familily (actually only IPv6 is supported)
 */
int ip_addr_init_sol(struct ip_addr* sn, struct ip_addr* ip, u_int8 *tmac)
{
   switch (ntohs(ip->addr_type)) {
      case AF_INET:
         (void) sn;
         (void) tmac;
         /* not applicable for IPv4 */
      break;
#ifdef WITH_IPV6
      case AF_INET6:
         /* 
          * initialize the ip_addr struct with the solicited-node
          * multicast prefix and copy the tailing 24-bit into the
          * address to form the complete solicited-node address
          */
         ip_addr_init(sn, AF_INET6, (u_char*)IP6_SOL_NODE);
         memcpy((sn->addr + 13), (ip->addr + 13), 3);

         /*
          * initialize the MAC address derived from the solicited
          * node multicast IPv6 address by overwriting the tailing
          * 32-bit of the all-nodes link-layer multicast address for IPv6
          */
         memcpy(tmac, LLA_IP6_ALLNODES_MULTICAST, MEDIA_ADDR_LEN);
         memcpy((tmac + 2), (sn->addr + 12), 4);


         return E_SUCCESS;
      break;
#endif
   }

   return -E_INVALID;
}


/*
 * convert to ascii an ip address
 */
char * ip_addr_ntoa(struct ip_addr *sa, char *dst)
{

   switch (ntohs(sa->addr_type)) {
      case AF_INET:
         inet_ntop4(sa->addr, dst, IP_ASCII_ADDR_LEN);
         return dst;
         break;
      case AF_INET6:
         inet_ntop6(sa->addr, dst, IP6_ASCII_ADDR_LEN);
         return dst;
         break;
   };
   
   return "invalid";
}

const char *
inet_ntop4(const u_char *src, char *dst, size_t size)
{
   char str[IP_ASCII_ADDR_LEN];
   int n;
   
   n = snprintf(str, IP_ASCII_ADDR_LEN, "%u.%u.%u.%u", src[0], src[1], src[2], src[3]);
   
   str[n] = '\0';
 
   strncpy(dst, str, size);
   
   return dst;
}

const char *
inet_ntop6(const u_char *src, char *dst, size_t size)
{
   /*
    * Note that int32_t and int16_t need only be "at least" large enough
    * to contain a value of the specified size.  On some systems, like
    * Crays, there is no such thing as an integer variable with 16 bits.
    * Keep this in mind if you think this function should have been coded
    * to use pointer overlays.  All the world's not a VAX.
    */
   char tmp[IP6_ASCII_ADDR_LEN], *tp;
   struct { int base, len; } best, cur;
   u_int words[NS_IN6ADDRSZ / NS_INT16SZ];
   int i;

   best.len = 0;
   cur.len = 0;

   /*
    * Preprocess:
    *   Copy the input (bytewise) array into a wordwise array.
    *   Find the longest run of 0x00's in src[] for :: shorthanding.
    */
   memset(words, '\0', sizeof words);
   for (i = 0; i < NS_IN6ADDRSZ; i += 2)
      words[i / 2] = (src[i] << 8) | src[i + 1];
   best.base = -1;
   cur.base = -1;
   for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
      if (words[i] == 0) {
         if (cur.base == -1)
            cur.base = i, cur.len = 1;
         else
            cur.len++;
      } else {
         if (cur.base != -1) {
            if (best.base == -1 || cur.len > best.len)
               best = cur;
            cur.base = -1;
         }
      }
   }
   if (cur.base != -1) {
      if (best.base == -1 || cur.len > best.len)
         best = cur;
   }
   if (best.base != -1 && best.len < 2)
      best.base = -1;

   /*
    * Format the result.
    */
   tp = tmp;
   for (i = 0; i < (NS_IN6ADDRSZ / NS_INT16SZ); i++) {
      /* Are we inside the best run of 0x00's? */
      if (best.base != -1 && i >= best.base &&
          i < (best.base + best.len)) {
         if (i == best.base)
            *tp++ = ':';
         continue;
      }
      /* Are we following an initial run of 0x00s or any real hex? */
      if (i != 0)
         *tp++ = ':';
      /* Is this address an encapsulated IPv4? */
      if (i == 6 && best.base == 0 &&
          (best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
         if (inet_ntop4(src+12, tp, IP_ASCII_ADDR_LEN) != 0)
            return (NULL);
         tp += strlen(tp);
         break;
      }
      tp += sprintf(tp, "%x", words[i]);
   }
   /* Was it a trailing run of 0x00's? */
   if (best.base != -1 && (best.base + best.len) == 
       (NS_IN6ADDRSZ / NS_INT16SZ))
      *tp++ = ':';
   *tp++ = '\0';

     /*
    * Check for overflow, copy, and we're done.
    */
   if ((size_t)(tp - tmp) > size) {
      __set_errno (ENOSPC);
      return (NULL);
   }

   strncpy(dst, tmp, size);
   
   return dst;
}

/* Converts character string to IP address if possible */
int ip_addr_pton(char *str, struct ip_addr *addr)
{
   struct in_addr inaddr;
#ifdef WITH_IPV6
   struct in6_addr in6addr;
#endif
   
   if(inet_pton(AF_INET, str, &inaddr) == 1) { /* try IPv4 */
      ip_addr_init(addr, AF_INET, (u_char*)&inaddr);
      return E_SUCCESS;
   }
#ifdef WITH_IPV6
   else if (inet_pton(AF_INET6, str, &in6addr) == 1) { /* try IPv6 */
      ip_addr_init(addr, AF_INET6, (u_char*)&in6addr);
      return E_SUCCESS;
   } 
#endif
   else {
      return -E_INVALID;
   }
}

/*
 * convert a MAC address to a human readable form
 */
char *mac_addr_ntoa(u_char *mac, char *dst)
{
   char str[ETH_ASCII_ADDR_LEN];
   int n;
   
   n = snprintf(str, ETH_ASCII_ADDR_LEN, "%02X:%02X:%02X:%02X:%02X:%02X", 
         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
   
   str[n] = '\0';
 
   strncpy(dst, str, ETH_ASCII_ADDR_LEN);
   
   return dst;
   
}

/*
 * convert a string to a u_char mac[6]
 */
int mac_addr_aton(char *str, u_char *mac)
{
   int i;
   u_int tmp[MEDIA_ADDR_LEN];

   i = sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X", 
         (u_int *)&tmp[0], (u_int *)&tmp[1], (u_int *)&tmp[2], 
         (u_int *)&tmp[3], (u_int *)&tmp[4], (u_int *)&tmp[5]); 
 
   /* incorrect parsing */
   if (i != MEDIA_ADDR_LEN) {
      memset(mac, 0, MEDIA_ADDR_LEN);
      return 0;
   }
   
   for (i = 0; i < MEDIA_ADDR_LEN; i++)
      mac[i] = (u_char)tmp[i];
      
   return i;
}

/*
 * returns  1 if the ip is a Global Unicast 
 * returns  0 if not
 * returns -E_INVALID if address family is unknown
 */
int ip_addr_is_global(struct ip_addr *ip)
{

   switch (ntohs(ip->addr_type)) {
      case AF_INET:
         /* Global for IPv4 means not status "RESERVED" by IANA */
         if (
               *ip->addr != 0x0 &&                         /* not 0/8        */
               *ip->addr != 0x7f &&                        /* not 127/8      */
               *ip->addr != 0x0a &&                        /* not 10/8       */
               (ntohs(*ip->addr16) & 0xfff0) != 0xac10 &&  /* not 172.16/12  */
               ntohs(*ip->addr16) != 0xc0a8 &&             /* not 192.168/16 */
               !ip_addr_is_multicast(ip)                   /* not 224/3      */
            )
            return 1;
      break;
      case AF_INET6:
         /* 
          * as IANA does not appy masks > 8-bit for Global Unicast block, 
          * only the first 8-bit are significant for this test.
          */
         if ((*ip->addr & 0xe0) == 0x20) {
            /* 
             * This may be extended in future as IANA assigns further ranges
             * to Global Unicast
             */ 
            return 1;
         } 
      break;
      default: 
         return -E_INVALID;
   }

   return 0;
}

/*
 * returns  1 if the ip is multicast
 * returns  0 if not
 * returns -E_INVALID if address family is unknown
 */
int ip_addr_is_multicast(struct ip_addr *ip)
{

   switch(ntohs(ip->addr_type)) {
      case AF_INET:
         if ((*ip->addr & 0xf0) == 0xe0)
            return 1;
      break;

      case AF_INET6:
         if ((*ip->addr & 0xff) == 0xff)
            return 1;
      break;

      default:
         return -E_INVALID;
   }
   return 0;
}

/*
 * returns  E_SUCCESS if the ip is broadcast
 * returns -E_NOTFOUND if not
 */
int ip_addr_is_broadcast(struct ip_addr *sa)
{
   struct ip_addr *nw;
   struct ip_addr *nm;

   u_int32* address;
   u_int32* netmask;
   u_int32* network;
   u_int32 broadcast;

   switch(ntohs(sa->addr_type)) {
      case AF_INET:
         if(!EC_GBL_IFACE->has_ipv4)
            return -E_INVALID;
         nm = &EC_GBL_IFACE->netmask;
         nw = &EC_GBL_IFACE->network;

         /* 255.255.255.255 is definitely broadcast */
         if(!memcmp(sa->addr, "\xff\xff\xff\xff", IP_ADDR_LEN))
            return E_SUCCESS;

         address = sa->addr32;
         netmask = nm->addr32;
         network = nw->addr32;

         broadcast = (*network) | ~(*netmask);

         if (broadcast == *address)
            return E_SUCCESS;

         break;
      case AF_INET6:
         if(!EC_GBL_IFACE->has_ipv6)
            return -E_INVALID;

         /* IPv6 has no such thing as a broadcast address. The closest
          * equivalent is the multicast address ff02::1. Packets sent to that
          * address are delivered to all link-local nodes.
          */
         if(!memcmp(sa->addr, IP6_ALL_NODES, IP6_ADDR_LEN))
            return E_SUCCESS;
         
         break;
   }

   return -E_NOTFOUND;
}

/*
 * returns E_SUCCESS if the ip address is local.
 * returns -E_NOTFOUND if it is non local.
 * the choice is make reading the EC_GBL_IFACE infos
 *
 * if the EC_GBL_IFACE is not filled (while reading from files)
 * returns -E_INVALID.
 */
int ip_addr_is_local(struct ip_addr *sa, struct ip_addr *ifaddr)
{
   struct ip_addr *nm;
   struct ip_addr *nw;
   struct net_list* ip6;
   u_int32* address;
   u_int32* netmask;
   u_int32* network;
   unsigned int i, matched = 0;


   switch (ntohs(sa->addr_type)) {
      case AF_INET:
         nm = &EC_GBL_IFACE->netmask;
         nw = &EC_GBL_IFACE->network;
         /* the address 0.0.0.0 is used by DHCP and it is local for us*/
         if ( !memcmp(&sa->addr, "\x00\x00\x00\x00", ntohs(sa->addr_len)) )
            return E_SUCCESS;
         
         /* make a check on EC_GBL_IFACE (is it initialized ?) */
         if ( !memcmp(&nw->addr, "\x00\x00\x00\x00", ntohs(sa->addr_len)) )
            /* return UNKNOWN */
            return -E_INVALID;
   
         address = sa->addr32;
         netmask = nm->addr32;
         network = nw->addr32;
         /* check if it is local */
         if ((*address & *netmask) == *network) {
            if(ifaddr != NULL)
               memcpy(ifaddr, &EC_GBL_IFACE->ip, sizeof(*ifaddr));
            return E_SUCCESS;
         }
         break;
      case AF_INET6:
         if(!EC_GBL_IFACE->has_ipv6)
             return -E_INVALID;
         LIST_FOREACH(ip6, &EC_GBL_IFACE->ip6_list, next) {
            nm = &ip6->netmask;
            nw = &ip6->network;
            address = sa->addr32;
            netmask = nm->addr32;
            network = nw->addr32;


            for(i = 0; i < IP6_ADDR_LEN / sizeof(u_int32); i++) {
               if (netmask[i] == 0) { /* no need to check further */
                  break;
               }
               else if((address[i] & netmask[i]) != network[i]) {
                  matched = 0;
                  break;
               } 
               else {
                  matched = 1;
               }
            }

            if(ifaddr != NULL) 
               memcpy(ifaddr, &ip6->ip, sizeof(*ifaddr));
            
            if (matched)
               return E_SUCCESS;
         }
      
         break;
   };

   return -E_NOTFOUND;
}

int ip_addr_is_ours(struct ip_addr *ip)
{
   struct net_list *i;
   switch(ntohs(ip->addr_type)) {
      case AF_INET:
         if(!ip_addr_cmp(ip, &EC_GBL_IFACE->ip))
            return E_FOUND;
         else if(!ip_addr_cmp(ip, &EC_GBL_BRIDGE->ip))
            return E_BRIDGE;
         else
            return -E_NOTFOUND;
         break;

      case AF_INET6:
         LIST_FOREACH(i, &EC_GBL_IFACE->ip6_list, next) {
            if(!ip_addr_cmp(ip, &i->ip))
               return E_FOUND;
         }
         return -E_NOTFOUND;
   }

   return -E_INVALID;
}

int ip_addr_get_network(struct ip_addr *ip, struct ip_addr *netmask, struct ip_addr *network)
{
   u_int32 ip4;
   u_int32 ip6[IP6_ADDR_LEN / sizeof(u_int32)];

   if(ntohs(ip->addr_type) != ntohs(netmask->addr_type))
      return -E_INVALID;

   switch(ntohs(ip->addr_type)) {
      case AF_INET:
         ip4 = *ip->addr32 & *netmask->addr32;
         ip_addr_init(network, AF_INET, (u_char*)&ip4);
         break;
      case AF_INET6:
         ip6[0] = ip->addr32[0] & netmask->addr32[0];
         ip6[1] = ip->addr32[1] & netmask->addr32[1];
         ip6[2] = ip->addr32[2] & netmask->addr32[2];
         ip6[3] = ip->addr32[3] & netmask->addr32[3];
         ip_addr_init(network, AF_INET6, (u_char*)&ip6);
         break;
      default:
         BUG("Invalid addr_type");
         return -E_INVALID;
         break;
   }
   return E_SUCCESS;
}

int ip_addr_get_prefix(struct ip_addr* netmask)
{
   size_t s;
   unsigned int i;
   int prefix = 0;
   u_int32* mask;
   u_int32 x;

   s = ntohs(netmask->addr_len) / sizeof(u_int32);

   mask = netmask->addr32;

   for(i = 0; i < s; i++) {
      x = mask[i];
      x -= (x >> 1) & 0x55555555;
      x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
      prefix += (((x + (x >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24;
   }

   return prefix;
}

/* EOF */

// vim:ts=3:expandtab

