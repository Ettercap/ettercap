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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_inet.c,v 1.9 2003/04/14 21:05:17 alor Exp $
*/

#include <ec.h>
#include <ec_inet.h>
#include <ec_ui.h>

#include <sys/socket.h>
#include <libnet.h>
#include <pcap.h>

/* prototypes */
int ip_addr_init(struct ip_addr *sa, int type, char *addr);
int ip_addr_cmp(struct ip_addr *sa, struct ip_addr *sb);

char *ip_addr_ntoa(struct ip_addr *sa, char *dst);
char *mac_addr_ntoa(u_char *mac, char *dst);
int mac_addr_aton(char *str, u_char *mac);

int ip_addr_is_local(struct ip_addr *sa);

static const char *inet_ntop4(const u_char *src, char *dst, size_t size);
static const char *inet_ntop6(const u_char *src, char *dst, size_t size);

/***********************************************************************/

int ip_addr_init(struct ip_addr *sa, int type, char *addr)
{
   sa->type = type;
   
   switch (type) {
      case AF_INET:
         sa->addr_size = IP_ADDR_LEN;
         break;
      case AF_INET6:
         sa->addr_size = IP6_ADDR_LEN;
         break;
      default:
         return -EINVALID;
   }
   
   memcpy(&sa->addr, addr, sa->addr_size);
   
   return ESUCCESS;
};

/* 
 * compare two ip_addr structure.
 */

int ip_addr_cmp(struct ip_addr *sa, struct ip_addr *sb)
{
   /* different type are incompatible */
   if (sa->type != sb->type)
      return 0;

   return memcmp(sa->addr, sb->addr, sa->addr_size);
   
}


char * ip_addr_ntoa(struct ip_addr *sa, char *dst)
{

   switch (sa->type) {
      case AF_INET:
         inet_ntop4(sa->addr, dst, IP_ASCII_ADDR_LEN);
         return dst;
         break;
      case AF_INET6:
         inet_ntop6(sa->addr, dst, IP6_ASCII_ADDR_LEN);
         return dst;
         break;
   };
   
   return NULL;
}

const char *
inet_ntop4(const u_char *src, char *dst, size_t size)
{
   char str[IP_ASCII_ADDR_LEN];
   int n;
   
	n = sprintf(str, "%u.%u.%u.%u", src[0], src[1], src[2], src[3]);
   
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

	/*
	 * Preprocess:
	 *	Copy the input (bytewise) array into a wordwise array.
	 *	Find the longest run of 0x00's in src[] for :: shorthanding.
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
	if ((tp - tmp) > size) {
		__set_errno (ENOSPC);
		return (NULL);
	}

   strncpy(dst, tmp, size);
   
   return dst;
}

/*
 * convert a MAC address to a uman readable form
 */

char *mac_addr_ntoa(u_char *mac, char *dst)
{
   char str[ETH_ASCII_ADDR_LEN];
   int n;
   
	n = sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X", 
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
   u_int tmp[ETH_ADDR_LEN];

   i = sscanf(str, "%02X:%02X:%02X:%02X:%02X:%02X", 
         (u_int *)&tmp[0], (u_int *)&tmp[1], (u_int *)&tmp[2], 
         (u_int *)&tmp[3], (u_int *)&tmp[4], (u_int *)&tmp[5]); 
 
   /* incorrect parsing */
   if (i != ETH_ADDR_LEN) {
      memset(mac, 0, ETH_ADDR_LEN);
      return 0;
   }
   
   for (i = 0; i < ETH_ADDR_LEN; i++)
      mac[i] = (u_char)tmp[i];
      
   return i;
}


/*
 * returns 1 if the ip address is local.
 * the choice is make reading the GBL_IFACE infos
 */

int ip_addr_is_local(struct ip_addr *sa)
{
   struct ip_addr *nm = &GBL_IFACE->netmask;
   struct ip_addr *nw = &GBL_IFACE->network;
   u_int32 address;
   u_int32 netmask;
   u_int32 network;
   
   switch (sa->type) {
      case AF_INET:
         address = *(u_int32 *)sa->addr;
         netmask = *(u_int32 *)nm->addr;
         network = *(u_int32 *)nw->addr;
         /* check if it is local */
         if ((address & netmask) == network)
            return 1;
         break;
      case AF_INET6:
         /* XXX - implement this */
         NOT_IMPLEMENTED();
         return 0;
         break;
   };

   return 0;
}


/* EOF */

// vim:ts=3:expandtab

