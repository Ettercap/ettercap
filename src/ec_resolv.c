/*
    ettercap -- name resolution module

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

    $Id: ec_resolv.c,v 1.1 2003/05/20 16:30:20 alor Exp $
*/

#include <ec.h>
#include <ec_resolv.h>
#include <ec_hash.h>

#include <netdb.h>

#define TABBIT    9 /* 2^9 bit tab entries: 512 SLISTS */
#define TABSIZE   (1UL<<TABBIT)
#define TABMASK   (TABSIZE-1) /* to mask fnv_1 hash algorithm */

/* globals */

static SLIST_HEAD(, resolv_entry) resolv_cache_head[TABSIZE];

struct resolv_entry {
   struct ip_addr ip;
   char *hostname;
   SLIST_ENTRY(resolv_entry) next;
};

/* protos */

int host_iptoa(struct ip_addr *ip, char *name);
static int cache_search(struct ip_addr *ip, char *name);
static void cache_insert(struct ip_addr *ip, char *name);

/************************************************/

/*
 * resolves an ip address into an hostname.
 * before doing the real gethostbyaddr it search in
 * a cache of previously resolved hosts to increase
 * speed.
 * after each gethostbyaddr the result is inserted 
 * in the cache.
 */

int host_iptoa(struct ip_addr *ip, char *name)
{
   struct hostent *host = NULL;
#ifdef CYGWIN
   WSADATA wsdata;
#endif

   /* we MUST NOT resolve if the user does not want it */
   BUG_ON(!GBL_OPTIONS->resolve);

   DEBUG_MSG("host_iptoa: %#x", *(u_int32 *)&ip->addr);
   
   /*
    * if the entry is already present in the cache
    * return that entry and don't call the real
    * gethostbyaddr. we want to increase the speed...
    */
   if (cache_search(ip, name) == ESUCCESS)
      return ESUCCESS;
   
   /* if not found in the cache, resolve it */
   
#ifdef CYGWIN
   if ( WSAStartup(MAKEWORD(2, 2), &wsdata) != 0)
      ERROR_MSG("Cannot inizialize winsock WSAStartup()");
#endif
  
   /* XXX - add support for IPv6 */
   host = gethostbyaddr((char *)ip->addr, sizeof(struct in_addr), AF_INET);

#ifdef CYGWIN
   WSACleanup();
#endif
   
   /* not found or error */
   if (host == NULL) {
      strcpy(name, "");
      /* 
       * insert the "" in the cache so we don't search for
       * non existent hosts every new query.
       */
      cache_insert(ip, name);
      return -ENOTFOUND;
   } 
 
   /* the host was resolved... */
   strlcpy(name, host->h_name, MAX_HOSTNAME_LEN);

   /* insert the result in the cache for later use */
   cache_insert(ip, name);
   
   return ESUCCESS;
}

/*
 * search in the cache for an already
 * resolved host
 */

static int cache_search(struct ip_addr *ip, char *name)
{
   struct resolv_entry *r;
      
   SLIST_FOREACH(r, &resolv_cache_head[fnv_32(ip->addr, ip->addr_size) & TABMASK], next) {
      if (!ip_addr_cmp(&r->ip, ip)) {
         /* found in the cache */
         
         DEBUG_MSG("cache_search: found: %s", r->hostname);
         
         strncpy(name, r->hostname, MAX_HOSTNAME_LEN);
         return ESUCCESS;
      }
   }
   
   DEBUG_MSG("cache_search: cache missed !");

   /* cache miss */
   return -ENOTFOUND;
}

/*
 * insert an entry in the cache
 */

static void cache_insert(struct ip_addr *ip, char *name)
{
   struct resolv_entry *r;

   r = calloc(1, sizeof(struct resolv_entry));
   ON_ERROR(r, NULL, "Can't allocate memory");

   memcpy(&r->ip, ip, sizeof(struct ip_addr));
   r->hostname = strdup(name);
   
   SLIST_INSERT_HEAD(&(resolv_cache_head[fnv_32(ip->addr, ip->addr_size) & TABMASK]), r, next);

   DEBUG_MSG("cache_insert: %s", r->hostname);
}

/* EOF */

// vim:ts=3:expandtab

