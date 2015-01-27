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

*/

#include <ec.h>
#include <ec_resolv.h>
#include <ec_hash.h>
#include <ec_threads.h>

#ifndef OS_WINDOWS
   #include <netdb.h>
#endif

#define TABBIT    9 /* 2^9 bit tab entries: 512 SLISTS */
#define TABSIZE   (1UL<<TABBIT)
#define TABMASK   (TABSIZE-1) /* to mask fnv_1 hash algorithm */

/* globals */
static pthread_mutex_t resolv_mutex = PTHREAD_MUTEX_INITIALIZER;
#define RESOLV_LOCK do{pthread_mutex_lock(&resolv_mutex);}while(0)
#define RESOLV_UNLOCK do{pthread_mutex_unlock(&resolv_mutex);}while(0)


static SLIST_HEAD(, resolv_entry) resolv_cache_head[TABSIZE];

struct resolv_entry {
   struct ip_addr ip;
   char *hostname;
   SLIST_ENTRY(resolv_entry) next;
};

/* protos */
EC_THREAD_FUNC(resolv_dns);
EC_THREAD_FUNC(resolv_passive);
static int resolv_cache_search(struct ip_addr *ip, char *name);
void resolv_cache_insert(struct ip_addr *ip, char *name);

/************************************************/

/*
 * resolves an ip address into an hostname.
 * before doing the real getnameinfo it search in
 * a cache of previously resolved hosts to increase
 * speed.
 * if the name can not be found in the cache and name
 * resolution is enabled, -E_NOMATCH is returned indicating
 * that the background resolution using getnameinfo 
 * starts and the the result is inserted in the cache.
 * The caller can fetch the name with a second call
 * directly from the cache, even if no name was found.
 */

int host_iptoa(struct ip_addr *ip, char *name)
{
   char tmp[MAX_ASCII_ADDR_LEN];
   char thread_name[MAX_ASCII_ADDR_LEN + 6 + 2 + 1];
   
   /* initialize the name */
   strncpy(name, "", 1);
  
   /* sanity check */
   if (ip_addr_is_zero(ip))
      return -E_NOTHANDLED;

   /*
    * if the entry is already present in the cache
    * return that entry and don't call the real
    * getnameinfo. we want to increase the speed...
    */
   if (resolv_cache_search(ip, name) == E_SUCCESS)
      return E_SUCCESS;

   /*
    * the user has requested to not resolve the host,
    * but we perform the search in the cache because
    * the passive engine might have intercepted some
    * request. it is resolution for free... ;)
    */
   if (!GBL_OPTIONS->resolve)
      return -E_NOTFOUND;
  
   DEBUG_MSG("host_iptoa() %s not in cache", ip_addr_ntoa(ip, tmp));

   /* 
    * The host was not in the cache but requests to resolve,
    * so we continue resolving it in a non-blocking manner.
    * We return -E_NOMATCH to indicate that we try to resolve it
    * and the result may be in the cache later.
    * That way we don't block the application if the OS is configured
    * to include mDNS in the host resolution process (/etc/nsswitch.conf).
    * Including mDNS enriches the results but heavily delays if 
    * many hosts are online on the link.
    */
   snprintf(thread_name, sizeof(thread_name), "resolv[%s]", tmp);
   ec_thread_new(thread_name, "DNS resolver", &resolv_dns, ip);

   return -E_NOMATCH;
}

/* 
 * perform the ip to name resolution as a dedicated thread per IP.
 * In any case the name cache is updated so that a second call of
 * of host_iptoa() gets a result.
 */
EC_THREAD_FUNC(resolv_dns)
{
   struct ip_addr ip;
   struct sockaddr_storage ss;
   struct sockaddr_in *sa4;
   struct sockaddr_in6 *sa6;
   char host[MAX_HOSTNAME_LEN];
   char tmp[MAX_ASCII_ADDR_LEN];
   pthread_t pid;

   /* immediatelly copy data avoiding race conditions */
   memcpy(&ip, EC_THREAD_PARAM, sizeof(ip));

   /* initialize the thread */
   ec_thread_init();
   
   /* if not found in the cache, prepare struct and resolve it */
   switch (ntohs(ip.addr_type)) {
      case AF_INET:
         sa4 = (struct sockaddr_in *)&ss;
         sa4->sin_family = AF_INET;
         ip_addr_cpy((u_char*)&sa4->sin_addr.s_addr, &ip);
      break;
      case AF_INET6:
         sa6 = (struct sockaddr_in6 *)&ss;
         sa6->sin6_family = AF_INET6;
         ip_addr_cpy((u_char*)&sa6->sin6_addr.s6_addr, &ip);
      break;
   }

   /* not found or error */
   if (getnameinfo((struct sockaddr *)&ss, sizeof(struct sockaddr), 
            host, MAX_HOSTNAME_LEN, NULL, 0, NI_NAMEREQD)) {
      /* 
       * insert the "" in the cache so we don't search for
       * non existent hosts every new query.
       */
      DEBUG_MSG("resolv_dns: not found for %s", ip_addr_ntoa(&ip, tmp));

      RESOLV_LOCK;
      resolv_cache_insert(&ip, "");
      RESOLV_UNLOCK;

   } else {
      DEBUG_MSG("resolv_dns: %s found for %s", host, ip_addr_ntoa(&ip, tmp));

      /* insert the result in the cache for later use */
      RESOLV_LOCK;
      resolv_cache_insert(&ip, host);
      RESOLV_UNLOCK;
   }

   /* work done - thread self destruction */
   pid = pthread_self();
   if (!pthread_equal(pid, EC_PTHREAD_NULL))
      ec_thread_destroy(pid);

   /* only reached if not threaded */
   return NULL;
}

/*
 * search in the cache for an already
 * resolved host
 */

static int resolv_cache_search(struct ip_addr *ip, char *name)
{
   struct resolv_entry *r;
   u_int32 h;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* calculate the hash */
   h = fnv_32(ip->addr, ntohs(ip->addr_len)) & TABMASK;
      
   SLIST_FOREACH(r, &resolv_cache_head[h], next) {
      if (!ip_addr_cmp(&r->ip, ip)) {
         /* found in the cache */
         
         DEBUG_MSG("resolv_cache_search: found: %s -> %s", 
               ip_addr_ntoa(ip, tmp), r->hostname);
         
         strlcpy(name, r->hostname, MAX_HOSTNAME_LEN - 1);
         return E_SUCCESS;
      }
   }
   
   /* cache miss */
   return -E_NOTFOUND;
}

/*
 * insert an entry in the cache
 */

void resolv_cache_insert(struct ip_addr *ip, char *name)
{
   struct resolv_entry *r;
   u_int32 h;
   pthread_t pid;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* 
    * make sure this function is not called by the main thread.
    * this is important because parallel writing of the cache
    * can lead to segmentation faults due to race conditions
    */
   pid = pthread_self();
   if (pthread_equal(pid, EC_PTHREAD_NULL)) {
      DEBUG_MSG("resolv_cache_insert: not called by a thread - aborting");
      return;
   }

   /* calculate the hash */
   h = fnv_32(ip->addr, ntohs(ip->addr_len)) & TABMASK;

   /* 
    * search if it is already in the cache.
    * this will pervent passive insertion to overwrite
    * previous cached results
    */
   SLIST_FOREACH(r, &resolv_cache_head[h], next) {
      /* found in the cache skip it */
      if (!ip_addr_cmp(&r->ip, ip)) {
         DEBUG_MSG("resolv_cache_insert: %s already in cache - skipping",
               ip_addr_ntoa(ip, tmp));
         return; 
      }
   }

   DEBUG_MSG("resolv_cache_insert: no entry found for %s",
         ip_addr_ntoa(ip, tmp));
   SAFE_CALLOC(r, 1, sizeof(struct resolv_entry));

   memcpy(&r->ip, ip, sizeof(struct ip_addr));
   r->hostname = strdup(name);
   
   SLIST_INSERT_HEAD(&(resolv_cache_head[h]), r, next);

   DEBUG_MSG("resolv_cache_insert: inserted %s --> %s",
         tmp, name);
   
}

/* 
 * wrapper function for the passive name recognition
 * ensuring syncronization with active name resolving 
 * threads
 */
void resolv_cache_insert_passive(struct ip_addr *ip, char *name)
{
   struct resolv_entry r;
   char thread_name[MAX_ASCII_ADDR_LEN + 14 + 2 + 1];
   char tmp[MAX_ASCII_ADDR_LEN];

   /* store params in one resolv_entry struct to be passed to the thread */
   memcpy(&r.ip, ip, sizeof(r.ip));
   r.hostname = name;

   /* create a new thread to write into the cache */
   ip_addr_ntoa(ip, tmp);
   snprintf(thread_name, sizeof(thread_name), "resolv_passive[%s]", tmp);
   ec_thread_new(thread_name, "DNS resolver", &resolv_passive, &r);

}

/*
 * thread to insert into name cache
 * the threaded approach unblocks the dissector from waiting
 * for the lock to write the cache
 */
EC_THREAD_FUNC(resolv_passive)
{
   struct resolv_entry *r;
   struct ip_addr ip;
   char hostname[MAX_HOSTNAME_LEN];
   char tmp[MAX_ASCII_ADDR_LEN];
   pthread_t pid;

   r = EC_THREAD_PARAM;

   /* copy param value to stack to avoid race conditions */
   memcpy(&ip, &r->ip, sizeof(ip));
   memcpy(hostname, r->hostname, sizeof(hostname));

   ec_thread_init();

   DEBUG_MSG("resolv_passive: inserting %s -> %s into name cache",
         ip_addr_ntoa(&ip, tmp), hostname);

   /* wait for mutex and write cache entry */
   RESOLV_LOCK;
   resolv_cache_insert(&ip, hostname);
   RESOLV_UNLOCK;

   /* work done - self destroy thread */
   pid = pthread_self();
   if (!pthread_equal(pid, EC_PTHREAD_NULL))
      ec_thread_destroy(pid);

   /* only reached if not threaded */
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

