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
#ifdef SIGUSR1
#include <ec_signals.h>
#else
#include <ec_sleep.h>
#endif

#ifndef OS_WINDOWS
   #include <netdb.h>
#endif

#define TABBIT    9 /* 2^9 bit tab entries: 512 SLISTS */
#define TABSIZE   (1UL<<TABBIT)
#define TABMASK   (TABSIZE-1) /* to mask fnv_1 hash algorithm */

/* globals */
static pthread_mutex_t resolvc_mutex = PTHREAD_MUTEX_INITIALIZER;
#define RESOLVC_LOCK do{pthread_mutex_lock(&resolvc_mutex);}while(0)
#define RESOLVC_UNLOCK do{pthread_mutex_unlock(&resolvc_mutex);}while(0)

static pthread_mutex_t resolvq_mutex = PTHREAD_MUTEX_INITIALIZER;
#define RESOLVQ_LOCK do{pthread_mutex_lock(&resolvq_mutex);}while(0)
#define RESOLVQ_UNLOCK do{pthread_mutex_unlock(&resolvq_mutex);}while(0)

#define NUM_RESOLV_THREADS 3
#define MAX_RESOLVQ_LEN    512
pthread_t resolv_threads[NUM_RESOLV_THREADS];

static STAILQ_HEAD(, queue_entry) resolv_queue_head;
static SLIST_HEAD(, resolv_entry) resolv_cache_head[TABSIZE];

struct queue_entry {
   struct ip_addr ip;
   STAILQ_ENTRY(queue_entry) next;
};

struct resolv_entry {
   struct ip_addr ip;
   char *hostname;
   SLIST_ENTRY(resolv_entry) next;
};

/* protos */
EC_THREAD_FUNC(resolv_thread_main);
static int resolv_dns(struct ip_addr *ip, char *hostname);
static int resolv_cache_search(struct ip_addr *ip, char *name);
void resolv_cache_insert(struct ip_addr *ip, char *name);
static int resolv_queue_push(struct ip_addr *ip);
static int resolv_queue_pop(struct ip_addr *ip);

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
#ifdef SIGUSR1
   int i;
#endif
   int ret = 0;
   char tmp[MAX_ASCII_ADDR_LEN];

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
   if (!EC_GBL_OPTIONS->resolve)
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
   RESOLVQ_LOCK;
   ret = resolv_queue_push(ip);
   RESOLVQ_UNLOCK;

#ifdef SIGUSR1
   /* Sending signal of updated resolv queue to all resolv threads */
   if (ret == E_SUCCESS)
      for (i = 0; i < NUM_RESOLV_THREADS; i++)
         pthread_kill(resolv_threads[i], SIGUSR1);
#endif

   return -E_NOMATCH;
}

/*
 * initialize <NUM_RESOLV_THREADS> number of threads
 * acting as the working horses for the IP to name
 * resolution in the background
 */
void resolv_thread_init(void)
{
   int i;
   char thread_name[16]; 

   DEBUG_MSG("resolv_thread_init()");

   /* initialize queue */
   STAILQ_INIT(&resolv_queue_head);

   /* spawn resolution worker threads */
   for (i = 0; i < NUM_RESOLV_THREADS; i++) {
      snprintf(thread_name, sizeof(thread_name), "resolver-%d", i+1);
      resolv_threads[i] = ec_thread_new(thread_name, "DNS resolver", 
            &resolv_thread_main, NULL);
   }
}

/*
 * gracefully shut down name resolution threads:
 * - destroy all created threads
 * - flush and free resolv queue completely
 */
void resolv_thread_fini(void)
{
   int i;
   struct queue_entry *entry;

   DEBUG_MSG("resolv_thread_fini()");

   /* destroy resolution worker threads */
   for (i = 0; i < NUM_RESOLV_THREADS; i++)
      /* check if thread exists */
      if (strcmp(ec_thread_getname(resolv_threads[i]), "NR_THREAD"))
         /* send cancel signal to thread */
         ec_thread_destroy(resolv_threads[i]);
   
   /* empty queue and free allocated memory if applicable */
   RESOLVQ_LOCK;
   while (!STAILQ_EMPTY(&resolv_queue_head)) {
      entry = STAILQ_FIRST(&resolv_queue_head);
      STAILQ_REMOVE_HEAD(&resolv_queue_head, entry, next);
      SAFE_FREE(entry);
   }
   RESOLVQ_UNLOCK;
}

/*
 * this function the resolution threads wait in this function
 * until a IP address is to be resolved and inserted into the 
 * name cache. With many IP hosts on the link, the number of
 * parallel threads can be increased by NUM_RESOLV_THREADS.
 */
EC_THREAD_FUNC(resolv_thread_main)
{
   struct ip_addr ip;
   char host[MAX_HOSTNAME_LEN];
   char tmp[MAX_ASCII_ADDR_LEN];
   int ret = 0;
#ifdef SIGUSR1
   int sig;
   sigset_t sigmask;
#endif

   /* variable not used */
   (void) EC_THREAD_PARAM;

   /* init the thread */
   ec_thread_init();

#ifdef SIGUSR1
   /* initialize signal mask non-blocking */
   sigfillset(&sigmask);
   pthread_sigmask(SIG_UNBLOCK, &sigmask, NULL);
#endif

   /* wait for something to do */
   LOOP {
      /* provide the chance to cancel the thread */
      CANCELLATION_POINT();

      /* check if something is in the queue */
      RESOLVQ_LOCK;
      ret = resolv_queue_pop(&ip);
      RESOLVQ_UNLOCK;

      /* nothing to do - booring !! */
      if (ret != E_SUCCESS) {
         /* wait if something new comes in to do */
#ifdef SIGUSR1
         while (sigwait(&sigmask, &sig) == 0)
            if (sig == SIGUSR1)
               break;
#else
         ec_usleep(SEC2MICRO(1));
#endif
         /* broke off waiting - start over checking the queue */
         continue;
      }

      /*
       * yeah, we got something to do - lets rock..... 
       * In any case the name cache is updated so that a second call of
       * of host_iptoa() gets a result.
       */
      if (resolv_dns(&ip, host)) {
         /* 
          * insert the "" in the cache so we don't search for
          * non existent hosts every new query.
          */
         DEBUG_MSG("resolv_dns: not found for %s", 
               ip_addr_ntoa(&ip, tmp));

         RESOLVC_LOCK;
         resolv_cache_insert(&ip, "");
         RESOLVC_UNLOCK;
      } else {
         DEBUG_MSG("resolv_dns: %s found for %s", host, 
               ip_addr_ntoa(&ip, tmp));

         /* insert the result in the cache for later use */
         RESOLVC_LOCK;
         resolv_cache_insert(&ip, host);
         RESOLVC_UNLOCK;
      }
   }

   return NULL;
}

/* 
 * perform the ip to name resolution as a dedicated thread.
 */
static int resolv_dns(struct ip_addr *ip, char *hostname)
{
   struct sockaddr_storage ss;
   struct sockaddr_in *sa4;
   struct sockaddr_in6 *sa6;
   socklen_t sa_len;
   
   /* prepare struct */
   switch (ntohs(ip->addr_type)) {
      case AF_INET:
         sa4 = (struct sockaddr_in *)&ss;
         sa4->sin_family = AF_INET;
         ip_addr_cpy((u_char*)&sa4->sin_addr.s_addr, ip);
         sa_len = sizeof(struct sockaddr_in);
      break;
      case AF_INET6:
         sa6 = (struct sockaddr_in6 *)&ss;
         sa6->sin6_family = AF_INET6;
         ip_addr_cpy((u_char*)&sa6->sin6_addr.s6_addr, ip);
         sa_len = sizeof(struct sockaddr_in6);
      break;
   }

   /* resolve */
   return getnameinfo((struct sockaddr *)&ss, sa_len, 
            hostname, MAX_HOSTNAME_LEN, NULL, 0, NI_NAMEREQD);

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
   /* wait for mutex and write cache entry */
   RESOLVC_LOCK;
   resolv_cache_insert(ip, name);
   RESOLVC_UNLOCK;
}

/*
 * pushing a resolution request to the queue
 */
int resolv_queue_push(struct ip_addr *ip)
{
   struct queue_entry *entry;
   char tmp[MAX_ASCII_ADDR_LEN];
   int i = 0;

   /* avoid pushing duplicate IPs to the queue */
   STAILQ_FOREACH(entry, &resolv_queue_head, next) {
      if (!ip_addr_cmp(&entry->ip, ip))
         return -E_DUPLICATE;

      /* count queue length */
      i++;
   }

   /* avoid memory exhaustion - limit queue length */
   if (i >= MAX_RESOLVQ_LEN) {
      DEBUG_MSG("resolv_queue_push(): maximum resolv queue length reached");
      return -E_INVALID;
   }

   /* allocate memory for new queue entry and add to queue */
   SAFE_CALLOC(entry, 1, sizeof(struct queue_entry));
   memcpy(&entry->ip, ip, sizeof(struct ip_addr));

   STAILQ_INSERT_TAIL(&resolv_queue_head, entry, next);

   DEBUG_MSG("resolv_queue_push(): %s queued", ip_addr_ntoa(ip, tmp));

   return E_SUCCESS;

}

/*
 * popping and returning a resolution request from the queue
 */
int resolv_queue_pop(struct ip_addr *ip)
{
   struct queue_entry *entry;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* check if queue is emtpy */
   if (STAILQ_EMPTY(&resolv_queue_head))
      return -E_NOMATCH;

   /* copy IP address to caller's memory */
   entry = STAILQ_FIRST(&resolv_queue_head);
   memcpy(ip, &entry->ip, sizeof(struct ip_addr));

   /* remove entry from queue and free memory */
   STAILQ_REMOVE_HEAD(&resolv_queue_head, entry, next);
   SAFE_FREE(entry);

   DEBUG_MSG("resolv_queue_pop(): %s returned and removed from queue",
         ip_addr_ntoa(ip, tmp));

   return E_SUCCESS;
}

/* EOF */

// vim:ts=3:expandtab

