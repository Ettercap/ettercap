/*
    ettercap -- connection list handling module

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

    $Id: ec_conntrack.c,v 1.5 2003/08/07 20:25:18 alor Exp $
*/

#include <ec.h>
#include <ec_threads.h>
#include <ec_packet.h>
#include <ec_proto.h>
#include <ec_hook.h>
#include <ec_conntrack.h>
#include <ec_hash.h>

/* globals */

struct conn_tail {
   struct conn_object *co;
   struct conn_hash_search *cs;
   TAILQ_ENTRY(conn_tail) next;
};

/* the hash table used to index the tailq */
struct conn_hash_search {
   struct conn_tail *cl;
   LIST_ENTRY(conn_hash_search) next;
};

#define TABBIT    10             /* 2^10 bit tab entries: 1024 LISTS */
#define TABSIZE   (1 << TABBIT)
#define TABMASK   (TABSIZE - 1)

/*
 * the connection list.
 * this list is created adding new element in the tail.
 * the search method is established in the search function. 
 * an hash table is used and it is double-linked with the 
 * tailq so from each element you can delete the corresponding
 * in the tailq or viceversa
 */
static TAILQ_HEAD(conn_head, conn_tail) conntrack_tail_head = TAILQ_HEAD_INITIALIZER(conntrack_tail_head);
static LIST_HEAD(, conn_hash_search) conntrack_search_head[TABSIZE];

/* global mutex on connections list */

static pthread_mutex_t conntrack_mutex = PTHREAD_MUTEX_INITIALIZER;
#define CONNTRACK_LOCK     do{ pthread_mutex_lock(&conntrack_mutex); }while(0)
#define CONNTRACK_UNLOCK   do{ pthread_mutex_unlock(&conntrack_mutex); }while(0)

/* protos */

void __init conntrack_init(void);

static void conntrack_parse(struct packet_object *po);
static u_int32 conntrack_hash(struct packet_object *po);
static struct conn_object *conntrack_search(struct packet_object *po);
static void conntrack_update(struct conn_object *co, struct packet_object *po);
static void conntrack_add(struct packet_object *po);
static void conntrack_del(struct conn_object *co);
static int conntrack_match(struct conn_object *co, struct packet_object *po);
static int conntrack_match(struct conn_object *co, struct packet_object *po);
EC_THREAD_FUNC(conntrack_timeouter);
int conntrack_print(u_int32 spos, u_int32 epos, void (*func)(int n, struct conn_object *co));

/************************************************/
  
/*
 * add the hook function
 */
void __init conntrack_init(void)
{
   /* receive all the top half packets */
   hook_add(HOOK_DISPATCHER, &conntrack_parse);
}

/*
 * the conntrack main()
 */
static void conntrack_parse(struct packet_object *po)
{
   struct conn_object *conn;

   CONNTRACK_LOCK;
   
   /* search if the connection already exists */
   conn = conntrack_search(po);

   /* update if it was found, else add to the list */
   if (conn)
      conntrack_update(conn, po);
   else
      conntrack_add(po);
   
   CONNTRACK_UNLOCK;
}

/* 
 * calculate the hash for a packet object 
 */
static u_int32 conntrack_hash(struct packet_object *po)
{
   u_int32 hash_array[4];

   /* 
    * put them in an array and then compute the hash on the array.
    * use XOR on src and dst because the hash must be equal for 
    * packets from dst to src and viceversa
    */
   hash_array[0] = fnv_32((u_char *)&po->L2.src, ETH_ADDR_LEN) ^
                   fnv_32((u_char *)&po->L2.dst, ETH_ADDR_LEN);
   hash_array[1] = fnv_32((u_char *)&po->L3.src, sizeof(struct ip_addr)) ^
                   fnv_32((u_char *)&po->L3.dst, sizeof(struct ip_addr));
   hash_array[2] = po->L4.src ^ po->L4.dst;
   hash_array[3] = po->L4.proto;

   /* compute the resulting hash */
   return fnv_32((u_char *)&hash_array, sizeof(hash_array)) & TABMASK;
}

/* 
 * search the connection in the connection table
 * and return the pointer.
 */
static struct conn_object *conntrack_search(struct packet_object *po)
{
   struct conn_hash_search *cs;
   u_int32 h;
  
   /* use the hash table to find the connection in the tailq */
   h = conntrack_hash(po);
   
   LIST_FOREACH(cs, &conntrack_search_head[h], next) {
      if (conntrack_match(cs->cl->co, po) == ESUCCESS) {
         return cs->cl->co;
      }
   }

   return NULL;
#if 0   
   struct conn_tail *cl;
   
   /* search in the list sequentially */
   TAILQ_FOREACH(cl, &conntrack_tail_head, next) {
      if (conntrack_match(cl->co, po) == ESUCCESS) {
         return cl->co;
      }
   }

   return NULL;
#endif
}


/*
 * update the variable parameters in the connection struct.
 * the status, the buffer and the timestamp will be updated
 */
static void conntrack_update(struct conn_object *co, struct packet_object *po)
{
   /* update the timestamp */
   gettimeofday(&co->ts, 0);
  
   /* update the status for TCP conn */
   if (po->L4.flags & TH_SYN)
      co->status = CONN_OPENING;
   else if (po->L4.flags & TH_FIN)
      co->status = CONN_CLOSING;
   else if (po->L4.flags & TH_ACK) { 
      /* syn + ack,  ack */
      if (co->status == CONN_OPENING )
         co->status = CONN_OPEN;
      /* fin + ack,  ack */
      else if (co->status == CONN_CLOSING)
         co->status = CONN_CLOSED;
   } 

   if (po->L4.flags & TH_PSH)
      co->status = CONN_ACTIVE;
   
   if (po->L4.flags & TH_RST)
      co->status = CONN_KILLED;
      
   /* update the buffer */
   connbuf_add(&co->data, po);
  

   /* update the status for UDP conn */
   if (po->L4.proto == NL_TYPE_UDP)
      co->status = CONN_ACTIVE;
   
   /* 
    * update the byte count 
    * use DATA.len and not DATA.disp_len to have an
    * effective count of byte trasferred, disp_data
    * may be longer or shorted than DATA.data
    */
   co->xferred += po->DATA.len;

   /* 
    * update the password 
    * always overwrite the old one, a better one may
    * has been collected...
    */
   if (po->DISSECTOR.user) {
      SAFE_FREE(co->DISSECTOR.user);
      SAFE_FREE(co->DISSECTOR.pass);
      SAFE_FREE(co->DISSECTOR.info);
      co->DISSECTOR.user = strdup(po->DISSECTOR.user);
      if (po->DISSECTOR.pass)
         co->DISSECTOR.pass = strdup(po->DISSECTOR.pass);
      if (po->DISSECTOR.info)
         co->DISSECTOR.info = strdup(po->DISSECTOR.info);
   }
   
   /* execute the hookpoint */
   /* XXX - HOOK_CONN */
}


/*
 * create a new entry in the tail 
 */
static void conntrack_add(struct packet_object *po)
{
   struct conn_tail *cl;
   struct conn_hash_search *cs;

   DEBUG_MSG("conntrack_add: NEW CONNECTION");
   
   /* alloc the list element */
   cl = calloc(1, sizeof(struct conn_tail));
   ON_ERROR(cl, NULL, "Can't allocate memory");

   /* alloc the conn object in the element */
   cl->co = calloc(1, sizeof(struct conn_object));
   ON_ERROR(cl->co, NULL, "Can't allocate memory");

   /* 
    * here we create the connection.
    * this is the first packet seen...
    * addr1 will be the source and addr2 the dest 
    */

   /* fill the addresses */
   memcpy(&cl->co->L2_addr1, &po->L2.src, ETH_ADDR_LEN);
   memcpy(&cl->co->L2_addr2, &po->L2.dst, ETH_ADDR_LEN);

   memcpy(&cl->co->L3_addr1, &po->L3.src, sizeof(struct ip_addr));
   memcpy(&cl->co->L3_addr2, &po->L3.dst, sizeof(struct ip_addr));

   /* copy the port */
   cl->co->L4_addr1 = po->L4.src;
   cl->co->L4_addr2 = po->L4.dst;
   cl->co->L4_proto = po->L4.proto;
 
   /* initialize the connection buffer */
   connbuf_init(&cl->co->data, GBL_CONF->connection_buffer);
   
   /* update the connection entry */
   conntrack_update(cl->co, po);
   
   /* alloc the hash table element */
   cs = calloc(1, sizeof(struct conn_hash_search));
   ON_ERROR(cs, NULL, "Can't allocate memory");
   
   /* set the pointer to the list */
   cs->cl = cl;
  
   /* 
    * set the pointer to the element in the hash table 
    * it is used when a connection is deleted because
    * even the element in the hash table must be deleted
    */
   cl->cs = cs;
   
   /* insert the new connection in the tail */
   TAILQ_INSERT_TAIL(&conntrack_tail_head, cl, next);
   /* insert the new connection in the tail */
   LIST_INSERT_HEAD(&conntrack_search_head[conntrack_hash(po)], cs, next);
}

/*
 * is the packet object belonging to this connection ?
 */
static int conntrack_match(struct conn_object *co, struct packet_object *po)
{
   /* different protocol, they don't match */
   if (co->L4_proto != po->L4.proto)
      return -EINVALID;

   /* match it in one way... */
   if (!memcmp(co->L2_addr1, po->L2.src, ETH_ADDR_LEN) &&
       !memcmp(co->L2_addr2, po->L2.dst, ETH_ADDR_LEN) &&
       !ip_addr_cmp(&co->L3_addr1, &po->L3.src) &&
       !ip_addr_cmp(&co->L3_addr2, &po->L3.dst) &&
       co->L4_addr1 == po->L4.src &&
       co->L4_addr2 == po->L4.dst)
      return ESUCCESS;

   /* ...and in the other */
   if (!memcmp(co->L2_addr1, po->L2.dst, ETH_ADDR_LEN) &&
       !memcmp(co->L2_addr2, po->L2.src, ETH_ADDR_LEN) &&
       !ip_addr_cmp(&co->L3_addr1, &po->L3.dst) &&
       !ip_addr_cmp(&co->L3_addr2, &po->L3.src) &&
       co->L4_addr1 == po->L4.dst &&
       co->L4_addr2 == po->L4.src)
      return ESUCCESS;
   
   return -ENOMATCH;
}

/* 
 * erase a connection object
 */
static void conntrack_del(struct conn_object *co)
{
   connbuf_wipe(&co->data);
   SAFE_FREE(co);
}

/*
 * print the connection list from spos to epos.
 * you can use 0, MAX_INT to print all the connections
 */
int conntrack_print(u_int32 spos, u_int32 epos, void (*func)(int n, struct conn_object *co))
{
   struct conn_tail *cl;
   u_int32 i = 1, count = 0;
  
   CONNTRACK_LOCK;
   
   /* search in the list */
   TAILQ_FOREACH(cl, &conntrack_tail_head, next) {
      /* print within the given range */
      if (i >= spos && i <= epos) {
         /* update the couter */
         count++;
         /* callback */
         func(count, cl->co);

      } 
      i++;
      /* speed up the exit */
      if (i > epos)
         break;
   }

   CONNTRACK_UNLOCK;

   return count;
}


EC_THREAD_FUNC(conntrack_timeouter)
{
   struct timeval ts;
   struct timeval diff;
   struct conn_tail *cl;
   struct conn_tail *old = NULL;
  
   LOOP {

      /* 
       * sleep for the maximum time possible
       * (determined as the minumum of the timeouts)
       */
      sleep(MIN(GBL_CONF->connection_idle, GBL_CONF->connection_timeout));
     
      DEBUG_MSG("conntrack_timeouter: %d", MIN(GBL_CONF->connection_idle, GBL_CONF->connection_timeout));
      
      /* get current time */
      gettimeofday(&ts, NULL);
     
      /*
       * the timeouter is the only thread that erase a connection
       * so we are sure that the list will be consistent till the
       * end.
       * we can lock and unlock every time we handle an element of 
       * the list to permit the conntrack functions to operate on the
       * list even when timeouter goes thru the list
       */
      TAILQ_FOREACH(cl, &conntrack_tail_head, next) {
         
         CONNTRACK_LOCK;
         
         /* calculate the difference */
         time_sub(&ts, &cl->co->ts, &diff);
         
         /* delete pending request */
         SAFE_FREE(old);
         /* 
          * update it only if the staus is active,
          * all the other status must be left as they are
          */
         if (cl->co->status == CONN_ACTIVE && diff.tv_sec >= GBL_CONF->connection_idle)
            cl->co->status = CONN_IDLE;
         
         /* delete the timeouted connections */
         if (diff.tv_sec >= GBL_CONF->connection_timeout) {
            /* wipe the connection */
            conntrack_del(cl->co);
            /* remove the element in the hash table */
            LIST_REMOVE(cl->cs, next);
            SAFE_FREE(cl->cs);
            /* remove the element in the tailq */
            TAILQ_REMOVE(&conntrack_tail_head, cl, next);
            old = cl;
         }

         CONNTRACK_UNLOCK;
      }
      /* if it was the last one */
      SAFE_FREE(old);
   }
}

/* EOF */

// vim:ts=3:expandtab

