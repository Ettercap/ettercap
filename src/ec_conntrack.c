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

    $Id: ec_conntrack.c,v 1.3 2003/08/04 13:59:07 alor Exp $
*/

#include <ec.h>
#include <ec_threads.h>
#include <ec_packet.h>
#include <ec_proto.h>
#include <ec_hook.h>
#include <ec_conntrack.h>

/* globals */

struct conn_tail {
   struct conn_object *co;
   TAILQ_ENTRY(conn_tail) next;
};

/*
 * the connection list.
 * this list is created adding new element in the tail.
 * the search method is established in the search function 
 * (using an hash table).
 */
static TAILQ_HEAD(conn_head, conn_tail) conntrack_tail_head = TAILQ_HEAD_INITIALIZER(conntrack_tail_head);

/* global mutex on connections list */

static pthread_mutex_t conntrack_mutex = PTHREAD_MUTEX_INITIALIZER;
#define CONNTRACK_LOCK     do{ pthread_mutex_lock(&conntrack_mutex); }while(0)
#define CONNTRACK_UNLOCK   do{ pthread_mutex_unlock(&conntrack_mutex); }while(0)

/* protos */

void __init conntrack_init(void);

static void conntrack_parse(struct packet_object *po);
static struct conn_object *conntrack_search(struct packet_object *po);
static void conntrack_update(struct conn_object *co, struct packet_object *po);
static void conntrack_add(struct packet_object *po);
static int conntrack_match(struct conn_object *co, struct packet_object *po);

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

return;
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
 * search the connection in the connection table
 * and return the pointer.
 */
static struct conn_object *conntrack_search(struct packet_object *po)
{
   struct conn_tail *cl;
  
   /* XXX - use an hash table to find the connection */
   
   /* search in the list */
   TAILQ_FOREACH(cl, &conntrack_tail_head, next) {
      if (conntrack_match(cl->co, po)) {
printf("found\n");         
         return cl->co;
      }
   }
printf("NOT found\n");         

   return NULL;
}


/*
 * update the variable parameters in the connection struct.
 * the status, the buffer and the timestamp will be updated
 */
static void conntrack_update(struct conn_object *co, struct packet_object *po)
{
   /* update the timestamp */
   gettimeofday(&co->ts, 0);
  
   /* update the status */
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
  
   /* 
    * update the byte count 
    * use DATA.len and not DATA.disp_len to have an
    * effective count of byte trasferred, disp_data
    * may be longer or shorted than DATA.data
    */
   co->xferred += po->DATA.len;
   
   /* execute the hookpoint */
   /* XXX - HOOK_CONN */
}


/*
 * create a new entry in the tail 
 */
static void conntrack_add(struct packet_object *po)
{
   struct conn_tail *cl;

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
   
   /* insert the new connection in the tail */
   TAILQ_INSERT_TAIL(&conntrack_tail_head, cl, next);
   
}

/*
 * is the packet object belonging to this connection ?
 */
static int conntrack_match(struct conn_object *co, struct packet_object *po)
{
   return 0;
}

/* EOF */

// vim:ts=3:expandtab

