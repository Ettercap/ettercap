/*
    ettercap -- top half and dispatching module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_dispatcher.c,v 1.10 2003/03/31 21:46:49 alor Exp $
*/

#include <ec.h>
#include <ec_threads.h>
#include <ec_hook.h>


/* this is the PO queue from bottom to top half */
struct po_queue_entry {
   struct packet_object *po;
   SIMPLEQ_ENTRY(po_queue_entry) next;
};

static SIMPLEQ_HEAD(, po_queue_entry) po_queue = SIMPLEQ_HEAD_INITIALIZER(po_queue);

/* global mutex on interface */

static pthread_mutex_t po_mutex = PTHREAD_MUTEX_INITIALIZER;
#define PO_QUEUE_LOCK     do{ pthread_mutex_lock(&po_mutex); }while(0)
#define PO_QUEUE_UNLOCK   do{ pthread_mutex_unlock(&po_mutex); }while(0)

/* proto */

void top_half_queue_add(struct packet_object *po);
EC_THREAD_FUNC(top_half);

/* XXX - remove me */
void __init init_packet_print(void);

/*******************************************/

/*
 * top half function
 * it is the dispatcher for the various methods
 * which need to process packet objects 
 * created by the bottom_half (capture).
 * it read the queue created by top_half_queue_add()
 * and deliver the po to all the registered functions
 */

EC_THREAD_FUNC(top_half)
{
   struct po_queue_entry *e;
   
   DEBUG_MSG("top_half activated !");
  
   ec_thread_init();

   LOOP { 
     
      /* XXX - this is responsible for the responsiveness */
      usleep(1); 
      
      CANCELLATION_POINT();
      
      /* the queue is updated by other threads */
      PO_QUEUE_LOCK;
      e = SIMPLEQ_FIRST(&po_queue);
      if (e == NULL) {
         PO_QUEUE_UNLOCK;
      
         /* XXX - exit if feof */
         if (GBL_UI->type == UI_CONSOLE || GBL_UI->type == UI_DAEMONIZE) {
            if (GBL_OPTIONS->read && GBL_PCAP->dump_size == GBL_PCAP->dump_off) {
               USER_MSG("\nEnd of dump file...\n");
               clean_exit(0);
            }
         }
         continue;
      }
   
      
      /* HOOK_POINT: DISPATCHER */
      hook_point(HOOK_DISPATCHER, e->po);
      
      SIMPLEQ_REMOVE_HEAD(&po_queue, e, next);
      packet_destroy_object(&e->po);
      SAFE_FREE(e);
      
      PO_QUEUE_UNLOCK;
   } 
}

/* 
 * add a packet to the top half queue.
 * this fuction is called by the bottom half thread
 */

void top_half_queue_add(struct packet_object *po)
{
   struct po_queue_entry *e;

   e = calloc(1, sizeof(struct po_queue_entry));
   ON_ERROR(e, NULL, "can't allocate memory");
   
   e->po = packet_dup(po);
   
   /* add the message to the queue */
   PO_QUEUE_LOCK;
   SIMPLEQ_INSERT_TAIL(&po_queue, e, next);
   PO_QUEUE_UNLOCK;
}


/* XXX - remove this */
void __init init_packet_print(void)
{
   //hook_add(HOOK_DISPATCHER, &packet_print);
}

/* EOF */

// vim:ts=3:expandtab

