/*
    ettercap -- TCP/UDP injection module

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

    $Id: ec_inject.c,v 1.6 2003/10/14 21:20:47 lordnaga Exp $
*/

#include <ec.h>
#include <ec_packet.h>
#include <ec_inject.h>
#include <ec_send.h>

/* globals */
static SLIST_HEAD (, inj_entry) injectors_table;

struct inj_entry {
   u_int32 type;
   u_int8 level;
   FUNC_INJECTOR_PTR(injector);
   SLIST_ENTRY (inj_entry) next;
};


/* proto */

int inject_buffer(struct packet_object *po);
void add_injector(u_int8 level, u_int32 type, FUNC_INJECTOR_PTR(injector));
void * get_injector(u_int8 level, u_int32 type);
size_t inject_protocol(struct packet_object *po);
void inject_split_data(struct packet_object *po);

/*******************************************/

/*
 * add an injector to the injector table 
 */
void add_injector(u_int8 level, u_int32 type, FUNC_INJECTOR_PTR(injector))
{
   struct inj_entry *e;

   SAFE_CALLOC(e, 1, sizeof(struct inj_entry));

   e->level = level;
   e->type = type;
   e->injector = injector;

   SLIST_INSERT_HEAD (&injectors_table, e, next); 
   
   return;
}

/*
 * get an injector from the injector table 
 */

void * get_injector(u_int8 level, u_int32 type)
{
   struct inj_entry *e;
   
   SLIST_FOREACH (e, &injectors_table, next) {
      if (e->level == level && e->type == type) 
         return (void *)e->injector;
   }

   return NULL;
}


size_t inject_protocol(struct packet_object *po)
{
   FUNC_INJECTOR_PTR(injector);
   size_t len = 0;
      
   injector = get_injector(CHAIN_ENTRY, po->L4.proto);
   
   if (injector == NULL) 
      return 0;

   /* Start the injector chain */
   if (injector(po, &len) == ESUCCESS)
      return len;
      
   /* if there's an error */
   return 0;              
}


/*
 * the idea is that the application will pass a buffer
 * and a len, and this function will split up the 
 * buffer to fit the MTU and inject the resulting packet(s).
 */
int inject_buffer(struct packet_object *po)
{

   /* the packet_object passed is a fake.
    * it is used only to pass:
    *    - IP source and dest
    *    - IPPROTO
    *    - (tcp/udp) port source and dest
    * all the field have to be filled int and the buffer
    * has to be alloc'd
    */       
   struct packet_object *pd;
   size_t injected;
   u_char *pck_buf;
   int ret = ESUCCESS;
  
   /* we can't inject in unoffensive mode or in bridge mode */
   if (GBL_OPTIONS->unoffensive || GBL_OPTIONS->iface_bridge) {
      SAFE_FREE(po->DATA.inject);
      return -EINVALID;
   }
   
   /* Duplicate the packet to modify the payload buffer */
   pd = packet_dup(po);

   /* Allocate memory for the packet (double sized)*/
   SAFE_CALLOC(pck_buf, 1, (GBL_IFACE->mtu * 2));
         
   /* Loop until there's data to send */
   do {
   
      /* 
       * Slide to middle. First part is for header's stack'ing.
       * Second part is for packet data. 
       */
      pd->packet = pck_buf + GBL_IFACE->mtu;

      /* Start the injector cascade */
      injected = inject_protocol(pd);
      
      if (injected == 0) {
         ret = -ENOTHANDLED;
         break;
      }
      
      /* Send on the wire */ 
      send_to_L3(pd);
      
      /* Ready to inject the rest */
      pd->DATA.inject_len -= injected;
      pd->DATA.inject += injected;
   } while (pd->DATA.inject_len);
   
   /* we cannot use packet_object_destroy because
    * the packet is not yet in the queue to tophalf.
    * so we have to free the duplicates by hand.
    */ 
   SAFE_FREE(pck_buf);
   SAFE_FREE(pd->DATA.disp_data);
   SAFE_FREE(pd);
   
   return ret;
}

void inject_split_data(struct packet_object *po) 
{
   size_t max_len;
   
   max_len = GBL_IFACE->mtu - (po->L4.header - (po->packet + po->L2.len) + po->L4.len);

   /* the packet has exceeded the MTU */
   if (po->DATA.len > max_len) {
      po->DATA.inject = po->DATA.data + max_len;
      po->DATA.inject_len = po->DATA.len - max_len;
      po->DATA.delta -= po->DATA.len - max_len;
      po->DATA.len = max_len;
   } 
}

/* EOF */

// vim:ts=3:expandtab

