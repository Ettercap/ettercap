/*
    ettercap -- dissector portmap 

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

    $Id: ec_portmap.c,v 1.2 2004/01/18 14:29:06 lordnaga Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>

/* globals */
struct portmap_entry {
   u_int32 xid;
   u_int32 prog;
   u_int32 ver;
   u_int32 spr;
   u_int32 proto;
   SLIST_ENTRY(portmap_entry) next;
};
#define DUMP 1
#define MAP_LEN 20

typedef struct {
   u_int32 program;
   u_int32 version;
   u_char name[32];
   FUNC_DECODER_PTR(dissector);
} RPC_DISSECTOR;

extern FUNC_DECODER(dissector_mountd);

RPC_DISSECTOR Available_RPC_Dissectors[] = {
   {100005,  1, "mountd", dissector_mountd },
   {100005,  2, "mountd", dissector_mountd },
   {100005,  3, "mountd", dissector_mountd },
   {     0,  0, "", NULL }
};

SLIST_HEAD(, portmap_entry) portmap_table;

/* protos */
FUNC_DECODER(dissector_portmap);
void portmap_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init portmap_init(void)
{
   dissect_add("portmap", APP_LAYER_TCP, 111, dissector_portmap);
   dissect_add("portmap", APP_LAYER_UDP, 111, dissector_portmap);
}

FUNC_DECODER(dissector_portmap)
{
   DECLARE_DISP_PTR_END(ptr, end);
   u_int32 type, xid, proc, port, proto, program, version, offs, i;
   struct portmap_entry *pe;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* don't complain about unused var */
   (void)end;

   /* skip unuseful packets */
   if (PACKET->DATA.len < 24)
      return NULL;
   
   DEBUG_MSG("portmap --> dissector_portmap");

   /* Offsets differs from TCP to UDP (?) */
   if (PACKET->L4.proto == NL_TYPE_TCP)
      ptr += 4;

   xid  = pntol(ptr);
   proc = pntol(ptr + 20);
   type = pntol(ptr + 4);

   /* CALL */
   if (FROM_CLIENT("portmap", PACKET)) {
      if (type != 0) 
         return NULL;

      SAFE_CALLOC(pe, sizeof(struct portmap_entry), sizeof(char));
      pe->xid   = xid;
      pe->prog  = pntol(ptr + 40);
      pe->ver   = pntol(ptr + 44);
      pe->proto = pntol(ptr + 48);
      pe->spr   = PACKET->L4.proto;

      /* DUMP */
      if ( proc == 4 ) 
         pe->prog = DUMP;

      SLIST_INSERT_HEAD(&portmap_table, pe, next);

      return NULL;
   }

   /* REPLY */
   SLIST_FOREACH(pe, &portmap_table, next) {
      if (pe->xid == xid && pe->spr == PACKET->L4.proto)
         break;
   }   

   /* Unsuccess or not a reply */
   if (!pe || pntol(ptr + 8) != 0 || type != 1) 
      return NULL;

   SLIST_REMOVE(&portmap_table, pe, portmap_entry, next);

   /* GETPORT Reply */
   if (pe->prog != DUMP) {
      port = pntol(ptr + 24);

      for (i=0; Available_RPC_Dissectors[i].program != 0; i++ ) {
         if ( Available_RPC_Dissectors[i].program == pe->prog &&
              Available_RPC_Dissectors[i].version == pe->ver ) {

            if (pe->proto == IPPROTO_TCP) {
               if (dissect_on_port_level(Available_RPC_Dissectors[i].name, port, APP_LAYER_TCP) == ESUCCESS)
                  break;
               dissect_add(Available_RPC_Dissectors[i].name, APP_LAYER_TCP, port, Available_RPC_Dissectors[i].dissector);
               DISSECT_MSG("portmap : %s binds [%s] on port %d TCP\n", ip_addr_ntoa(&PACKET->L3.src, tmp),
                                                                       Available_RPC_Dissectors[i].name, 
                                                                       port);
            } else {
               if (dissect_on_port_level(Available_RPC_Dissectors[i].name, port, APP_LAYER_UDP) == ESUCCESS)
                  break;
               dissect_add(Available_RPC_Dissectors[i].name, APP_LAYER_UDP, port, Available_RPC_Dissectors[i].dissector);
               DISSECT_MSG("portmap : %s binds [%s] on port %d UDP\n", ip_addr_ntoa(&PACKET->L3.src, tmp),
                                                                       Available_RPC_Dissectors[i].name, 
                                                                       port);
            }
            break;
         }
      }
   } else { /* DUMP Reply */
      offs = 24;
      while ( (PACKET->DATA.len - offs) >= MAP_LEN ) {
         program = pntol(ptr + offs + 4);
         version = pntol(ptr + offs + 8);
         proto   = pntol(ptr + offs + 12);
         port    = pntol(ptr + offs + 16);

         for (i=0; Available_RPC_Dissectors[i].program != 0; i++) {
            if ( Available_RPC_Dissectors[i].program == program &&
                 Available_RPC_Dissectors[i].version == version ) {

               if (proto == IPPROTO_TCP) {
                  if (dissect_on_port_level(Available_RPC_Dissectors[i].name, port, APP_LAYER_TCP) == ESUCCESS)
                     break;
                  dissect_add(Available_RPC_Dissectors[i].name, APP_LAYER_TCP, port, Available_RPC_Dissectors[i].dissector);
                  DISSECT_MSG("portmap : %s binds [%s] on port %d TCP\n", ip_addr_ntoa(&PACKET->L3.src, tmp),
                                                                          Available_RPC_Dissectors[i].name, 
                                                                          port);
               } else {
                  if (dissect_on_port_level(Available_RPC_Dissectors[i].name, port, APP_LAYER_UDP) == ESUCCESS)
                     break;
                  dissect_add(Available_RPC_Dissectors[i].name, APP_LAYER_UDP, port, Available_RPC_Dissectors[i].dissector);
                  DISSECT_MSG("portmap : %s binds [%s] on port %d UDP\n", ip_addr_ntoa(&PACKET->L3.src, tmp),
                                                                          Available_RPC_Dissectors[i].name, 
                                                                          port);
               }	 
               break;
            }
         }
         offs += MAP_LEN;
      }
   }
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

