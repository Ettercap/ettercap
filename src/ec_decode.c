/*
    ettercap -- decoder module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_decode.c,v 1.1 2003/03/08 13:53:38 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dispatcher.h>
#include <ec_threads.h>
#include <ec_ui.h>
#include <ec_packet.h>

#include <pcap.h>

/* globals */

static FUNC_DECODER_PTR(l2_decoder);

static SLIST_HEAD (, dec_entry) decoders_table;

struct dec_entry {
   u_int32 type;
   u_int8 level;
   FUNC_DECODER_PTR(decoder);
   SLIST_ENTRY (dec_entry) next;
};


/* protos */

void __init data_init(void);
FUNC_DECODER(decode_data);

void ec_decode(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt);
int set_L2_decoder(u_int16 dlt);
void add_decoder(u_int8 level, u_int32 type, FUNC_DECODER_PTR(decoder));
void del_decoder(u_int8 level, u_int32 type);
void * get_decoder(u_int8 level, u_int32 type);


/*******************************************/


void ec_decode(u_char *u, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
   struct packet_object *po;
   int len;
   u_char *data;
   int datalen;
  
   ec_thread_testcancel();
  
   USER_MSG("\n***************************************************************\n");
   USER_MSG("ec_get_packets (one packet dispatched from pcap)\n");

   USER_MSG("CAPTURED: 0x%04x bytes\n", pkthdr->caplen);
   
   /* dump packet to file if specified on command line */
   if (GBL_OPTIONS->dump)
      pcap_dump((u_char *)GBL_PCAP->dump, pkthdr, pkt);
  
   /* extract data and datalen from pcap packet */
   data = (u_char *)pkt;
   datalen = pkthdr->caplen;
   
   /* alloc the packet object structure to be passet through decoders */
   packet_create_object(&po, data, datalen);
  
   /* XXX -- HOOK POINT: RECEIVED */ 
   
   /* 
    * by default the packet should not be processed by ettercap.
    * if the sniffing filter matches it, the flag will be reset.
    */
   po->flags |= PO_IGNORE;
  
   /* 
    * start the analisys through the decoders stack 
    *
    * if the packet can be handled it will reach the top of the stack
    * where the decoder_data will add it to the top_half queue,
    * else the packet will not be handled but it should be forwarded
    */
   l2_decoder(data, datalen, &len, po);
   
   /* XXX -- HOOK POINT: DECODED */ 
   
   /* 
    * use the sniffing method funcion to forward the packet 
    * do NOT forward OUTGOING packet !!
    * they are forwarded packet and we MUST avoid infinite loop !
    */
   if (!(po->flags & PO_OUTGOING) ) {
      /* XXX -- HOOK POINT: PRE_FORWARD */ 
      EXECUTE(GBL_SNIFF->forward, po);
   }
   
   /* free the structure */
   packet_destroy_object(&po);
   
   return;
}

/* register the data decoder */
void __init data_init(void)
{
   add_decoder(APP_LAYER, PL_DEFAULT, decode_data);
}

/* 
 * if the packet reach the top of the stack (it can be handled),
 * this decoder is invoked
 */

FUNC_DECODER(decode_data)
{
   
   /* XXX -- HOOK POINT: HANDLED */ 

   /* reset the flag PO_INGNORE if the packet should be processed */
   EXECUTE(GBL_SNIFF->display, po);

   /* 
    * the display engine has stated that this
    * packet should not be processed by us.
    */
   if ( (po->flags & PO_IGNORE) || 
        (GBL_SNIFF->type != SM_CLASSIC && po->flags & PO_OUTGOING) )
      return NULL;
   
   /*
    * here we can filter the content of the packet.
    * the injection is done elsewhere.
    */
      
   // fiter_packet(po);
   
   /* XXX -- HOOK POINT: FILTER */ 
   
   /* 
    * add the packet to the queue and return.
    * we must be fast here !
    */
   top_half_queue_add(po);     

   return NULL;
}
      
/*
 * set the L2 decoder and the pcap offset.
 * lookup the decoders_table to find wich decoder are
 * available
 */

int set_L2_decoder(u_int16 dlt)
{
   struct dec_entry *e;

   SLIST_FOREACH (e, &decoders_table, next) {
      if (e->level == 2 && e->type == dlt) {
         DEBUG_MSG("DLT = %d : decoder found !", dlt);
         l2_decoder = e->decoder;
         return ESUCCESS;
      }
   }

   /* error NOT FOUND */
   return -ENOTFOUND;
}

/*
 * add a decoder to the decoders table 
 */

void add_decoder(u_int8 level, u_int32 type, FUNC_DECODER_PTR(decoder))
{
   struct dec_entry *e;

   e = calloc(1, sizeof(struct dec_entry));
   ON_ERROR(e, NULL, "can't allocate memory");

   e->level = level;
   e->type = type;
   e->decoder = decoder;

   SLIST_INSERT_HEAD (&decoders_table, e, next); 

   return;
}

/*
 * get a decoder from the decoders table 
 */

void * get_decoder(u_int8 level, u_int32 type)
{
   struct dec_entry *e;

   SLIST_FOREACH (e, &decoders_table, next) {
      if (e->level == level && e->type == type)
         return (void *)e->decoder;
   }

/*   DEBUG_MSG("L%d 0x%04x not found !!", level, type); */
   return NULL;
}

/*
 * remove a decoder from the decoders table
 */

void del_decoder(u_int8 level, u_int32 type)
{
   struct dec_entry *e;

   SLIST_FOREACH (e, &decoders_table, next) {
      if (e->level == level && e->type == type) {
         DEBUG_MSG("L%d 0x%04x removed !!", level, type);
         SLIST_REMOVE(&decoders_table, e, dec_entry, next);
         SAFE_FREE(e);
         return;
      }
   }
   
   return;
}


/* EOF */

// vim:ts=3:expandtab

