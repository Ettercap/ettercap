/*
    ettercap -- UDP decoder module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/protocols/ec_udp.c,v 1.5 2003/09/15 16:16:59 lordnaga Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_checksum.h>


/* globals */

struct udp_header {
   u_int16  sport;           /* source port */
   u_int16  dport;           /* destination port */
   u_int16  ulen;            /* udp length */
   u_int16  csum;            /* udp checksum */
};

/* protos */

FUNC_DECODER(decode_udp);
void udp_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init udp_init(void)
{
   add_decoder(PROTO_LAYER, NL_TYPE_UDP, decode_udp);
}


FUNC_DECODER(decode_udp)
{
   FUNC_DECODER_PTR(next_decoder);
   struct udp_header *udp;

   udp = (struct udp_header *)DECODE_DATA;

   DECODED_LEN = sizeof(struct udp_header);

   /* source and dest port */
   PACKET->L4.src = udp->sport;
   PACKET->L4.dst = udp->dport;

   PACKET->L4.len = DECODED_LEN;
   PACKET->L4.header = (u_char *)DECODE_DATA;
   PACKET->L4.options = NULL;
   
   /* this is UDP */
   PACKET->L4.proto = NL_TYPE_UDP;

   /* set up the data poiters */
   PACKET->DATA.data = ((u_char *)udp) + sizeof(struct udp_header);
   PACKET->DATA.len = ntohs(udp->ulen) - sizeof(struct udp_header);
  
   /* create the buffer to be displayed */
   packet_disp_data(PACKET, PACKET->DATA.data, PACKET->DATA.len);

   /* 
    * if the checsum is wrong, don't parse it (avoid ettercap spotting) 
    * the checksum is should be 0 and not equal to ip->csum ;)
    */
   if (L4_checksum(PACKET) != 0) {
      char tmp[MAX_ASCII_ADDR_LEN];
      USER_MSG("Invalid UDP packet from %s:%d : csum [%#x] (%#x)\n", ip_addr_ntoa(&PACKET->L3.src, tmp),
                                    ntohs(udp->sport), L4_checksum(PACKET), ntohs(udp->csum) );
      return NULL;
   }

   /* HOOK POINT: PACKET_UDP */
   hook_point(PACKET_UDP, po);
   
   /* get the next decoder */
   next_decoder =  get_decoder(APP_LAYER, PL_DEFAULT);
   EXECUTE_DECODER(next_decoder);
   
   /* Adjustments after filters */
   if (PACKET->flags & PO_MODIFIED) {
      /* XXX We assume len>=delta (required for checksum) */
      PACKET->DATA.len += PACKET->delta;
            
      /* Recalculate checksum */
      udp->csum = 0; 
      udp->csum = L4_checksum(PACKET);
   }

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

