/*
    ettercap -- ICMP decoder module

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

    $Id: ec_icmp.c,v 1.5 2003/10/16 16:46:48 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>

/* globals */

struct icmp_header {
   u_int8   type;     /* message type */
   u_int8   code;     /* type sub-code */
   u_int16  checksum;
   union {
      struct {
         u_int16  id;
         u_int16  sequence;
      } echo;       /* echo datagram */
      u_int32     gateway; /* gateway address */
      struct {
         u_int16  unused;
         u_int16  mtu;
      } frag;       /* path mtu discovery */
   } un;
};


/* protos */

FUNC_DECODER(decode_icmp);
void icmp_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init icmp_init(void)
{
   add_decoder(PROTO_LAYER, NL_TYPE_ICMP, decode_icmp);
}


FUNC_DECODER(decode_icmp)
{
   struct icmp_header *icmp;

   icmp = (struct icmp_header *)DECODE_DATA;
  
   DECODED_LEN = sizeof(struct icmp_header);

   /* fill the data */
   PACKET->L4.len = DECODED_LEN;
   PACKET->L4.header = (u_char *)DECODE_DATA;
   PACKET->L4.options = NULL;
   
   PACKET->L4.proto = NL_TYPE_ICMP;
   
   /* this is a lie... but we have to put this somewhere */
   PACKET->L4.flags = icmp->type;
  
   /* XXX - checksum check */
   
   /* 
    * if the host is sending strange 
    * ICMP messages, it might be a router
    */
   switch (icmp->type) {
      case ICMP_DEST_UNREACH:
         switch (icmp->code) {
            case ICMP_NET_UNREACH:
            case ICMP_HOST_UNREACH:
               PACKET->PASSIVE.flags |= FP_ROUTER;
               break;
         }
      case ICMP_REDIRECT:
      case ICMP_TIME_EXCEEDED:
         PACKET->PASSIVE.flags |= FP_ROUTER;
         break;
   }

   /* HOOK POINT:  HOOK_PACKET_ICMP */
   hook_point(HOOK_PACKET_ICMP, po);
   

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

