/*
    ettercap -- IPv6 decoder module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/protocols/ec_ip6.c,v 1.5 2003/06/14 09:29:35 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_inet.h>
//#include <ec_fingerprint.h>

enum {
   IP6_HDR_LEN = 40,
};

/* globals */

struct ip6_header {
#ifndef WORDS_BIGENDIAN
   u_int8   version:4;
   u_int8   priority:4;
#else 
   u_int8   priority:4;
   u_int8   version:4;
#endif
   u_int8   flow_lbl[3];
   u_int16  payload_len;
   u_int8   next_hdr;
   u_int8   hop_limit;

   u_int8   saddr[IP6_ADDR_LEN];
   u_int8   daddr[IP6_ADDR_LEN];
   
   /* OPTIONS MAY FOLLOW */
};

/* protos */

FUNC_DECODER(decode_ip6);
void ip6_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init ip6_init(void)
{
   add_decoder(NET_LAYER, LL_TYPE_IP6, decode_ip6);
}


FUNC_DECODER(decode_ip6)
{
   FUNC_DECODER_PTR(next_decoder);
   struct ip6_header *ip6;
   int opt; /* -1 means no options defined, if 0 an option is present */
   
   ip6 = (struct ip6_header *)DECODE_DATA;
  
   if (ip6->payload_len == 0) {
      DEBUG_MSG("IPv6 jumbogram, Hop-By-Hop header should follow");
      DECODED_LEN = 0;
   } else {
      DECODED_LEN = ip6->payload_len + IP6_HDR_LEN;
   }

   /* IP addresses */
   ip_addr_init(&PACKET->L3.src, AF_INET6, (u_char *)&ip6->saddr);
   ip_addr_init(&PACKET->L3.dst, AF_INET6, (u_char *)&ip6->daddr);
   
   /*
    * if the L3 is parsed for the first time,
    * set the fwd_packet pointer
    * this is needed because incapsulated packet may 
    * overwrite the L3.header pointer used by send_to_L3
    */
   if (PACKET->L3.header == NULL) {
      PACKET->fwd_packet = (u_char *)DECODE_DATA;
      PACKET->fwd_len = PACKET->len - PACKET->L2.len;
   }
   
   /* other relevant infos */
   PACKET->L3.header = (u_char *)DECODE_DATA;
   PACKET->L3.len = DECODED_LEN;
   
   /* this is needed at upper layer to calculate the tcp payload size */
   PACKET->L3.payload_len = ntohs(ip6->payload_len);

   /* XXX - how IPv6 options work ?? */
   PACKET->L3.options = NULL;
   PACKET->L3.optlen = 0;
   
   PACKET->L3.proto = htons(LL_TYPE_IP6);
   PACKET->L3.ttl = ip6->hop_limit;

   /* calculate if the dest is local or not */
   switch (ip_addr_is_local(&PACKET->L3.src)) {
      case ESUCCESS:
         PACKET->PASSIVE.flags |= FP_HOST_LOCAL;
         break;
      case -ENOTFOUND:
         PACKET->PASSIVE.flags |= FP_HOST_NONLOCAL;
         break;
      case -EINVALID:
         PACKET->PASSIVE.flags = FP_UNKNOWN;
         break;
   }
   
   /* XXX had to implement passive fingerprint for IPv6 */
   
   /* XXX - implemet checksum check */
   
   switch (ip6->next_hdr) {
      case 0:
	      DEBUG_MSG(" --> option  Hop-By-Hop");
	      opt = 0;
	      break;
      case 43:
	      DEBUG_MSG(" --> option  Routing");
	      opt = 0;
	      break;
      case 44:
	      DEBUG_MSG(" --> option  Fragment");
	      opt = 0;
	      break;
      case 60:
	      DEBUG_MSG(" --> option  Destination");
	      opt = 0;
	      break;
      case 59:
	      DEBUG_MSG(" --> option  No-Next-Header");
	      opt = 0;
	      break;
      default:
	      opt = -1;
	      break;
   }
      
   /* if (opt == 0)
      return get_decoder(OPT6_LAYER, ip6->next_hdr);
   else */
  
   /* HOOK POINT: PACKET_IP6 */
   hook_point(PACKET_IP6, po);
   
   next_decoder = get_decoder(PROTO_LAYER, ip6->next_hdr);

   EXECUTE_DECODER(next_decoder);
   
   /* XXX - implement modification checks */
#if 0
   if (po->flags & PO_MOD_LEN)
      
   if (po->flags & PO_MOD_CHECK)
#endif   
   
   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

