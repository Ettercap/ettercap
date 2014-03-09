/*
    ettercap -- Null/Loopback decoder module

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
#include <ec_decode.h>
#include <ec_capture.h>


/* globals */
struct null_header {
   u_int32 proto; /* next protocol (usually) in host-byte order */
};

/* protos */

FUNC_DECODER(decode_null);
FUNC_ALIGNER(align_null);
void null_init(void);


/*
 * this function initiates the decoder and adds the entry in
 * the decoder table
 */
void __init null_init(void)
{
   add_decoder(LINK_LAYER, IL_TYPE_NULL, decode_null);
   add_aligner(IL_TYPE_NULL, align_null);
}

FUNC_DECODER(decode_null)
{
   FUNC_DECODER_PTR(next_decoder);
   struct null_header *null;
   u_int32 lltype, proto;

   DECODED_LEN = sizeof(struct null_header);

   null = (struct null_header*)DECODE_DATA;

   /*
    * byte order can vary depending on the endianess of the system
    * the packets have been captured 
    */
   proto = ntohl(null->proto);

   /* 
    * the proto (mainly for IPv6) need to be treated differently 
    * because because for the different BSD derivates the values
    * have not been standardized
    */
   switch (proto) {
      case AF_INET:          /* IPv4 on any system */
         lltype = LL_TYPE_IP;
         break;
#if AF_INET6 != AF_INET6_BSD
      case AF_INET6_BSD:     /* IPv6 on NetBSD,OpenBSD,BSD/OS */
#endif
#if AF_INET6 != AF_INET6_FREEBSD
      case AF_INET6_FREEBSD: /* IPv6 on FreeBSD,DragonFlyBSD */
#endif
#if AF_INET6 != AF_INET6_DARWIN
      case AF_INET6_DARWIN:  /* IPv6 on Darwin/Mac OS X */
#endif
#if AF_INET6 != AF_INET6_LINUX
      case AF_INET6_LINUX:   /* IPv6 on Linux */
#endif
      case AF_INET6:         /* IPv6 on the compiling system */
         lltype = LL_TYPE_IP6; 
         break;
      default:               /* upper protocol not supported by ettercap */
         lltype = 0;
   }

   /* fill the packet object */
   PACKET->L2.header = (u_char*)DECODE_DATA;
   PACKET->L2.proto = IL_TYPE_NULL;
   PACKET->L2.len = DECODED_LEN;

   /* set dummy L2 addresses as they doesn't exist in this proto */
   memset(PACKET->L2.src, 0, ETH_ADDR_LEN);
   memset(PACKET->L2.dst, 0, ETH_ADDR_LEN);

   /* Hooking on a Loopback interface doesn't make much sense */

   /* hand upper protocols over to the next decoder */
   next_decoder = get_decoder(NET_LAYER, lltype);

   EXECUTE_DECODER(next_decoder);

   return NULL;

}

/*
 * alignment function
 */
FUNC_ALIGNER(align_null)
{
   /* 16 is the nearest multiplier of 4 */
   return (16 - sizeof(struct  null_header));
}
/* EOF */

// vim:ts=3:expandtab

