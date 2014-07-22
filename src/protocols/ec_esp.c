/*
    ettercap -- ESP decoder module

    Copyright (C) CaptainMcSpankyPants

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
#include <ec_inject.h>

/* globals */

struct esp_header {
   u_int32  spi;           /* Security Parameters Index */
   u_int32  seq;           /* Sequence Number */
};


/* protos */

FUNC_DECODER(decode_esp);
void esp_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init esp_init(void)
{
   add_decoder(PROTO_LAYER, NL_TYPE_ESP, decode_esp);
}


FUNC_DECODER(decode_esp)
{
   FUNC_DECODER_PTR(next_decoder);
   struct esp_header *esp;
   
   DECODED_LEN = sizeof(struct esp_header);
   
   esp = (struct esp_header *)DECODE_DATA;

   PACKET->DATA.data = ((u_char *)esp) + sizeof(struct esp_header);
   
   /* HOOK POINT: HOOK_PACKET_ESP */
   hook_point(HOOK_PACKET_ESP, PACKET);
      
   /* get the next decoder */
   next_decoder = get_decoder(APP_LAYER, PL_DEFAULT);
   EXECUTE_DECODER(next_decoder);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

