/*
    ettercap -- Prism2 header for WiFi packets 

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

struct rtap_header {
   u_int8   rtap_rev;            /* Header revision */
   u_int8   rtap_pad;
   u_int8   rtap_hdrlen[2];      /* Length of entire header, little endian */
   u_int32  rtap_fields;         /* Fields present in data */
   u_int8   rtap_data[0];
};

/* protos */

FUNC_DECODER(decode_radiotap);
FUNC_ALIGNER(align_radiotap);
void radiotap_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init radiotap_init(void)
{
   add_decoder(LINK_LAYER, IL_TYPE_RADIOTAP, decode_radiotap);
   add_aligner(IL_TYPE_RADIOTAP, align_radiotap);
}


FUNC_DECODER(decode_radiotap)
{
   FUNC_DECODER_PTR(next_decoder);

   /* Determine the length of the radiotap header first and then skip the
    * portion and pass the whole packet on to the wifi layer */
   struct rtap_header *rtaphdr = (struct rtap_header*)DECODE_DATA;

   /* Header length is not NBO, but little endian */
   u_int16 hdrlen = rtaphdr->rtap_hdrlen[0] | (rtaphdr->rtap_hdrlen[1] << 8);
   DECODED_LEN = hdrlen;
   
   next_decoder =  get_decoder(LINK_LAYER, IL_TYPE_WIFI);
   EXECUTE_DECODER(next_decoder);

   return NULL;
}

/*
 * alignment function
 */
FUNC_ALIGNER(align_radiotap)
{
   /* already aligned */
   return 0;
}

/* EOF */

// vim:ts=3:expandtab

