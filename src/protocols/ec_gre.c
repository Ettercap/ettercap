/*
    ettercap -- GRE decoder module

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

    $Id: ec_gre.c,v 1.1 2003/12/01 16:33:41 lordnaga Exp $
*/

#include <ec.h>
#include <ec_decode.h>


/* globals */

/* Flag mask - 
 * (taken from ethereal gre decoder 
 * by Brad Robel-Forrest) 
 */
#define GH_B_C		0x8000
#define GH_B_R		0x4000
#define GH_B_K		0x2000
#define GH_B_S		0x1000
#define GH_B_s		0x0800
#define GH_B_RECUR	0x0700
#define GH_P_A		0x0080	
#define GH_P_FLAGS	0x0078	
#define GH_R_FLAGS	0x00F8
#define GH_B_VER	0x0007


/* protos */

FUNC_DECODER(decode_gre);
void gre_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init gre_init(void)
{
   add_decoder(PROTO_LAYER, NL_TYPE_GRE, decode_gre);
}


FUNC_DECODER(decode_gre)
{
   FUNC_DECODER_PTR(next_decoder);
   u_int16 flags;
   u_int16 proto;
   
   DECODED_LEN = 4;
   
   flags = pntos(DECODE_DATA);
   proto = pntos(DECODE_DATA + sizeof(flags));
   
   /* Parse the flags and see which fields are present */
   if (flags & GH_B_C || flags & GH_B_R)
      DECODED_LEN += 4;
   if (flags & GH_B_K)
      DECODED_LEN += 4;
   if (flags & GH_B_S)
      DECODED_LEN += 4;
   if (flags & GH_P_A)
      DECODED_LEN += 4;
   
   /* get the next decoder */
   next_decoder =  get_decoder(NET_LAYER, proto);
   EXECUTE_DECODER(next_decoder);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

