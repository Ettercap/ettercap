/*
    ettercap -- dissector X11 -- TCP 6000, 6001, ...

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

    $Id: ec_x11.c,v 1.1 2003/07/07 10:43:20 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>


/* protos */

FUNC_DECODER(dissector_x11);
void x11_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init x11_init(void)
{
   dissect_add("x11", APP_LAYER_TCP, 6000, dissector_x11);
   dissect_add("x11", APP_LAYER_TCP, 6001, dissector_x11);
   dissect_add("x11", APP_LAYER_TCP, 6002, dissector_x11);
   dissect_add("x11", APP_LAYER_TCP, 6003, dissector_x11);
}

FUNC_DECODER(dissector_x11)
{
   char tmp[MAX_ASCII_ADDR_LEN];
   char *cookie;
   
   /* skip messages coming from the server */
   if (dissect_on_port("x11", ntohs(PACKET->L4.src)) == ESUCCESS)
      return NULL;

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
 
   DEBUG_MSG("X11 --> TCP dissector_x11");
   
   /* search the magic string */
   cookie = strstr(PACKET->DATA.disp_data + 12, "MIT-MAGIC-COOKIE-1");
   
   if (cookie) {
      int i;
      
      DEBUG_MSG("\tDissector_x11 COOKIE");

      /* fill the structure */
      PACKET->DISSECTOR.user = strdup("MIT-MAGIC-COOKIE-1");
     
      /* the cookie's lenght is 32, take care of the null char */
      PACKET->DISSECTOR.pass = calloc(33, sizeof(char));
         
      for (i = 0; i < 16; i++)                                                                      
         sprintf(PACKET->DISSECTOR.pass + (i * 2), "%.2x", cookie[i + 20]); 
      
      USER_MSG("X11 : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass);
   }
   
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

