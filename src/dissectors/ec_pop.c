/*
    ettercap -- dissector POP3 -- TCP 110

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

    $Id: ec_pop.c,v 1.5 2003/04/01 22:13:44 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>


/* protos */

FUNC_DECODER(dissector_pop);
void pop_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init pop_init(void)
{
   add_decoder(APP_LAYER_TCP, 110, dissector_pop);
}

FUNC_DECODER(dissector_pop)
{
   DECLARE_PTR_END(ptr, end);
   char tmp[MAX_ASCII_ADDR_LEN];

   /* skip messages coming from the server */
   if (ntohs(PACKET->L4.src) == 110) 
      return NULL;

   /* skip empty packets */
   if (PACKET->DATA.len == 0)
      return NULL;
  
   /* skip the whitespaces at the beginning */
   while(*ptr == ' ' && ptr != end) ptr++;
   
   if ( !strncasecmp(ptr, "USER ", 5) ) {
      ptr += 5;
      DEBUG_MSG("\tDissector_POP USER");
      /* the \n is already present in the packet, no need to add it */
      PACKET->INFO.user = strdup(ptr);
      if ( (ptr = strchr(PACKET->INFO.user,'\r')) != NULL )
         *ptr = '\0';
         
      USER_MSG("POP : %s:%d -> USER: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), PACKET->INFO.user);
   }

   if ( !strncasecmp(ptr, "PASS ", 5) ) {
      ptr += 5;
      DEBUG_MSG("\tDissector_POP PASS");
      /* the \n is already present in the packet, no need to add it */
      PACKET->INFO.pass = strdup(ptr);
      if ( (ptr = strchr(PACKET->INFO.pass,'\r')) != NULL )
         *ptr = '\0';
      USER_MSG("POP : %s:%d -> PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), PACKET->INFO.pass);
   }
   
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

