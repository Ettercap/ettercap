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

    $Id: ec_pop.c,v 1.8 2003/04/12 19:11:34 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>


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
   struct session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* the connection is starting... create the session */
   if (ntohs(PACKET->L4.src) == 110 && PACKET->L4.flags & TH_SYN && PACKET->L4.flags & TH_ACK) {
      /* create the session */
      dissect_create_session(&s, PACKET);
      session_put(s);
      return NULL;
   }
   
   /* check if it is the first packet sent by the server */
   if (ntohs(PACKET->L4.src) == 110 && PACKET->L4.flags & TH_PSH) {
      
      dissect_create_ident(&ident, PACKET);

      /* the session exist */
      if (session_get(&s, ident) != -ENOTFOUND) {
         if (s->data == NULL) {
            /* get the banner */
            if (!strncmp(ptr, "+OK", 3))
               PACKET->DISSECTOR.banner = strdup(ptr+4);

            if ( (ptr = strchr(PACKET->DISSECTOR.banner, '<')) != NULL )
               *ptr = '\0';

            session_del(ident);
         }
      }
      SAFE_FREE(ident);
      return NULL;
   }

   
   /* skip messages coming from the server */
   if (ntohs(PACKET->L4.src) == 110) 
      return NULL;

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
 
   /* skip the whitespaces at the beginning */
   while(*ptr == ' ' && ptr != end) ptr++;
  
   /* harvest the username */
   if ( !strncasecmp(ptr, "USER ", 5) ) {

      DEBUG_MSG("\tDissector_POP USER");
      
      /* create the session */
      dissect_create_session(&s, PACKET);
      
      ptr += 5;
      /* fill the session data */
      s->data = strdup(ptr);
      s->data_len = strlen(ptr);
      
      if ( (ptr = strchr(s->data,'\r')) != NULL )
         *ptr = '\0';
      
      /* save the session */
      session_put(s);
   }

   /* harvest the password */
   if ( !strncasecmp(ptr, "PASS ", 5) ) {

      DEBUG_MSG("\tDissector_POP PASS");
      
      ptr += 5;
      
      /* create an ident to retrieve the session */
      dissect_create_ident(&ident, PACKET);
      
      /* retrieve the session and delete it */
      if (session_get_and_del(&s, ident) == -ENOTFOUND)
         return NULL;
      
      /* fill the structure */
      PACKET->DISSECTOR.user = strdup(s->data);
      
      PACKET->DISSECTOR.pass = strdup(ptr);
      if ( (ptr = strchr(PACKET->DISSECTOR.pass, '\r')) != NULL )
         *ptr = '\0';

      USER_MSG("POP : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass);

      /* free the session */
      session_free(s);
      SAFE_FREE(ident);
   }
   
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

