/*
    ettercap -- dissector FTP -- TCP 21

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

    $Id: ec_ftp.c,v 1.4 2003/06/24 16:36:00 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>


/* protos */

FUNC_DECODER(dissector_ftp);
void ftp_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init ftp_init(void)
{
   dissect_add("ftp", APP_LAYER_TCP, 21, dissector_ftp);
}

FUNC_DECODER(dissector_ftp)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* the connection is starting... create the session */
   CREATE_SESSION_ON_SYN_ACK(21, s);
   
   /* check if it is the first packet sent by the server */
   IF_FIRST_PACKET_FROM_SERVER(21, s, ident) {
            
      /* get the banner */
      PACKET->DISSECTOR.banner = strdup(ptr+4);
     
   } ENDIF_FIRST_PACKET_FROM_SERVER(21, s, ident)
   
   /* skip messages coming from the server */
   if (ntohs(PACKET->L4.src) == 21) 
      return NULL;

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
   
   DEBUG_MSG("FTP --> TCP 21  dissector_ftp");
 
   /* skip the whitespaces at the beginning */
   while(*ptr == ' ' && ptr != end) ptr++;
  
   /* harvest the username */
   if ( !strncasecmp(ptr, "USER ", 5) ) {

      DEBUG_MSG("\tDissector_FTP USER");
      
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

      DEBUG_MSG("\tDissector_FTP PASS");
      
      ptr += 5;
      
      /* create an ident to retrieve the session */
      dissect_create_ident(&ident, PACKET);
      
      /* retrieve the session and delete it */
      if (session_get_and_del(&s, ident) == -ENOTFOUND) {
         SAFE_FREE(ident);
         return NULL;
      }
      
      /* check that the user was sent before the pass */
      if (s->data == NULL) {
         SAFE_FREE(ident);
         return NULL;
      }
      
      /* fill the structure */
      PACKET->DISSECTOR.user = strdup(s->data);
      
      PACKET->DISSECTOR.pass = strdup(ptr);
      if ( (ptr = strchr(PACKET->DISSECTOR.pass, '\r')) != NULL )
         *ptr = '\0';

      USER_MSG("FTP : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
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

