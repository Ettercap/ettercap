/*
    ettercap -- dissector NNTP -- TCP 119

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

    $Id: ec_nntp.c,v 1.4 2003/07/17 21:13:12 alor Exp $
*/

/*
 * The authentication schema can be found here:
 * 
 * ftp://ftp.rfc-editor.org/in-notes/rfc2980.txt
 * 
 */

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>


/* protos */

FUNC_DECODER(dissector_nntp);
void nntp_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init nntp_init(void)
{
   dissect_add("nntp", APP_LAYER_TCP, 119, dissector_nntp);
}

FUNC_DECODER(dissector_nntp)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];
   
   /* the connection is starting... create the session */
   CREATE_SESSION_ON_SYN_ACK("nntp", s);
   
   /* check if it is the first packet sent by the server */
   IF_FIRST_PACKET_FROM_SERVER("nntp", s, ident) {
          
      DEBUG_MSG("\tdissector_nntp BANNER");
      /*
       * get the banner 
       * ptr + 4 to skip the initial 200 response
       */
      if (!strncmp(ptr, "200", 3)) {
         PACKET->DISSECTOR.banner = strdup(ptr + 4);
      
         /* remove the \r\n */
         if ( (ptr = strchr(PACKET->DISSECTOR.banner, '\r')) != NULL )
            *ptr = '\0';
      }
            
   } ENDIF_FIRST_PACKET_FROM_SERVER(s, ident)
   
   /* skip messages coming from the server */
   if (dissect_on_port("nntp", ntohs(PACKET->L4.src)) == ESUCCESS)
      return NULL;

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
 
   DEBUG_MSG("NNTP --> TCP dissector_nntp");
   
   /* skip the whitespaces at the beginning */
   while(*ptr == ' ' && ptr != end) ptr++;
  
   /* harvest the username */
   if ( !strncasecmp(ptr, "AUTHINFO USER ", 14) ) {

      DEBUG_MSG("\tDissector_nntp USER");
      
      /* create the session */
      dissect_create_session(&s, PACKET);
      
      ptr += 14;

      /* fill the session data */
      s->data = strdup(ptr);
      s->data_len = strlen(ptr);
      
      /* remove the \r\n */
      if ( (ptr = strchr(s->data,'\r')) != NULL )
         *ptr = '\0';
      
      /* save the session */
      session_put(s);

      return NULL;
   }

   /* harvest the password */
   if ( !strncasecmp(ptr, "AUTHINFO PASS ", 14) ) {

      DEBUG_MSG("\tDissector_nntp PASS");
      
      ptr += 14;
      
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

      /* free the session */
      session_free(s);
      SAFE_FREE(ident);
      
      USER_MSG("NNTP : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass);

      return NULL;
   }
   
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

