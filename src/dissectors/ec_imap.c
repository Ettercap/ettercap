/*
    ettercap -- dissector IMAP -- TCP 143 220

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

    $Id: ec_imap.c,v 1.1 2003/07/09 08:53:53 alor Exp $
*/

/*
 * The authentication schema can be found here:
 *
 * ftp://ftp.rfc-editor.org/in-notes/rfc1730.txt
 * ftp://ftp.rfc-editor.org/in-notes/rfc1731.txt
 *
 * we currently support:
 *    - LOGIN
 *    - AUTHENTICATE LOGIN
 */

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <ec_strings.h>

/* protos */

FUNC_DECODER(dissector_imap);
void imap_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init imap_init(void)
{
   dissect_add("imap", APP_LAYER_TCP, 143, dissector_imap);
   dissect_add("imap", APP_LAYER_TCP, 220, dissector_imap);
}

FUNC_DECODER(dissector_imap)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];
   
   /* the connection is starting... create the session */
   CREATE_SESSION_ON_SYN_ACK("imap", s);
   
   /* check if it is the first packet sent by the server */
   IF_FIRST_PACKET_FROM_SERVER("imap", s, ident) {
          
      DEBUG_MSG("\tdissector_imap BANNER");
      /*
       * get the banner 
       * "* OK banner"
       */
       
      /* skip the number, go to response */
      while(*ptr != ' ' && ptr != end) ptr++;
      
      if (!strncmp(ptr, " OK ", 4))
         PACKET->DISSECTOR.banner = strdup(ptr + 3);
            
   } ENDIF_FIRST_PACKET_FROM_SERVER(s, ident)
   
   /* skip messages coming from the server */
   if (dissect_on_port("imap", ntohs(PACKET->L4.src)) == ESUCCESS)
      return NULL;
   
   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
 
   DEBUG_MSG("IMAP --> TCP dissector_imap");
   

   /* skip the number, move to the command */
   while(*ptr != ' ' && ptr != end) ptr++;
  
/*
 * LOGIN authentication:
 *
 * n LOGIN user pass
 */
   if ( !strncasecmp(ptr, " LOGIN ", 7) ) {

      DEBUG_MSG("\tDissector_imap LOGIN");

      ptr += 7;
      
      PACKET->DISSECTOR.user = strdup(ptr);
      
      /* split the string */
      if ( (ptr = strchr(PACKET->DISSECTOR.user, ' ')) != NULL )
         *ptr = '\0';
      
      /* save the second part */
      PACKET->DISSECTOR.pass = strdup(ptr + 1);
      
      if ( (ptr = strchr(PACKET->DISSECTOR.pass, '\r')) != NULL )
         *ptr = '\0';
      
      /* print the message */
      USER_MSG("IMAP : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass);
      return NULL;
   }

/* 
 * AUTHENTICATE LOGIN
 *
 * digest(user)
 * digest(pass)
 *
 * the digests are in base64
 */
   if ( !strncasecmp(ptr, "AUTHENTICATE LOGIN", 19) ) {
      
      DEBUG_MSG("\tDissector_imap AUTHENTICATE LOGIN");

      /* destroy any previous session */
      dissect_wipe_session(PACKET);
      
      /* create the new session */
      dissect_create_session(&s, PACKET);
     
      /* remember the state (used later) */
      s->data = strdup("AUTH");
      
      /* save the session */
      session_put(s);

      /* username is in the next packet */
      return NULL;
   }
   
   /* search the session (if it exist) */
   dissect_create_ident(&ident, PACKET);
   if (session_get(&s, ident) == -ENOTFOUND)
      return NULL;

   SAFE_FREE(ident);

   if (!strcmp(s->data, "AUTH")) {
      char *user;
      int i;
     
      DEBUG_MSG("\tDissector_imap AUTHENTICATE LOGIN USER");
      
      user = calloc(strlen(ptr), sizeof(char));
      ON_ERROR(user, NULL, "cant allocate memory");
     
      /* username is encoded in base64 */
      i = base64_decode(user, ptr);
     
      SAFE_FREE(s->data);

      /* store the username in the session */
      s->data = calloc(strlen("AUTH USER ") + i + 1, sizeof(char) );
      ON_ERROR(s->data, NULL, "cant allocate memory");
      
      sprintf(s->data, "AUTH USER %s", user);
      
      SAFE_FREE(user);

      /* pass is in the next packet */
      return NULL;
   }
   
   if (!strncmp(s->data, "AUTH USER", 9)) {
      char *pass;
      int i;
     
      DEBUG_MSG("\tDissector_imap AUTHENTICATE LOGIN PASS");
      
      pass = calloc(strlen(ptr), sizeof(char));
      ON_ERROR(pass, NULL, "cant allocate memory");
      
      /* password is encoded in base64 */
      i = base64_decode(pass, ptr);
     
      /* fill the structure */
      PACKET->DISSECTOR.user = strdup(s->data + strlen("AUTH USER "));
      PACKET->DISSECTOR.pass = strdup(pass);
      
      SAFE_FREE(pass);
      /* destroy the session */
      dissect_wipe_session(PACKET);
      
      /* print the message */
      USER_MSG("IMAP : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass);
      return NULL;
   }
   
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

