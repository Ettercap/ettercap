/*
    ettercap -- dissector POP3 -- TCP 110

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

    $Id: ec_pop.c,v 1.21 2003/09/27 17:22:02 alor Exp $
*/

/*
 * The authentication schema can be found here:
 * 
 * ftp://ftp.rfc-editor.org/in-notes/std/std53.txt
 *
 * we currently support:
 *    - USER & PASS
 *    - APOP
 *    - AUTH LOGIN (SASL)
 */

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <ec_strings.h>

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
   dissect_add("pop", APP_LAYER_TCP, 110, dissector_pop);
}

FUNC_DECODER(dissector_pop)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];
   
   /* the connection is starting... create the session */
   CREATE_SESSION_ON_SYN_ACK("pop", s);
   
   /* check if it is the first packet sent by the server */
   if (FROM_SERVER("pop", PACKET) && PACKET->L4.flags & TH_PSH) {  
      dissect_create_ident(&ident, PACKET);
      /* the session exist */
      if (session_get(&s, ident, DISSECT_IDENT_LEN) != -ENOTFOUND) { 
         /* prevent the deletion of session created for the user and pass */
         if (s->data == NULL) { 
            
            /* get the banner */
            if (!strncmp(ptr, "+OK", 3))
               PACKET->DISSECTOR.banner = strdup(ptr + 4);
            else {
               SAFE_FREE(ident);
               return NULL;
            }

            DEBUG_MSG("\tdissector_pop BANNER");

            /* remove the \r\n */
            if ( (ptr = strchr(PACKET->DISSECTOR.banner, '\r')) != NULL )
               *ptr = '\0';
            
            /* remove the trailing msg-id <...> */
            if ( (ptr = strchr(PACKET->DISSECTOR.banner, '<')) != NULL ) {
               /* save the msg-id for APOP authentication */
               s->data = strdup(ptr);
               /* save the session */
               *(ptr - 1) = '\0';
            } else {
               /* fake the msgid if it does not exist */
               s->data = strdup("");
            }
         } else if (!strcmp(s->data, "AUTH")) {
            /* 
             * the client has requested AUTH LOGIN, 
             * check if the server support it 
             * else delete the session
             */
            if (strstr(ptr, "-ERR"))
               dissect_wipe_session(PACKET);
         }
      }                         
      SAFE_FREE(ident);         
      return NULL;              
   }  
   
   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
 
   DEBUG_MSG("POP --> TCP dissector_pop");
   
   /* skip the whitespaces at the beginning */
   while(*ptr == ' ' && ptr != end) ptr++;

/*
 * USER & PASS authentication:
 *
 * USER user
 * PASS pass
 */
   if ( !strncasecmp(ptr, "USER ", 5) ) {

      DEBUG_MSG("\tDissector_POP USER");

      /* destroy any previous session */
      dissect_wipe_session(PACKET);
      
      /* create the new session */
      dissect_create_session(&s, PACKET);
      
      ptr += 5;
      
      /* if not null, free it */
      SAFE_FREE(s->data);

      /* fill the session data */
      s->data = strdup(ptr);
      s->data_len = strlen(ptr);
      
      if ( (ptr = strchr(s->data,'\r')) != NULL )
         *ptr = '\0';
      
      /* save the session */
      session_put(s);

      return NULL;
   }

   /* harvest the password */
   if ( !strncasecmp(ptr, "PASS ", 5) ) {

      DEBUG_MSG("\tDissector_POP PASS");
      
      ptr += 5;
      
      /* create an ident to retrieve the session */
      dissect_create_ident(&ident, PACKET);
      
      /* retrieve the session and delete it */
      if (session_get_and_del(&s, ident, DISSECT_IDENT_LEN) == -ENOTFOUND) {
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

      /* print the message */
      USER_MSG("POP : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass);

      return NULL;
   }
   
/* 
 * APOP authentication :
 *
 * APOP user md5-digest
 *
 * MD5-diges is computed on "<msg-id>pass"
 */
   if ( !strncasecmp(ptr, "APOP ", 5) ) {
     
      DEBUG_MSG("\tDissector_POP APOP");
      
      /* create an ident to retrieve the session */
      dissect_create_ident(&ident, PACKET);
      
      /* retrieve the session and delete it */
      if (session_get_and_del(&s, ident, DISSECT_IDENT_LEN) == -ENOTFOUND) {
         SAFE_FREE(ident);
         return NULL;
      }

      /* check that the digest was sent before APOP */
      if (s->data == NULL) {
         SAFE_FREE(ident);
         return NULL;
      }
      
      /* move the pointers to "user" */
      ptr += 5;
      PACKET->DISSECTOR.user = strdup(ptr);
     
      /* split the string */
      if ( (ptr = strchr(PACKET->DISSECTOR.user, ' ')) != NULL )
         *ptr = '\0';
     
      /* skip the \0 */
      ptr += 1;
      
      /* save the user */
      PACKET->DISSECTOR.pass = strdup(ptr);
      if ( (ptr = strchr(PACKET->DISSECTOR.pass, '\r')) != NULL )
         *ptr = '\0';
         
      /* set the info */
      PACKET->DISSECTOR.info = strdup(s->data);

      /* free the session */
      session_free(s);
      SAFE_FREE(ident);

      /* print the message */
      USER_MSG("POP : %s:%d -> USER: %s  MD5-digest: %s  %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass,
                                    PACKET->DISSECTOR.info);
      return NULL;
   }
   
/* 
 * AUTH LOGIN
 *
 * digest(user)
 * digest(pass)
 *
 * the digests are in base64
 */
   if ( !strncasecmp(ptr, "AUTH LOGIN", 10) ) {
      
      DEBUG_MSG("\tDissector_POP AUTH LOGIN");

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
   if (session_get(&s, ident, DISSECT_IDENT_LEN) == -ENOTFOUND) {
      SAFE_FREE(ident);
      return NULL;
   }

   SAFE_FREE(ident);
   
   /* the session is invalid */
   if (s->data == NULL) {
      dissect_wipe_session(PACKET);
      return NULL;
   }

/* collect the user */   
   if (!strcmp(s->data, "AUTH")) {
      char *user;
      int i;
     
      DEBUG_MSG("\tDissector_POP AUTH LOGIN USER");
     
      SAFE_CALLOC(user, strlen(ptr), sizeof(char));
     
      /* username is encoded in base64 */
      i = base64_decode(user, ptr);
     
      SAFE_FREE(s->data);

      /* store the username in the session */
      SAFE_CALLOC(s->data, strlen("AUTH USER ") + i + 1, sizeof(char) );
      
      sprintf(s->data, "AUTH USER %s", user);
      
      SAFE_FREE(user);

      /* pass is in the next packet */
      return NULL;
   }
   
/* collect the pass */     
   if (!strncmp(s->data, "AUTH USER", 9)) {
      char *pass;
      int i;
     
      DEBUG_MSG("\tDissector_POP AUTH LOGIN PASS");
      
      SAFE_CALLOC(pass, strlen(ptr), sizeof(char));
      
      /* password is encoded in base64 */
      i = base64_decode(pass, ptr);
     
      /* fill the structure */
      PACKET->DISSECTOR.user = strdup(s->data + strlen("AUTH USER "));
      PACKET->DISSECTOR.pass = strdup(pass);
      
      SAFE_FREE(pass);
      /* destroy the session */
      dissect_wipe_session(PACKET);
      
      /* print the message */
      USER_MSG("POP : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass);
      return NULL;
   }
   
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

