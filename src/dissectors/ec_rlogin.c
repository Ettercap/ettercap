/*
    ettercap -- dissector RLOGIN -- TCP 512 513

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

    $Id: ec_rlogin.c,v 1.1 2003/07/15 21:31:34 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <ec_strings.h>

/* protos */

FUNC_DECODER(dissector_rlogin);
void rlogin_init(void);
void skip_rlogin_command(u_char **ptr, u_char *end);
//int match_login_regex(char *ptr);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init rlogin_init(void)
{
   dissect_add("rlogin", APP_LAYER_TCP, 512, dissector_rlogin);
   dissect_add("rlogin", APP_LAYER_TCP, 513, dissector_rlogin);
}

/*
 * rlogin sends characters one per packet for the password
 * but the login is sent all together on the second packet 
 * sent by the client.
 */

FUNC_DECODER(dissector_rlogin)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* skip messages from the server */
   if (dissect_on_port("rlogin", ntohs(PACKET->L4.src)) == ESUCCESS)
      return NULL;
   
   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
   
   DEBUG_MSG("rlogin --> TCP dissector_rlogin");

   /* create an ident to retrieve the session */
   dissect_create_ident(&ident, PACKET);

   /* this is the rlogin handshake */
   if (*ptr == '\0') {
      /* retrieve the session */
      if (session_get(&s, ident) == -ENOTFOUND) {
         dissect_create_session(&s, PACKET);
         /* remember the state (used later) */
         s->data = strdup("HANDSHAKE");
         /* save the session */
         session_put(s);
         
         SAFE_FREE(ident);
         return NULL;
      } 
   }
   
   /* the first packet after handshake */
   if (session_get(&s, ident) == ESUCCESS) {
      if (!strcmp(s->data, "HANDSHAKE")) {
         u_char *localuser;
         u_char *remoteuser;

         localuser = ptr;

         /* sanity check */
         if (localuser + strlen(localuser) + 2 < end)
            remoteuser = localuser + strlen(localuser) + 1;
         else {
            SAFE_FREE(ident);
            return NULL;
         }

         SAFE_FREE(s->data);

         /* one byte for space, one for \r and one for null */
         s->data = calloc(strlen(localuser) + strlen(remoteuser) + 3, sizeof(char));
         ON_ERROR(s->data, NULL, "can't allocate memory");
         
         sprintf(s->data, "%s (%s)\r", remoteuser, localuser);

         SAFE_FREE(ident);
         return NULL;
      }
   }
  
   /* concat the pass to the collected user */
   if (session_get(&s, ident) == ESUCCESS) {
      char str[strlen(s->data) + 2];

      memset(str, 0, sizeof(str));
     
      /* concat the char to the previous one */
      sprintf(str, "%s%c", (char *)s->data, *ptr);

      /* save the new string */
      SAFE_FREE(s->data);
      s->data = strdup(str);
      
      /* 
       * the user input is terminated
       * check if it was the password by checking
       * the presence of \r in the string
       * we store "user\rpass\r" and then we split it
       */
      if (strchr(ptr, '\r') || strchr(ptr, '\n')) {
         /* there is the \r and it is not the last char */
         if ( ((ptr = strchr(s->data, '\r')) || (ptr = strchr(s->data, '\n')))
               && ptr != s->data + strlen(s->data) - 1 ) {

            /* fill the structure */
            PACKET->DISSECTOR.user = strdup(s->data);
            if ( (ptr = strchr(PACKET->DISSECTOR.user, '\r')) != NULL )
               *ptr = '\0';
   
            PACKET->DISSECTOR.pass = strdup(ptr + 1);
            if ( (ptr = strchr(PACKET->DISSECTOR.pass, '\r')) != NULL )
               *ptr = '\0';
           
            /* 
             * delete the session to remember that 
             * user and pass was collected
             */
            session_del(ident);
            
            /* display the message */
            USER_MSG("RLOGIN : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                 ntohs(PACKET->L4.dst), 
                                 PACKET->DISSECTOR.user,
                                 PACKET->DISSECTOR.pass);
         }
      }
   }
     
   SAFE_FREE(ident);
   
   return NULL;
}

#if 0
/* 
 * serach the strings which can identify failed login...
 * return 1 on succes, 0 on failure
 */
int match_login_regex(char *ptr)
{
   regex_t *regex;
   int ret = 0;

   /*
    * matches: 
    *    - login at the beginning of the buffer
    *    - inccorect
    *    - failed
    *    - failure
    */
#define LOGIN_REGEX "\\`login.*|.*incorrect.*|.*failed.*|.*failure.*"
   
   /* allocate the new structure */
   regex = calloc(1, sizeof(regex_t));
   ON_ERROR(regex, NULL, "can't allocate memory");

   /* failed compilation of regex */
   if (regcomp(regex, LOGIN_REGEX, REG_EXTENDED | REG_NOSUB | REG_ICASE ) != 0) {
      SAFE_FREE(regex);
      return 0;
   }

   /* execute the regex */
   if (regexec(regex, ptr, 0, NULL, 0) == 0)
      ret = 1;
    
   SAFE_FREE(regex);
   return ret;
}
#endif

/* EOF */

// vim:ts=3:expandtab

