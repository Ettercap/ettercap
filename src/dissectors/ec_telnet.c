/*
    ettercap -- dissector TELNET -- TCP 23

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

    $Id: ec_telnet.c,v 1.12 2003/10/28 22:15:04 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <ec_strings.h>

/* protos */

FUNC_DECODER(dissector_telnet);
void telnet_init(void);
void skip_telnet_command(u_char **ptr, u_char *end);
int match_login_regex(char *ptr);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init telnet_init(void)
{
   dissect_add("telnet", APP_LAYER_TCP, 23, dissector_telnet);
}

/*
 * telnet sends characters one per packet,
 * so we have to make sessions to collect 
 * the string among the packet stram.
 *
 * the telnet collector collects user and pass only if
 * a session is present.
 * the session is created looking at the server response
 * and searching for "login:", "failed" ecc... so we will
 * collect even failed logins.
 */

FUNC_DECODER(dissector_telnet)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* the connection is starting... create the session */
   CREATE_SESSION_ON_SYN_ACK("telnet", s);

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
   
   /* move the pointer to skip commands */
   skip_telnet_command(&ptr, end);
   
   /* the packet was made only by commands, skip it */
   if (ptr == end)
      return NULL;

   DEBUG_MSG("TELNET --> TCP dissector_telnet");
      
   /* create an ident to retrieve the session */
   dissect_create_ident(&ident, PACKET);
   
   /* is the message from the server or the client ? */
   if (FROM_SERVER("telnet", PACKET)) {
      
      /* the login was not successful, restart the collecting 
       * the collectin process is active if the session is empty
       * (as the one created on SYN+ACK)
       */
      /* this is not the session created on synack */
      if (session_get(&s, ident, DISSECT_IDENT_LEN) == -ENOTFOUND) {
         if (match_login_regex(ptr)) {
            DEBUG_MSG("\tdissector_telnet - BEGIN");
         
            /* create the session to begin the collection */
            dissect_create_session(&s, PACKET);
            /* use this value to remember to not collect the banner again */
            s->data = "\xe7\x7e";
            session_put(s);

            return NULL;
         }
      }
   } else {
      
      /* retrieve the session */
      if (session_get(&s, ident, DISSECT_IDENT_LEN) == ESUCCESS) {

         /* if the collecting process has to be initiated */
         if (!strcmp(s->data, "\xe7\x7e")) {
         
            /* the characters are not printable, skip them */
            if (!isprint((int)*ptr)) {
               SAFE_FREE(ident);
               return NULL;
            }
            
            DEBUG_MSG("\tdissector_telnet - FIRST PACKET");

            /* save the first packet */
            s->data = strdup(ptr);
         
         /* collect the subsequent packets */
         } else {
            size_t i;
            u_char *p;
            u_char str[strlen(s->data) + PACKET->DATA.disp_len + 2];

            memset(str, 0, sizeof(str));

            /* concat the char to the previous one */
            sprintf(str, "%s%s", (char *)s->data, ptr);
            
            /* parse the string for backspaces and erase as wanted */
            for (p = str, i = 0; i < strlen(str); i++) {
               if (str[i] == '\b' || str[i] == 0x7f) {
                  p--;
               } else {
                  *p = str[i];
                  p++;  
               }
            }
            *p = '\0';

            /* save the new string */
            SAFE_FREE(s->data);
            p = s->data = strdup(str);
            
            /* terminate the string at \n */
            if ((p = strchr(s->data, '\n')) != NULL)
               *p = '\0';
            
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
                  
                  
                  /* display the message */
                  DISSECT_MSG("TELNET : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                       ntohs(PACKET->L4.dst), 
                                       PACKET->DISSECTOR.user,
                                       PACKET->DISSECTOR.pass);

                  /* delete the session to stop the collection */
                  dissect_wipe_session(PACKET);
               }
               SAFE_FREE(ident);
               return NULL;
            }
         }
      }
   }
  
   /* delete the ident */
   SAFE_FREE(ident);

   /* check if it is the first readable packet sent by the server */
   IF_FIRST_PACKET_FROM_SERVER("telnet", s, ident) {
      size_t i;
   
      DEBUG_MSG("\tdissector_telnet BANNER");
      
      /* get the banner */
      SAFE_CALLOC(PACKET->DISSECTOR.banner, PACKET->DATA.len + 1, sizeof(char));
      memcpy(PACKET->DISSECTOR.banner, ptr, end - ptr );

      ptr = PACKET->DISSECTOR.banner;
      /* replace \r\n with spaces */ 
      for (i = 0; i < PACKET->DATA.len; i++) {
         if (ptr[i] == '\r' || ptr[i] == '\n' || ptr[i] == '\0')
         ptr[i] = ' ';
      }

      /* 
       * some OS (e.g. windows and ipso) send the "login:" in the
       * same packet as teh banner...
       */
      if (match_login_regex(ptr)) {
         DEBUG_MSG("\tdissector_telnet - BEGIN");
         
         /* create the session to begin the collection */
         dissect_create_session(&s, PACKET);
         /* use this value to remember to not collect the banner again */
         s->data = "\xe7\x7e";
         session_put(s);

         return NULL;
      }

   } ENDIF_FIRST_PACKET_FROM_SERVER(s, ident);           
      
   return NULL;
}

/*
 * move the pointer ptr while it is a telnet command.
 */
void skip_telnet_command(u_char **ptr, u_char *end)
{
   while(**ptr == 0xff && *ptr != end) {
      /* sub option 0xff 0xfa ... ... 0xff 0xf0 */
      if (*(*ptr + 1) == 0xfa) {
         *ptr += 1;
         /* search the sub-option end (0xff 0xf0) */
         do {
            *ptr += 1;
         } while(**ptr != 0xff && *ptr != end);
         /* skip the sub-option end */
         *ptr += 2;
      } else {
      /* normal option 0xff 0xXX 0xXX */
         *ptr += 3;
      }
   }
}

/* 
 * serach the strings which can identify failed login...
 * return 1 on succes, 0 on failure
 */
int match_login_regex(char *ptr)
{
   char *words[] = {"incorrect", "failed", "failure", NULL };
   int i = 0;
  
   /* 
    * "login:" is a special case, we have to take care
    * of messages from the server, they can contain login:
    * even if it is not the login prompt
    */
   if (strcasestr(ptr, "login:") && !strcasestr(ptr, "last") && !strcasestr(ptr, "from"))
      return 1;
   
   /* search for keywords */ 
   do {
      if (strcasestr(ptr, words[i]))
         return 1;
   } while (words[++i] != NULL);
   
   return 0;
}

/* EOF */

// vim:ts=3:expandtab

