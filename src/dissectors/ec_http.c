/*
    ettercap -- dissector http -- TCP 80

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

    $Id: ec_http.c,v 1.1 2003/11/27 23:35:19 lordnaga Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <ec_strings.h>

/* globals */
#define USER 1
#define PASS 2

struct http_status {
   u_char post_status;
#define POST_WAIT_DELIMITER 1
#define POST_LAST_CHANCE 2
   u_char url[150];
/* XXX - Manage this array dinamically (with session_destroyer) */
};

/* protos */
FUNC_DECODER(dissector_http);
void http_init(void);
void Parse_Method_Get(u_char *ptr, struct packet_object *po);
void Parse_Method_Post(u_char *ptr, struct packet_object *po);
void Decode_Url(u_char *src);
void Find_Url(u_char *to_parse, char **ret);
void Parse_Post_Payload(u_char *ptr, struct http_status *conn_status, struct packet_object *po);
u_char Parse_Form(u_char *to_parse, char **ret, char mode);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init http_init(void)
{
   dissect_add("http", APP_LAYER_TCP, 80, dissector_http);
}

FUNC_DECODER(dissector_http)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct ec_session *s = NULL;
   void *ident = NULL;
   struct http_status *conn_status;

   /* unused variable */
   (void)end;

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;

   dissect_create_ident(&ident, PACKET);

   /* Parse client requests.
    * Check the request type first. 
    */
   if (FROM_CLIENT("http", PACKET)) {
      if (!strncmp(ptr, "GET ", 4))
         Parse_Method_Get(ptr + strlen("GET "), PACKET);
      else if (!strncmp(ptr, "POST ", 5))
         Parse_Method_Post(ptr + strlen("POST "), PACKET);
      else if (session_get(&s, ident, DISSECT_IDENT_LEN) == ESUCCESS) {
         conn_status = (struct http_status *) s->data;
	 
	 /* Are we waiting for post termination? */
	 if (conn_status->post_status)
            Parse_Post_Payload(ptr, conn_status, PACKET);
      } 	 
      /* CONNECT method brings only Proxy-Auth */
   } else {
      /* Parse only server's header packets */
      if (!strncmp(ptr, "HTTP", 4)) {
         if (session_get(&s, ident, DISSECT_IDENT_LEN) == ESUCCESS) {      
            conn_status = (struct http_status *) s->data;
	    
            /* Since the server replies there's no need
             * to wait for POST termination
             */
            if (conn_status->post_status)
               dissect_wipe_session(PACKET);
         }
      }
   }

   SAFE_FREE(ident);
   return NULL;
}      

/* Deal with POST continuation */
void Parse_Post_Payload(u_char *ptr, struct http_status *conn_status, struct packet_object *po)
{ 
   char *user=NULL, *pass=NULL;
   
   if (conn_status->post_status == POST_WAIT_DELIMITER)
      if ((ptr = strstr(ptr, "\r\n\r\n"))) { 
         ptr+=4;
         conn_status->post_status = POST_LAST_CHANCE;
      }
   
   if (conn_status->post_status == POST_LAST_CHANCE) {
      if (Parse_Form(ptr, &user, USER) && Parse_Form(ptr, &pass, PASS)) {
         po->DISSECTOR.user = user;
         po->DISSECTOR.pass = pass;
         po->DISSECTOR.info = strdup(conn_status->url);
	 dissect_wipe_session(po);
	 //printf("DECODED %s %s %s\n", po->DISSECTOR.user, po->DISSECTOR.pass, po->DISSECTOR.info);
	 /* ----------- PRINT PASSWORDS ----------- */	 
      } else
         SAFE_FREE(user);
   }
}

/* Parse the POST header */
void Parse_Method_Post(u_char *ptr, struct packet_object *po) 
{
   char *url = NULL;
   struct ec_session *s = NULL;
   struct http_status *conn_status;
     
   DEBUG_MSG("HTTP --> dissector http (method POST)");
   
   Find_Url(ptr, &url);
   
   /* We create a session just in case the post was 
    * fragmented into more packets. The session will be
    * wiped on HTTP server reply.
    */
   dissect_create_session(&s, PACKET);
   SAFE_CALLOC(s->data, 1, sizeof(struct http_status));                  
   conn_status = (struct http_status *) s->data;
   conn_status->post_status = POST_WAIT_DELIMITER;
   strlcpy(conn_status->url, url, sizeof(conn_status->url));
   session_put(s);

   Parse_Post_Payload(ptr, conn_status, po);
   
   SAFE_FREE(url);
}

/* Search for passwords in the URL */
void Parse_Method_Get(u_char *ptr, struct packet_object *po) 
{
   u_char *to_parse = NULL;
   u_char *delimiter = NULL;
   char *user = NULL;
   char *pass = NULL;
   
   DEBUG_MSG("HTTP --> dissector http (method GET)");

   /* Isolate the parameters and copy them into another string */
   if (!(to_parse = strstr(ptr, "?")))
      return;
      
   if (!(to_parse = strdup(to_parse)))
      return;      
      
   if (!(delimiter = strstr(to_parse, " HTTP"))) 
      goto http_get_failure;
   
   /* NULL terminate the newly created parameter string */
   *delimiter = 0;
   
   /* Let's parse the parameter list */
   if (!Parse_Form(to_parse, &user, USER) || !Parse_Form(to_parse, &pass, PASS)) {
      SAFE_FREE(user);
      goto http_get_failure;
   }

   po->DISSECTOR.user = user;
   po->DISSECTOR.pass = pass;

   /* Fill the info with the URL */
   Find_Url(ptr, &(po->DISSECTOR.info));
      
   /* ----------- PRINT PASSWORDS ----------- */
   
http_get_failure:   
   SAFE_FREE(to_parse);
}


/* Match users or passwords in a string */
u_char Parse_Form(u_char *to_parse, char **ret, char mode)
{
   /* XXX - Move these fields into a separate file */
   u_char *user_field[] = {"user", "email", "username", "userid", "login",
                           "form_loginname", "loginname", "pop_login",
                           "uid", "id", "user_id", "screenname", "uname",
                           "ulogin", "acctname", "account", "member",
                           "mailaddress", "membername", "login_username",
                           "uin", ""};

   u_char *pass_field[] = {"pass", "password", "passwd", "form_pw", "pw",
                           "userpassword", "pwd", "upassword", "login_password",
                           "passwort", "passwrd", ""};

   u_char **ptr, *q, i;

   /* Strip the '?' from a GET method */
   if (*to_parse == '?') to_parse++;    
   if (*to_parse == 0) 
      return 0;

   /* Search for users or passwords */   
   if (mode == PASS)
      ptr = pass_field;
   else
      ptr = user_field;

   /* Search matches between each parameter and 
    * recognized users and passwords 
    */      
   for (i=0, q=to_parse; strcmp(ptr[i], ""); i++, q=to_parse) 
      do {
         if (*q == '&') q++;
         if (!strncasecmp(q, ptr[i], strlen(ptr[i])) && *(q+strlen(ptr[i])) == '=' ) {
	    /* Return the value past the '=' */
	    if (!(*ret = strdup(q + strlen(ptr[i]) + 1)))
               return 0;

            /* NULL terminate the value if it's not the last */
	    if ((q = strchr(*ret, '&')))
	       *q = 0; 

            Decode_Url((u_char *)*ret);
            return 1;
         }
      } while ( (q = strchr(q, '&')) );

   return 0;
}


/* Unescape the string */
void Decode_Url(u_char *src)
{
   u_char t[3];
   u_int32 i, j, ch;

   /* Paranoid test */
   if (!src)
      return;
      
   /* NULL terminate for the strtoul */
   t[3] = 0;
   
   for (i=0, j=0; src[i] != 0; i++, j++) {
      ch = (u_int32)src[i];
      if (ch == '%' && isxdigit((u_int32)src[i + 1]) && isxdigit((u_int32)src[i + 2])) {
         memcpy(t, src+i+1, 2);
         ch = strtoul(t, NULL, 16);
         i += 2;
      }
      src[j] = (u_char)ch;
   }
   src[j] = 0;
}

void Find_Url(u_char *to_parse, char **ret) 
{
   u_char *fromhere, *page=NULL, *host=NULL;     
   u_int32 len;

   /* If the referer exists */
   if ((fromhere = strstr(to_parse, "Referer: "))) 
            if ((*ret = strdup(fromhere + strlen("Referer: "))))
               strtok(*ret, "\r\n");
   else {
      /* Get the page from the request */
      page = strdup(to_parse);
      strtok(page, " HTTP");

      /* If the path is relative, search for the Host */
      if ((*page=='/') && (fromhere = strstr(to_parse, "Host: "))) {
         host = strdup( fromhere + strlen("Host: ") );
         strtok(host, "\r\n");
      } else 
         host = strdup("");
	 
      len = strlen(page) + strlen(host) + 2;
      SAFE_CALLOC(*ret, len, sizeof(char));
      sprintf(*ret, "%s%s", host, page);

      SAFE_FREE(page);
      SAFE_FREE(host);            
   }    
   
   Decode_Url((u_char *)*ret);
}

/* EOF */

// vim:ts=3:expandtab
