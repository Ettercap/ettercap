/*
    ettercap -- passive TCP finterprint module

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


*/

#include <ec.h>
#include <ec_file.h>
#include <ec_socket.h>
#include <ec_fingerprint.h>
#ifdef HAVE_CURL
   #include <curl/curl.h>
#endif

#define LOAD_ENTRY(p,h,v) do {                                 \
   SAFE_CALLOC((p), 1, sizeof(struct entry));                  \
   memcpy((p)->finger, h, FINGER_LEN);                         \
   (p)->finger[FINGER_LEN] = '\0';                             \
   (p)->os = strdup (v);                                       \
   (p)->os[strlen(p->os)-1] = '\0';                            \
} while (0)

/* globals */

static SLIST_HEAD(, entry) finger_head;

struct entry {
   char finger[FINGER_LEN+1];
   char *os;
   SLIST_ENTRY(entry) next;
};

/* protos */

static void fingerprint_discard(void);
   
/*****************************************/


static void fingerprint_discard(void)
{
   struct entry *l;

   while (SLIST_FIRST(&finger_head) != NULL) {
      l = SLIST_FIRST(&finger_head);
      SLIST_REMOVE_HEAD(&finger_head, next);
      SAFE_FREE(l->os);
      SAFE_FREE(l);
   }

   DEBUG_MSG("ATEXIT: fingerprint_discard");
   
   return;
}


int fingerprint_init(void)
{
   struct entry *p;
   struct entry *last = NULL;
   
   int i;

   char line[128];
   char os[OS_LEN+1];
   char finger[FINGER_LEN+1];
   char *ptr;

   FILE *f;

   i = 0;

   f = open_data("share", TCP_FINGERPRINTS, FOPEN_READ_TEXT);
   ON_ERROR(f, NULL, "Cannot open %s", TCP_FINGERPRINTS);

   while (fgets(line, 128, f) != 0) {
      
      if ( (ptr = strchr(line, '#')) )
         *ptr = 0;

      /*  skip 0 length line */
      if (!strlen(line))  
         continue;
        
      strncpy(finger, line, FINGER_LEN);
      strncpy(os, line + FINGER_LEN + 1, OS_LEN);

      LOAD_ENTRY(p, finger, os);

      /* sort the list ascending */
      if (last == NULL)
         SLIST_INSERT_HEAD(&finger_head, p, next);
      else
         SLIST_INSERT_AFTER(last, p, next);

      /* set the last entry */
      last = p;

      /* count the fingerprints */
      i++;

   }

   DEBUG_MSG("fingerprint_init -- %d fingers loaded", i);
   USER_MSG("%4d tcp OS fingerprint\n", i);
   
   fclose(f);

   atexit(fingerprint_discard);

   return i;
}

/*
 * search in the database for a given fingerprint
 */

int fingerprint_search(const char *f, char *dst)
{
   struct entry *l;
  
   //Do not process if length is invalid
   if (!strcmp(f, "") || strlen(f) != FINGER_LEN) {
      strncpy(dst, "UNKNOWN", 8);
      return E_SUCCESS;
   }
   
   /* if the fingerprint matches, copy it in the dst and
    * return E_SUCCESS.
    * if it is not found, copy the next finger in dst 
    * and return -E_NOTFOUND, it is the nearest fingerprint
    */
   
   SLIST_FOREACH(l, &finger_head, next) {
   
      /* this is exact match */
      if ( memcmp(l->finger, f, FINGER_LEN) == 0) {
         strncpy(dst, l->os, OS_LEN+1);
         return E_SUCCESS;
      }
      
      /* 
       * if not found seach with wildcalderd MSS 
       * but he same WINDOW size
       */
      if ( memcmp(l->finger, f, FINGER_LEN) > 0) {
         
         /* the window field is FINGER_MSS bytes */
         char win[FINGER_MSS];
         char pattern[FINGER_LEN+1];
         
         /* the is the next in the list */
         strncpy(dst, l->os, OS_LEN+1);  
        
         strncpy(win, f, FINGER_MSS);
         win[FINGER_MSS-1] = '\0';
         
         /* pattern will be something like:
          *
          *  0000:*:TT:WS:0:0:0:0:F:LT
          */
         snprintf(pattern, FINGER_LEN+1, "%s:*:%s", win, f + FINGER_TTL);

         /* search for equal WINDOW but wildcarded MSS */
         while (l != SLIST_END(&finger_head) && !strncmp(l->finger, win, 4)) {
            if (match_pattern(l->finger, pattern)) {
               /* save the nearest one (wildcarded MSS) */
               strncpy(dst, l->os, OS_LEN+1); 
               return -E_NOTFOUND;
            }
            l = SLIST_NEXT(l, next);
         }
         return -E_NOTFOUND;
      }
   }

   if(EC_GBL_CONF->submit_fingerprint)
   	fingerprint_submit(NULL, NULL, f, "Unknown");
   return -E_NOTFOUND;
}

/*
 * initialize the fingerprint string
 */

void fingerprint_default(char *finger)
{
   /* 
    * initialize the fingerprint 
    *
    * WWWW:_MSS:TT:WS:S:N:D:T:F:LT
    */
   strncpy(finger,"0000:_MSS:TT:WS:0:0:0:0:F:LT", 29);  
}

/*
 * add a parameter to the finger string
 */

void fingerprint_push(char *finger, int param, int value)
{
   char tmp[10];
   int lt_old = 0;

   ON_ERROR(finger, NULL, "finger_push used on NULL string !!");
   
   switch (param) {
      case FINGER_WINDOW:
         snprintf(tmp, sizeof(tmp), "%04X", value);
         memcpy(finger + FINGER_WINDOW, tmp, 4);
         break;
      case FINGER_MSS:
         snprintf(tmp, sizeof(tmp), "%04X", value);
         memcpy(finger + FINGER_MSS, tmp, 4);
         break;
      case FINGER_TTL:
         snprintf(tmp, sizeof(tmp), "%02X", TTL_PREDICTOR(value));
         memcpy(finger + FINGER_TTL, tmp, 2);
         break;
      case FINGER_WS:
         snprintf(tmp, sizeof(tmp), "%02X", value);
         memcpy(finger + FINGER_WS, tmp, 2);
         break;
      case FINGER_SACK:
         snprintf(tmp, sizeof(tmp), "%d", value);
         memcpy(finger + FINGER_SACK, tmp, 1);
         break;
      case FINGER_NOP:
         snprintf(tmp, sizeof(tmp), "%d", value);
         memcpy(finger + FINGER_NOP, tmp, 1);
         break;
      case FINGER_DF:
         snprintf(tmp, sizeof(tmp), "%d", value);
         memcpy(finger + FINGER_DF, tmp, 1);
         break;
      case FINGER_TIMESTAMP:
         snprintf(tmp, sizeof(tmp), "%d", value);
         memcpy(finger + FINGER_TIMESTAMP, tmp, 1);
         break;
      case FINGER_TCPFLAG:
         if (value == 1)
            memcpy(finger + FINGER_TCPFLAG, "A", 1);
         else
            memcpy(finger + FINGER_TCPFLAG, "S", 1);
         break;
      case FINGER_LT:
         /*
          * since the LENGTH is the sum of the IP header
          * and the TCP header, we have to calculate it
          * in two steps. (decoders are unaware of other layers)
          */
         lt_old = strtoul(finger + FINGER_LT, NULL, 16);
         snprintf(tmp, sizeof(tmp), "%02X", value + lt_old);
         memcpy(finger + FINGER_LT, tmp, 2);
         break;                                 
   }
}

/*
 * round the TTL to the nearest power of 2 (ceiling)
 */

u_int8 TTL_PREDICTOR(u_int8 x)
{                            
   register u_int8 i = x;
   register u_int8 j = 1;
   register u_int8 c = 0;

   do {
      c += i & 1;
      j <<= 1;
   } while ( i >>= 1 );

   if ( c == 1 )
      return x;
   else
      return ( j ? j : 0xff );
}


/*
 * submit a fingerprint to the ettercap website
 * Example of php code to intercept the post
 <?php
 $file = 'fingerprints.txt';
 if( isset($_POST['finger']) && isset($_POST['os']) ) {
   $fingerprint = 'finger is: ' . $_POST['finger'] . ' and os is: ' . $_POST['os'] . PHP_EOL;
   file_put_contents($file, $fingerprint, FILE_APPEND);
 }
?>

 */
int fingerprint_submit(char* host, char* page, const char *finger, const char *os)
{
   char postparams[1024];
   char *os_encoded;
   size_t i, os_enclen;
   char fullpage [ PAGE_LEN + 1 ];
   char fullurl[HOST_LEN + PAGE_LEN + 2];
#ifdef HAVE_CURL
   CURL *curl;
   CURLcode res;
#else
   int sock;
#endif

   if (strlen(host) == 0)
      strcpy(host, DEFAULT_HOST);

   if (strlen(page) == 0)
      strcpy(page, DEFAULT_PAGE);

   if (page[0] != '/')
      strcpy(fullpage, "/");

   strcat(fullpage, page);

   strcpy(fullurl, host);
   strcat(fullurl, fullpage);

   memset(postparams, 0, sizeof(postparams));

   /* some sanity checks */
   if (strlen(host) > HOST_LEN || strlen(fullpage) > PAGE_LEN || strlen(finger) > FINGER_LEN || strlen(os) > OS_LEN)
      return -E_INVALID;

   os_encoded = strdup(os);
   /* sanitize the os (encode the ' ' to '+') */
   os_enclen = strlen(os_encoded);
   for (i = 0; i < os_enclen; i++)
      if (os_encoded[i] == ' ') 
         os_encoded[i] = '+';

   USER_MSG("Submitting the fingerprint to %s...\n", fullurl);

#ifdef HAVE_CURL
   curl_global_init(CURL_GLOBAL_ALL);
   curl = curl_easy_init();

   if (curl) {

      snprintf(postparams, sizeof(postparams), "finger=%s&os=%s", finger, os_encoded);
      SAFE_FREE(os_encoded);

      curl_easy_setopt(curl, CURLOPT_URL, fullurl);
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postparams);

      res = curl_easy_perform(curl);

      DEBUG_MSG("Post request content is: %s\n", postparams);
      if (res != CURLE_OK) {
         USER_MSG("Failed to submit fingerprint: %s\n", curl_easy_strerror(res));
      } else {
         USER_MSG("New fingerprint submitted to the remote website...\n");
      }

      curl_easy_cleanup(curl);
   }

   curl_global_cleanup();

#else
      
   /* prepare the socket */
   sock = open_socket(host, 80);
   
   switch(sock) {
      case -E_NOADDRESS:
         FATAL_MSG("Cannot resolve %s", host);
         break;
      case -E_FATAL:
         FATAL_MSG("Cannot create the socket");
         break;
      case -E_TIMEOUT:
         FATAL_MSG("Connect timeout to %s on port 80", host);
         break;
      case -E_INVALID:
         FATAL_MSG("Error connecting to %s on port 80", host);
         break;
   }

   /* prepare the HTTP request */
   snprintf(postparams, sizeof(postparams), "POST %s HTTP/1.1\r\n"
                                     "Host: %s\r\n"
                                     "Accept: */*\r\n"
                                     "User-Agent: %s (%s)\r\n"
                                     "Content-Length: %zu\r\n"
                                     "Content-Type: application/x-www-form-urlencoded \r\n\r\n"
                                     "finger=%s&os=%s\r\n"
                                     "\r\n", fullpage, host, EC_GBL_PROGRAM, EC_GBL_VERSION, 7 + strlen(finger) + 4 + strlen(os_encoded), finger, os_encoded );
  
   SAFE_FREE(os_encoded);

   /* send the request to the server */
   socket_send(sock, (const u_char*)postparams, strlen(postparams));

   /* ignore the server response */
   close_socket(sock);

   DEBUG_MSG("Post request content is: %s\n", postparams);
   USER_MSG("New fingerprint submitted to the remote website...\n");

#endif

   return E_SUCCESS;
}

/* EOF */

// vim:ts=3:expandtab

