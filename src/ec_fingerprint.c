/*
    ettercap -- passive TCP finterprint module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_fingerprint.c,v 1.2 2003/03/14 23:46:36 alor Exp $

*/

#include <ec.h>
#include <ec_file.h>
#include <ec_hash.h>
#include <ec_fingerprint.h>

#define TABBIT    7 /* 2^7 bit tab entries: 128 SLISTS */
#define TABSIZE   (1UL<<TABBIT)
#define TABMASK   (TABSIZE-1) /* to mask fnv_1 hash algorithm */

#define LOAD_ENTRY(p,h,v) do {                                 \
   (p) = malloc (sizeof (struct entry));                       \
   ON_ERROR((p), NULL, "malloc() virtual memory exhausted");   \
   memcpy((p)->finger, h, FINGER_LEN);                         \
   (p)->os = strdup (v);                                       \
} while (0)

/* globals */

SLIST_HEAD(, entry) finger_head[TABSIZE];

struct entry {
   char finger[FINGER_LEN];
   char *os;
   SLIST_ENTRY(entry) entries;
};

/* protos */

static void fingerprint_discard(void);
int fingerprint_init(void);
char * fingerprint_search(char *f);

char * fingerprint_alloc(void);
char * fingerprint_destroy(char **finger);
void fingerprint_push(char *finger, int param, int value);
static u_char TTL_PREDICTOR(u_char x);
/*****************************************/


static void fingerprint_discard(void)
{
   struct entry *l;

   int i;

   for (i = 0; i < TABSIZE; i++) {

      while (SLIST_FIRST(&finger_head[i]) != NULL) {
         l = SLIST_FIRST(&finger_head[i]);
         SLIST_REMOVE_HEAD(&finger_head[i], entries);
         free(l->os);
         free(l);
      }
   }

   DEBUG_MSG("ATEXIT: fingerprint_discard");
   
   return;
}


int fingerprint_init(void)
{
   struct entry *p;
   
   int i;

   char line[128];
   char os[OS_LEN+1];
   char finger[FINGER_LEN+1];
   char *ptr;

   FILE *f;

   i = 0;

   f = open_data(TCP_FINGERPRINTS, "r");

   while (fgets(line, 128, f) != 0) {
      
      if ( (ptr = strchr(line, '#')) )
         *ptr = 0;

      /*  skip 0 length line */
      if (!strlen(line))  
         continue;
        
      strlcpy(finger, line, FINGER_LEN);
      strlcpy(os, line, OS_LEN);

      LOAD_ENTRY(p, finger, os);

      SLIST_INSERT_HEAD(&(finger_head[fnv_32(finger, FINGER_LEN) & TABMASK]), p, entries);

      i++;

   }

   DEBUG_MSG("fingerprint_init -- %d fingers loaded", i);
   
   fclose(f);

   atexit(fingerprint_discard);

   return i;
}

/*
 * search in the database for a given fingerprint
 */

char * fingerprint_search(char *f)
{
   struct entry *l;

   SLIST_FOREACH(l, &finger_head[fnv_32(f, FINGER_LEN) & TABMASK], entries) {
      if (!memcmp(l->finger, f, FINGER_LEN))
         return (l->os);
   }

   return NULL;

}

/*
 * initialize the fingerprint string
 */

char * fingerprint_alloc(void)
{
   char *q;

   q = calloc(FINGER_LEN+1, sizeof(char));
   ON_ERROR(q, NULL, "can't callocate memory");

   /* 
    * initialize the fingerprint 
    *
    * WWWW:_MSS:TT:WS:S:N:D:T:F:LT
    */
   strcpy(q,"0000:_MSS:TT:WS:0:0:0:0:F:LT");
   
   return q;
}

/*
 * destroy a fingerprint
 */

char * fingerprint_destroy(char **finger)
{
   SAFE_FREE(*finger);
   return NULL;
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
         strncpy(finger, tmp, 4);
         break;
      case FINGER_MSS:
         snprintf(tmp, sizeof(tmp), "%04X", value);
         strncpy(finger + 5, tmp, 4);
         break;
      case FINGER_TTL:
         snprintf(tmp, sizeof(tmp), "%02X", TTL_PREDICTOR(value));
         strncpy(finger + 10, tmp, 2);
         break;
      case FINGER_WS:
         snprintf(tmp, sizeof(tmp), "%02X", value);
         strncpy(finger + 13, tmp, 2);
         break;
      case FINGER_SACK:
         snprintf(tmp, sizeof(tmp), "%d", value);
         strncpy(finger + 16, tmp, 1);
         break;
      case FINGER_NOP:
         snprintf(tmp, sizeof(tmp), "%d", value);
         strncpy(finger + 18, tmp, 1);
         break;
      case FINGER_DF:
         snprintf(tmp, sizeof(tmp), "%d", value);
         strncpy(finger + 20, tmp, 1);
         break;
      case FINGER_TIMESTAMP:
         snprintf(tmp, sizeof(tmp), "%d", value);
         strncpy(finger + 22, tmp, 1);
         break;
      case FINGER_TCPFLAG:
         if (value == 1)
            strncpy(finger + 24, "A", 1);
         else
            strncpy(finger + 24, "S", 1);
         break;
      case FINGER_LT:
         /*
          * since the LENGHT is the sum of the IP header
          * and the TCP header, we have to calculate it
          * in two steps. (decoders are unaware of other layers)
          */
         lt_old = strtoul(finger + 26, NULL, 16);
         snprintf(tmp, sizeof(tmp), "%02X", value + lt_old);
         strncpy(finger + 26, tmp, 2);
         break;                                 
   }
}

/*
 * round the TTL to the nearest power of 2 (ceiling)
 */

static u_char TTL_PREDICTOR(u_char x)
{                            
   register u_char i = x;
   register u_char j = 1;
   register u_char c = 0;

   do {
      c += i & 1;
      j <<= 1;
   } while ( i >>= 1 );

   if ( c == 1 )
      return x;
   else
      return ( j ? j : 0xff );
}



/* EOF */

// vim:ts=3:expandtab

