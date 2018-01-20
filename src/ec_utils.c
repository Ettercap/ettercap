/*
    ettercap -- Ettercap utilities

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
#include <ec_interfaces.h>
#include <ec_sniff.h>
#include <ec_send.h>
#include <ec_log.h>
#include <ec_format.h>
#include <ec_mitm.h>
#include <ec_filter.h>
#include <ec_plugins.h>
#include <ec_conf.h>
#include <ec_strings.h>
#include <ec_encryption.h>
#ifdef HAVE_EC_LUA
#include <ec_lua.h>
#endif

#include <ctype.h>

#define BASE64_SIZE(x) (((x)+2) / 3 * 4 + 1)
static const uint8_t map2[] =
{
    0x3e, 0xff, 0xff, 0xff, 0x3f, 0x34, 0x35, 0x36,
    0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x01,
    0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
    0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
    0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
    0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33
};

/*
 * This function parses the input in the form [1-3,17,5-11]
 * and fill the structure with expanded numbers.
 */

int expand_token(char *s, u_int max, void (*func)(void *t, u_int n), void *t )
{
   char *str = strdup(s);
   char *p, *q, r;
   char *end;
   u_int a = 0, b = 0;
   
   DEBUG_MSG("expand_token %s", s);
   
   p = str;
   end = p + strlen(p);
   
   while (p < end) {
      q = p;
      
      /* find the end of the first digit */
      while ( isdigit((int)*q) && q++ < end);
      
      r = *q;   
      *q = 0;
      /* get the first digit */
      a = atoi(p);
      if (a > max) 
         FATAL_MSG("Out of range (%d) !!", max);
      
      /* it is a range ? */
      if ( r == '-') {
         p = ++q;
         /* find the end of the range */
         while ( isdigit((int)*q) && q++ < end);
         *q = 0;
         if (*p == '\0') 
            FATAL_MSG("Invalid range !!");
         /* get the second digit */
         b = atoi(p);
         if (b > max) 
            FATAL_MSG("Out of range (%d)!!", max);
         if (b < a)
            FATAL_MSG("Invalid decrementing range !!");
      } else {
         /* it is not a range */
         b = a; 
      } 
      
      /* process the range and invoke the callback */
      for(; a <= b; a++) {
         func(t, a);
      }
      
      if (q == end) break;
      else  p = q + 1;      
   }
  
   SAFE_FREE(str);
   
   return E_SUCCESS;
}

/*
 * compile the regex
 */

int set_regex(char *regex)
{
   int err;
   char errbuf[100];
   
   DEBUG_MSG("set_regex: %s", regex);

   /* free any previous compilation */
   if (EC_GBL_OPTIONS->regex)
      regfree(EC_GBL_OPTIONS->regex);

   /* unset the regex if empty */
   if (!strcmp(regex, "")) {
      SAFE_FREE(EC_GBL_OPTIONS->regex);
      return E_SUCCESS;
   }
  
   /* allocate the new structure */
   SAFE_CALLOC(EC_GBL_OPTIONS->regex, 1, sizeof(regex_t));
  
   /* compile the regex */
   err = regcomp(EC_GBL_OPTIONS->regex, regex, REG_EXTENDED | REG_NOSUB | REG_ICASE );

   if (err) {
      regerror(err, EC_GBL_OPTIONS->regex, errbuf, sizeof(errbuf));
      FATAL_MSG("%s\n", errbuf);
   }

   return E_SUCCESS;
}

char **parse_iflist(char *list)
{
   int i, n;
   char **r, *t, *p;

   for(i = 0, n = 1; list[i] != '\0'; list[i++] == ',' ? n++ : n);
   SAFE_CALLOC(r, n + 1, sizeof(char*));

   /* its self-explaining */
   for(r[i=0]=ec_strtok(list,",",&p);i<n&&(t=ec_strtok(NULL,",",&p))!=NULL;r[++i]=strdup(t));
   r[n] = NULL;

   return r;
}

/*
 * regain root privs inside an atexit call
 */
void regain_privs_atexit(void)
{
   DEBUG_MSG("ATEXIT: regain_privs");
   regain_privs();
}

/*
 * regain root privs
 */
void regain_privs(void)
{

#ifdef OS_WINDOWS
   return;
#endif
   if(seteuid(0) < 0)
      ERROR_MSG("seteuid()");

   USER_MSG("Regained root privileges: %d %d", getuid(), geteuid());
}

/* 
 * drop root privs 
 */
void drop_privs(void)
{
   u_int uid, gid;
   char *var;

#ifdef OS_WINDOWS
   /* do not drop privs under windows */
   return;
#endif

   /* are we root ? */
   if (getuid() != 0)
      return;

   /* get the env variable for the UID to drop privs to */
   var = getenv("EC_UID");

   /* if the EC_UID variable is not set, default to EC_GBL_CONF->ec_uid (nobody) */
   if (var != NULL)
      uid = atoi(var);
   else
      uid = EC_GBL_CONF->ec_uid;

   /* get the env variable for the GID to drop privs to */
   var = getenv("EC_GID");

   /* if the EC_UID variable is not set, default to EC_GBL_CONF->ec_gid (nobody) */
   if (var != NULL)
      gid = atoi(var);
   else
      gid = EC_GBL_CONF->ec_gid;

   reset_logfile_owners(geteuid(), getegid(), uid, gid);

   DEBUG_MSG("drop_privs: seteuid(%d) setegid(%d)", uid, gid);

   /* drop to a good uid/gid ;) */
   if ( setegid(gid) < 0 )
      ERROR_MSG("setegid()");

   if ( seteuid(uid) < 0 )
      ERROR_MSG("seteuid()");

   DEBUG_MSG("privs: UID: %d %d  GID: %d %d", (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid() );
   USER_MSG("Privileges dropped to EUID %d EGID %d...\n\n", (int)geteuid(), (int)getegid() );
}

/* base64 stuff */

int get_decode_len(const char *b64_str) {
   int len = strlen(b64_str);
   int padding = 0;

   if (len < 2)
       return 0;

   if (b64_str[len-1] == '=' && b64_str[len-2] == '=')
      padding = 2;
   else if (b64_str[len-1] == '=')
      padding = 1;
   return (int)len*0.75 - padding;
}


int base64decode(const char *src, char **outptr)
{
   int i, v;
   int decodeLen = get_decode_len(src);
   char *dst;

   SAFE_CALLOC(*outptr, decodeLen, sizeof(char));

   dst = *outptr;
   unsigned int sizeof_array = (sizeof(map2) / sizeof(map2[0]));
  
   v = 0;
   for (i=0; src[i] && src[i] != '='; i++) {
      unsigned int index = src[i] - 43;
      if (index >= sizeof_array || map2[index] == 0xff)
         return -1;
      v = (v << 6) + map2[index];
      if (i & 3) {
         if (dst - *outptr < decodeLen) {
            *dst++ = v >> (6 - 2 * (i & 3)); 
         }
      }    
   }

   return decodeLen;
}
int base64encode(const char *inputbuff, char **outptr)
{
   static const char b64[] = 
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

   char *ret, *dst;
   unsigned i_bits = 0;
   int i_shift = 0;
   int bytes_remaining = strlen(inputbuff);

   SAFE_CALLOC(*outptr, bytes_remaining*4/3+4, sizeof(char));

   ret = dst = *outptr;
   while(bytes_remaining) {
      i_bits = (i_bits << 8) + *inputbuff++;
      bytes_remaining--;
      i_shift += 8;

      do {
         *dst++ = b64[(i_bits << 6 >> i_shift) & 0x3f];
         i_shift -= 6;
      } while(i_shift > 6 || (bytes_remaining == 0 && i_shift > 0));
   }

   while((dst - ret) & 3)
      *dst++ = '=';
   *dst = '\0';
     
   return strlen(*outptr);
}

/*
 * Return a 'ctime()' time-string from either:
 *   a 'struct timeval *tv'
 * or if 'tv == NULL',
 *   returns a time-value for current time.
 *
 * NOT threadsafe (returns a static buffer), but there should hopefully
 * be no problem (?).
 */
const char *ec_ctime(const struct timeval *tv)
{
   const char *ts_str;
   static char result[30];
   time_t t;

   if (!tv)
      t = time(NULL);
   else
      t = (time_t) tv->tv_sec;

   ts_str = ctime(&t);

   /* ctime() has a newline at position 24. Get rid of it.  */
   if (ts_str)
      sprintf(result, "%.24s", ts_str);
   else
#if defined OS_DARWIN
      snprintf(result, sizeof(result), "%lu.%06d", (unsigned long)tv->tv_sec, tv->tv_usec);
#else
      snprintf(result, sizeof(result), "%lu.%06lu", (unsigned long)tv->tv_sec, tv->tv_usec);
#endif

  return (result);
}


/* EOF */


// vim:ts=3:expandtab
