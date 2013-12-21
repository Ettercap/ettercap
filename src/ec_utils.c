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
   
   return ESUCCESS;
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
   if (GBL_OPTIONS->regex)
      regfree(GBL_OPTIONS->regex);

   /* unset the regex if empty */
   if (!strcmp(regex, "")) {
      SAFE_FREE(GBL_OPTIONS->regex);
      return ESUCCESS;
   }
  
   /* allocate the new structure */
   SAFE_CALLOC(GBL_OPTIONS->regex, 1, sizeof(regex_t));
  
   /* compile the regex */
   err = regcomp(GBL_OPTIONS->regex, regex, REG_EXTENDED | REG_NOSUB | REG_ICASE );

   if (err) {
      regerror(err, GBL_OPTIONS->regex, errbuf, sizeof(errbuf));
      FATAL_MSG("%s\n", errbuf);
   }

   return ESUCCESS;
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
 * regain root privs
 */
void regain_privs(void)
{
   u_int uid, gid;
   char *var;
   DEBUG_MSG("ATEXIT: regain_privs");

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

   /* if the EC_UID variable is not set, default to GBL_CONF->ec_uid (nobody) */
   if (var != NULL)
      uid = atoi(var);
   else
      uid = GBL_CONF->ec_uid;

   /* get the env variable for the GID to drop privs to */
   var = getenv("EC_GID");

   /* if the EC_UID variable is not set, default to GBL_CONF->ec_gid (nobody) */
   if (var != NULL)
      gid = atoi(var);
   else
      gid = GBL_CONF->ec_gid;

   DEBUG_MSG("drop_privs: setuid(%d) setgid(%d)", uid, gid);

   /* drop to a good uid/gid ;) */
   if ( setgid(gid) < 0 )
      ERROR_MSG("setgid()");

   if ( seteuid(uid) < 0 )
      ERROR_MSG("seteuid()");

   DEBUG_MSG("privs: UID: %d %d  GID: %d %d", (int)getuid(), (int)geteuid(), (int)getgid(), (int)getegid() );
   USER_MSG("Privileges dropped to UID %d GID %d...\n\n", (int)getuid(), (int)getgid() );
}

/* EOF */


// vim:ts=3:expandtab

