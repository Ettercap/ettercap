/*
    ettercap -- debug module

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
#ifdef HAVE_EC_LUA
#include <ec_lua.h>
#endif

#include <ec_threads.h>

#include <ctype.h>

#ifdef DEBUG

#include <openssl/opensslv.h>
#include <openssl/crypto.h>

#include <libnet.h>
#include <pcap.h>
#include <zlib.h>

#include <stdarg.h>
#ifdef HAVE_SYS_UTSNAME_H
   #include <sys/utsname.h>
#ifdef OS_LINUX
   #include <features.h>
#endif
#endif

/* globals */

FILE *debug_file = NULL;

static pthread_mutex_t debug_mutex = PTHREAD_MUTEX_INITIALIZER;
#define DEBUG_LOCK     do{ pthread_mutex_lock(&debug_mutex); } while(0)
#define DEBUG_UNLOCK   do{ pthread_mutex_unlock(&debug_mutex); } while(0)

/* protos */

static void debug_close(void);

/**********************************/

void debug_init(void)
{
#ifdef HAVE_SYS_UTSNAME_H
   struct utsname buf;
#endif
   DEBUG_LOCK;
   
   if ((debug_file = fopen (EC_GBL_DEBUG_FILE, "w")) == NULL)
      ERROR_MSG("Couldn't open for writing %s", EC_GBL_DEBUG_FILE);
   
   fprintf (debug_file, "\n==============================================================\n\n");
                   
  	fprintf (debug_file, "-> ${prefix}        %s\n", INSTALL_PREFIX);
  	fprintf (debug_file, "-> ${exec_prefix}   %s\n", INSTALL_EXECPREFIX);
  	fprintf (debug_file, "-> ${bindir}        %s\n", INSTALL_BINDIR);
  	fprintf (debug_file, "-> ${libdir}        %s\n", INSTALL_LIBDIR);
  	fprintf (debug_file, "-> ${sysconfdir}    %s\n", INSTALL_SYSCONFDIR);
  	fprintf (debug_file, "-> ${datadir}       %s\n\n", INSTALL_DATADIR);

   #ifdef HAVE_EC_LUA
	ec_lua_print_info(debug_file);
   #endif

  	fprintf (debug_file, "-> %s %s\n\n", EC_GBL_PROGRAM, EC_GBL_VERSION);
   #ifdef HAVE_SYS_UTSNAME_H
      uname(&buf);
      fprintf (debug_file, "-> running on %s %s %s\n", buf.sysname, buf.release, buf.machine);
   #endif
   #if defined (__GNUC__) && defined (__GNUC_MINOR__)
      fprintf (debug_file, "-> compiled with gcc %d.%d (%s)\n", __GNUC__, __GNUC_MINOR__, CC_VERSION);
   #endif
   #if defined (__GLIBC__) && defined (__GLIBC_MINOR__)
      fprintf (debug_file, "-> glibc version %d.%d\n", __GLIBC__, __GLIBC_MINOR__);
   #endif
   fprintf(debug_file, "-> %s\n", pcap_lib_version());
   fprintf(debug_file, "-> libnet version %s\n", LIBNET_VERSION);
   fprintf(debug_file, "-> libz version %s\n", zlibVersion());
   #ifdef HAVE_PCRE
   fprintf(debug_file, "-> libpcre version %s\n", pcre_version());
   #endif
   #ifdef HAVE_PCRE2
   if(strlen(EC_TOSTRING(PCRE2_PRERELEASE)))
       fprintf(debug_file, "-> libpcre2 version %s.%s %s %s\n",
             EC_TOSTRING(PCRE2_MAJOR), EC_TOSTRING(PCRE2_MINOR),
             EC_TOSTRING(PCRE2_PRERELEASE), EC_TOSTRING(PCRE2_DATE));
   else
       fprintf(debug_file, "-> libpcre2 version %s.%s %s\n",
             EC_TOSTRING(PCRE2_MAJOR), EC_TOSTRING(PCRE2_MINOR),
             EC_TOSTRING(PCRE2_DATE));
   #endif
   #ifdef HAVE_EC_LUA
	ec_lua_print_version(debug_file);
   #endif
   fprintf (debug_file, "-> lib     %s\n", SSLeay_version(SSLEAY_VERSION));
   fprintf (debug_file, "-> headers %s\n", OPENSSL_VERSION_TEXT);
   fprintf (debug_file, "\n\nDEVICE OPENED FOR %s DEBUGGING\n\n", EC_GBL_PROGRAM);
   fflush(debug_file);
   
   DEBUG_UNLOCK;
   
   atexit(debug_close);
}



void debug_close(void)
{
   DEBUG_LOCK;
   
   fprintf (debug_file, "\n\nDEVICE CLOSED FOR DEBUGGING\n\n");
   fflush(debug_file);
   fclose (debug_file);
   /* set it to null and check from other threads */
   debug_file = NULL;

   DEBUG_UNLOCK;
}


void debug_msg(const char *message, ...)
{
   va_list ap;
   char debug_message[strlen(message)+2];

   DEBUG_LOCK;

   /* if it was closed by another thread on exit */
   if (debug_file == NULL)
      return;

   fprintf(debug_file, "[%9s]\t", ec_thread_getname(ec_thread_getpid(NULL)));

   strlcpy(debug_message, message, sizeof(debug_message));
   strlcat(debug_message, "\n", sizeof(debug_message));

   va_start(ap, message);
   vfprintf(debug_file, debug_message, ap);
   va_end(ap);

   fflush(debug_file);

   DEBUG_UNLOCK;
}

#endif /* DEBUG */


/* EOF */

// vim:ts=3:expandtab

