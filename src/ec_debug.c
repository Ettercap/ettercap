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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_debug.c,v 1.7 2003/09/17 11:49:12 alor Exp $

*/

#include <ec.h>
#include <ec_threads.h>
#include <ec_strings.h>

#include <ctype.h>

#ifdef DEBUG

#ifdef HAVE_NCURSES
   #include <ncurses.h>
#endif
#ifdef HAVE_GTK
   #include <gtk/gtk.h>
#endif
#ifdef HAVE_OPENSSL
   #include <openssl/opensslv.h>
   #include <openssl/crypto.h>
#endif

extern char pcap_version[];
#include <libnet.h>
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

/* protos */

void debug_init(void);
static void debug_close(void);
void debug_msg(const char *message, ...);

/**********************************/

void debug_init(void)
{
#ifdef HAVE_SYS_UTSNAME_H
   struct utsname buf;
#endif

   if ((debug_file = fopen (GBL_DEBUG_FILE, "w")) == NULL) {
      ERROR_MSG("Couldn't open for writing %s", GBL_DEBUG_FILE);
   }
   
   fprintf (debug_file, "\n==============================================================\n");
                   
  	fprintf (debug_file, "\n-> %s %s\n\n", GBL_PROGRAM, GBL_VERSION);
   #ifdef HAVE_SYS_UTSNAME_H
      uname(&buf);
      fprintf (debug_file, "-> running on %s %s %s\n", buf.sysname, buf.release, buf.machine);
   #endif
   #if defined (__GNUC__) && defined (__GNUC_MINOR__)
      fprintf (debug_file, "-> compiled with gcc %d.%d (%s)\n", __GNUC__, __GNUC_MINOR__, GCC_VERSION);
   #endif
   #if defined (__GLIBC__) && defined (__GLIBC_MINOR__)
      fprintf (debug_file, "-> glibc version %d.%d\n", __GLIBC__, __GLIBC_MINOR__);
   #endif
   fprintf(debug_file, "-> libpcap version %s\n", pcap_version);
   fprintf(debug_file, "-> libnet version %s\n", LIBNET_VERSION);
   fprintf(debug_file, "-> libz version %s\n", zlibVersion());
   #ifdef HAVE_OPENSSL 
      fprintf (debug_file, "-> lib     %s\n", SSLeay_version(SSLEAY_VERSION));
      fprintf (debug_file, "-> headers %s\n", OPENSSL_VERSION_TEXT);
   #endif
   #ifdef HAVE_NCURSES 
      fprintf (debug_file, "-> %s\n", curses_version());
   #endif
   #ifdef HAVE_GTK 
      fprintf (debug_file, "-> gtk+ %d.%d.%d\n", gtk_major_version, gtk_minor_version, gtk_micro_version);
   #endif
   fprintf (debug_file, "\n\nDEVICE OPENED FOR %s DEBUGGING\n\n", GBL_PROGRAM);
   fflush(debug_file);
   atexit(debug_close);
}



void debug_close(void)
{
   fprintf (debug_file, "\n\nDEVICE CLOSED FOR DEBUGGING\n\n");
   fflush(debug_file);
   fclose (debug_file);
}


void debug_msg(const char *message, ...)
{
   va_list ap;
   char debug_message[strlen(message)+2];

   fprintf (debug_file, "[%9s]\t", ec_thread_getname(EC_SELF));

   strlcpy(debug_message, message, sizeof(debug_message));
   strlcat(debug_message, "\n", sizeof(debug_message));

   va_start(ap, message);
   vfprintf(debug_file, debug_message, ap);
   va_end(ap);

   fflush(debug_file);
}

#endif /* DEBUG */


/* EOF */

// vim:ts=3:expandtab

