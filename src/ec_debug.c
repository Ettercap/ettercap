/*
    ettercap -- debug module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_debug.c,v 1.1 2003/03/08 13:53:38 alor Exp $

*/

#include <ec.h>
#include <ec_threads.h>

#include <ctype.h>

#ifdef DEBUG

#ifdef HAVE_NCURSES
   #include <ncurses.h>
#endif

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

char * hex_format(const u_char *buffer, int buff_len);

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
   #if defined (__GLIBC__) && defined (__GLIBC_MINOR__)
      fprintf (debug_file, "-> glibc version %d.%d\n", __GLIBC__, __GLIBC_MINOR__);
   #endif
   #if defined (__GNUC__) && defined (__GNUC_MINOR__)
      fprintf (debug_file, "-> compiled with gcc %d.%d\n", __GNUC__, __GNUC_MINOR__);
   #endif
//   fprintf(debug_file, "-> libpcap version %s\n", pcap_version);
   #ifdef HAVE_NCURSES 
      fprintf (debug_file, "-> %s\n", curses_version());
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

/* 
 * printf a binary string in a 
 * readable form
 */

char * hex_format(const u_char *buffer, int buff_len)
{
   static char *hexdata = NULL;
   int i, j, jm;
   int c, dim = 0;
   int cr = 16;

   if (buff_len == 0) return "";
   if (buffer == NULL) return "";

   c = cr*4 + 11;
   dim = c;

   for (i = 0; i < buff_len; i++)   // approximately
      if ( i % cr == 0)             // approximately
         dim += c;                  // approximately


   SAFE_FREE(hexdata);
   
   if ( (hexdata = (char *)calloc(dim, sizeof(char))) == NULL)
      ERROR_MSG("calloc()");

   sprintf(hexdata,"\n");
   for (i = 0; i < buff_len; i += cr) {
           sprintf(hexdata, "%s %04x: ", hexdata, i );
           jm = buff_len - i;
           jm = jm > cr ? cr : jm;

           for (j = 0; j < jm; j++) {
                   if ((j % 2) == 1) sprintf(hexdata, "%s%02x ", hexdata, (unsigned char) buffer[i+j]);
                   else sprintf(hexdata, "%s%02x", hexdata, (unsigned char) buffer[i+j]);
           }
           for (; j < cr; j++) {
                   if ((j % 2) == 1) strcat(hexdata, "   ");
                   else strcat(hexdata, "  ");
           }
           strcat(hexdata, " ");

           for (j = 0; j < jm; j++) {
                   c = buffer[i+j];
                   c = isprint(c) ? c : '.';
                   sprintf(hexdata, "%s%c", hexdata, c);
           }
           strcat(hexdata,"\n");
   }

   return hexdata;
}


/* EOF */

// vim:ts=3:expandtab

