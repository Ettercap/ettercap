/*
    WDG -- errors handling module

    Copyright (C) ALoR

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

    $Id: wdg_error.c,v 1.1 2003/10/22 20:36:25 alor Exp $
*/

#include <wdg.h>

#include <stdarg.h>
#include <string.h>
#include <errno.h>

#define ERROR_MSG_LEN 200

/* PROTOS */

void wdg_bug(char *file, char *function, int line, char *message);
void wdg_error_msg(char *file, char *function, int line, char *message, ...);

/*******************************************/

/*
 * raise an error
 */
void wdg_error_msg(char *file, char *function, int line, char *message, ...)
{
   va_list ap;
   char errmsg[ERROR_MSG_LEN + 1];    /* should be enough */

   va_start(ap, message);
   vsnprintf(errmsg, ERROR_MSG_LEN, message, ap);
   va_end(ap);

   /* close the interface and display the error */
   wdg_cleanup();
  
   fprintf(stderr, "WDG ERROR : %d, %s\n[%s:%s:%d]\n\n %s \n\n",  errno, strerror(errno),
                   file, function, line, errmsg );

   exit(-errno);
}

/*
 * used in sanity check
 * it represent a BUG in the software
 */
void wdg_bug(char *file, char *function, int line, char *message)
{
   /* close the interface and display the error */
   wdg_cleanup();
  
   fprintf(stderr, "\n\nWDG BUG at [%s:%s:%d]\n\n %s \n\n", file, function, line, message );

   exit(-666);
}

/* EOF */

// vim:ts=3:expandtab

