/*
    ettercap -- error handling module

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

    $Id: ec_error.c,v 1.6 2003/09/18 22:15:02 alor Exp $
*/

#include <ec.h>
#include <ec_ui.h>

#include <stdarg.h>
#include <errno.h>

#define ERROR_MSG_LEN 200

void error_msg(char *file, char *function, int line, char *message, ...);
void bug(char *file, char *function, int line, char *message);

/*******************************************/

/*
 * raise an error
 */

void error_msg(char *file, char *function, int line, char *message, ...)
{
   va_list ap;
   char errmsg[ERROR_MSG_LEN + 1];    /* should be enough */

   va_start(ap, message);
   vsnprintf(errmsg, ERROR_MSG_LEN, message, ap);
   va_end(ap);

   DEBUG_MSG("ERROR : %d, %s\n[%s:%s:%d] %s \n",  errno, strerror(errno),
                   file, function, line, errmsg );
   
   /* close the interface and display the error */
   ui_cleanup();
  
   fprintf(stderr, "ERROR : %d, %s\n[%s:%s:%d]\n\n %s \n\n",  errno, strerror(errno),
                   file, function, line, errmsg );

   exit(-errno);
}

/*
 * used in sanity check
 * it represent a BUG in the software
 */

void bug(char *file, char *function, int line, char *message)
{
   DEBUG_MSG("BUG : [%s:%s:%d] %s \n", file, function, line, message );
   
   /* close the interface and display the error */
   ui_cleanup();
  
   fprintf(stderr, "\n\nBUG at [%s:%s:%d]\n\n %s \n\n", file, function, line, message );

   exit(-666);
}


/* EOF */

// vim:ts=3:expandtab

