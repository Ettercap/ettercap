/*
    etterlog -- ettercap compatibility module
                here are stored functions needed by ec_* source
                but not linked in etterlog

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

#include <el.h>
#include <stdarg.h>

/* globals */
FILE *debug_file = (void *)1;  /* not NULL to avoid FATAL_ERROR */

/************************************************/
 
/* the void implementation */

void debug_msg(const char *message, ...) 
{
   (void) message;
}

/* fake the UI implementation */
void ui_msg(const char *fmt, ...) 
{ 
   va_list ap;
   /* print the message */ 
   va_start(ap, fmt);
   vfprintf (stderr, fmt, ap);
   va_end(ap);
   fprintf(stderr, "\n");
}

void ui_error(const char *fmt, ...) 
{ 
   va_list ap;
   /* print the message */ 
   va_start(ap, fmt);
   vfprintf (stderr, fmt, ap);
   va_end(ap);
   fprintf(stderr, "\n");
}

void ui_fatal_error(const char *fmt, ...)
{
   va_list ap;
   va_start(ap, fmt);
   vfprintf (stderr, fmt, ap);
   va_end(ap);
   fprintf(stderr, "\n");
   exit(-1);
}

void ui_cleanup(void) { }

/* EOF */

// vim:ts=3:expandtab

