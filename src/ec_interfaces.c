/*
    ettercap -- GUI management

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
#ifdef HAVE_NCURSES
   #include <ec_curses.h>
#endif
#include <ec_daemon.h>
#if defined HAVE_GTK || defined HAVE_GTK3
   #include <ec_gtk.h>
#endif

#include <ec_text.h>

/*******************************************/

void select_daemon_interface(void)
{
   DEBUG_MSG("select_daemon_interface");
   
   set_daemon_interface();
}

void select_text_interface(void)
{
   DEBUG_MSG("select_text_interface");
   
   set_text_interface();
}

void select_curses_interface(void)
{
   DEBUG_MSG("select_curses_interface");
#ifdef HAVE_NCURSES 
   /* check if the stdout is available */
   if (isatty(fileno(stdout)) <= 0)
      FATAL_ERROR("Cannot use Curses if stdout is redirected");
   
   set_curses_interface();
#else
   FATAL_ERROR("Curses support not compiled in %s", EC_GBL_PROGRAM);
#endif
   
}

void select_gtk_interface(void)
{
   DEBUG_MSG("select_gtk_interface");
#if defined HAVE_GTK || defined HAVE_GTK3
   set_gtk_interface();
#else
   FATAL_ERROR("GTK support is not compiled in %s", EC_GBL_PROGRAM);
#endif
}

/* EOF */


// vim:ts=3:expandtab

