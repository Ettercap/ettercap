/*
    ettercap -- curses GUI

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

    $Id: ec_curses_view.c,v 1.2 2003/12/13 18:41:11 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>

/* proto */

static void toggle_resolve(void);

/* globals */

static char tag_resolve[] = " ";

struct wdg_menu menu_view[] = { {"View",                "V", NULL},
                                {"Profiles",             "", NULL},
                                {"Connections",          "", NULL},
                                {"-",                    "", NULL},
                                {"Resolve IP addresses", tag_resolve, toggle_resolve},
                                {"-",                    "", NULL},
                                {"Statistics",           "", NULL},
                                {NULL, NULL, NULL},
                              };


/*******************************************/


static void toggle_resolve(void)
{
   if (GBL_OPTIONS->resolve) {
      tag_resolve[0] = ' ';
      GBL_OPTIONS->resolve = 0;
   } else {
      tag_resolve[0] = '*';
      GBL_OPTIONS->resolve = 1;
   }
}


/* EOF */

// vim:ts=3:expandtab

