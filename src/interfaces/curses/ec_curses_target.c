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

    $Id: ec_curses_target.c,v 1.1 2003/12/09 22:32:54 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>

/* globals */

struct wdg_menu menu_target[] = { {"Targets",         "T", NULL},
                                  {"Current Targets",  "", NULL},
                                  {"Select TARGET1",   "", NULL},
                                  {"Select TARGET2",   "", NULL},
                                  {"-",                "", NULL},
                                  {"Protocol...",      "", NULL},
                                  {"Reverse matching", "", NULL},
                                  {"-",                "", NULL},
                                  {"Wipe targets",     "", NULL},
                                  {NULL, NULL, NULL},
                                };

/* proto */


/*******************************************/




/* EOF */

// vim:ts=3:expandtab

