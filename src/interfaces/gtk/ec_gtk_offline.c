/*
    ettercap -- GTK+ GUI

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

    $Id: ec_gtk_offline.c,v 1.1 2004/02/27 03:34:33 daten Exp $
*/

#include <ec.h>
#include <ec_gtk.h>

/* globals */

/* proto */

void gui_sniff_offline(void);


/*******************************************/


/* the interface */

void gui_sniff_offline(void)
{
   DEBUG_MSG("gtk_sniff_offline");

   gui_create_menu(0); /* offline menus */
}


/* EOF */

// vim:ts=3:expandtab

