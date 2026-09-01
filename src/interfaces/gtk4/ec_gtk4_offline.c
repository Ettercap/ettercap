/*
    ettercap -- GTK4 GUI

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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <ec.h>
#include <ec_gtk4.h>

/*******************************************/

/*
 * Entry point for offline (pcap replay) sniffing.
 *
 * As with gtkui_sniff_live(), the menu construction this used to trigger
 * is now gtkui_create_menu()'s job.
 */
void gtkui_sniff_offline(void)
{
   DEBUG_MSG("gtk_sniff_offline");
}

/* EOF */

// vim:ts=3:expandtab
