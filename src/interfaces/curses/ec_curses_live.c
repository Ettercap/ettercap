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

    $Id: ec_curses_live.c,v 1.1 2003/11/30 21:31:59 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>

/* globals */

/* proto */

void curses_sniff_live(void);


/*******************************************/


/* the interface */

void curses_sniff_live(void)
{
   wdg_t *menu;
   struct wdg_menu file[] = { {"Quit",    "Q",  NULL},
                              {"Exit",    "Q", wdg_exit},
                              {NULL, NULL, NULL},
                            };
   struct wdg_menu target[] = { {"Targets", "T",  NULL},
                                {"Current Targets", "", NULL},
                                {"Select TARGET1", "", NULL},
                                {"Select TARGET2", "", NULL},
                                {"-", "", NULL},
                                {"Protocol...", "", NULL},
                                {"Reverse matching", "", NULL},
                                {"-", "", NULL},
                                {"Wipe targets", "", NULL},
                                {NULL, NULL, NULL},
                              };
   struct wdg_menu hosts[] = { {"Hosts", "H",  NULL},
                               {"Host list", "", NULL},
                               {"-", "", NULL},
                               {"Load from file...", "", NULL},
                               {"Save to file...", "", NULL},
                               {NULL, NULL, NULL},
                             };
   struct wdg_menu view[] = { {"View",    "V",  NULL},
                              {"Profiles",    "", NULL},
                              {"Connections", "", NULL},
                              {"-", "", NULL},
                              {"Resolve IP addresses", "", NULL},
                              {"-", "", NULL},
                              {"Statistics",  "",  NULL},
                              {NULL, NULL, NULL},
                            };
   struct wdg_menu mitm[] = { {"Mitm", "M", NULL},
                              {"Arp poisoning", "", NULL},
                              {"Icmp redirect", "", NULL},
                              {"Port stealing", "", NULL},
                              {"Dhcp spoofing", "", NULL},
                              {NULL, NULL, NULL},
                            };
   struct wdg_menu filter[] = { {"Filters", "F", NULL},
                                {"Load a filter...", "", NULL},
                                {"Stop filtering", "", NULL},
                                {NULL, NULL, NULL},
                              };
   struct wdg_menu plugin[] = { {"Plugins", "P", NULL},
                                {"Start a plugin", "", NULL},
                                {"Stop a plugin", "", NULL},
                                {NULL, NULL, NULL},
                              };
   
   DEBUG_MSG("curses_sniff_offline");

   wdg_create_object(&menu, WDG_MENU, WDG_OBJ_WANT_FOCUS | WDG_OBJ_ROOT_OBJECT);

   wdg_set_title(menu, GBL_VERSION, WDG_ALIGN_RIGHT);
   wdg_set_color(menu, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(menu, WDG_COLOR_WINDOW, EC_COLOR_MENU);
   wdg_set_color(menu, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(menu, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_menu_add(menu, file);
   wdg_menu_add(menu, target);
   wdg_menu_add(menu, hosts);
   wdg_menu_add(menu, view);
   wdg_menu_add(menu, mitm);
   wdg_menu_add(menu, filter);
   wdg_menu_add(menu, plugin);
   wdg_draw_object(menu);
   
   /* repaint the whole screen */
   wdg_redraw_all();

   /* add the message flush callback */
   wdg_add_idle_callback(curses_flush_msg);

   /* 
    * give the control to the event dispatcher
    * with the emergency exit key 'Q'
    */
   wdg_events_handler('Q');

   wdg_destroy_object(&menu);
}


/* EOF */

// vim:ts=3:expandtab

