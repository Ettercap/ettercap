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

    $Id: ec_curses_file.c,v 1.1 2003/11/30 21:31:59 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>

/* globals */

/* proto */

void curses_sniff_offline(void);


/*******************************************/


/* the interface */

void curses_sniff_offline(void)
{
   wdg_t *menu;
   struct wdg_menu file[] = { {"Main",    "M",  NULL},
                              {"Exit",    "Q", wdg_exit},
                              {NULL, NULL, NULL},
                            };
   struct wdg_menu view[] = { {"View",    "V",  NULL},
                              {"Item1",   "", NULL},
                              {"Item2",   "", NULL},
                              {"Item3",   "", NULL},
                              {"Item4",   "", NULL},
                              {"-",       "", NULL},
                              {"Item5",   "",  NULL},
                              {"Item6",   "",  NULL},
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
   wdg_menu_add(menu, view);
   wdg_draw_object(menu);
   
   /* repaint the whole screen */
   wdg_redraw_all();

   /* add the message flush callback */
   wdg_add_idle_callback(curses_flush_msg);

   /* start the sniffing method */
   EXECUTE(GBL_SNIFF->start);
      
   /* 
    * give the control to the event dispatcher
    * with the emergency exit key 'Q'
    */
   wdg_events_handler('Q');

   wdg_destroy_object(&menu);
}


/* EOF */

// vim:ts=3:expandtab

