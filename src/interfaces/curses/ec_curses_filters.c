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

    $Id: ec_curses_filters.c,v 1.4 2004/01/03 15:14:14 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>
#include <ec_filter.h>

/* proto */

static void curses_load_filter(void);
static void load_filter(char *path, char *file);
static void curses_stop_filter(void);

/* globals */

struct wdg_menu menu_filters[] = { {"Filters",          'F',       "",    NULL},
                                   {"Load a filter...", CTRL('F'), "C-f", curses_load_filter},
                                   {"Stop filtering",   'f',       "f",   curses_stop_filter},
                                   {NULL, 0, NULL, NULL},
                                 };

/*******************************************/


/*
 * display the file open dialog
 */
static void curses_load_filter(void)
{
   wdg_t *fop;
   
   DEBUG_MSG("curses_load_filter");
   
   wdg_create_object(&fop, WDG_FILE, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   
   wdg_set_title(fop, "Select a precompiled filter file...", WDG_ALIGN_LEFT);
   wdg_set_color(fop, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(fop, WDG_COLOR_WINDOW, EC_COLOR_MENU);
   wdg_set_color(fop, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(fop, WDG_COLOR_TITLE, EC_COLOR_TITLE);

   wdg_file_set_callback(fop, load_filter);
   
   wdg_draw_object(fop);
   
   wdg_set_focus(fop);
}

static void load_filter(char *path, char *file)
{
   char *tmp;
   
   DEBUG_MSG("load_filter %s/%s", path, file);
   
   SAFE_CALLOC(tmp, strlen(path)+strlen(file)+2, sizeof(char));

   sprintf(tmp, "%s/%s", path, file);

   /* 
    * load the filters chain.
    * errors are spawned by the function itself
    */
   filter_load_file(tmp, GBL_FILTERS);
   
   SAFE_FREE(tmp);
}


/*
 * uload the filter chain
 */
static void curses_stop_filter(void)
{
   DEBUG_MSG("curses_stop_filter");

   filter_unload(GBL_FILTERS);
   
   curses_message("Filters were unloaded");
}

/* EOF */

// vim:ts=3:expandtab

