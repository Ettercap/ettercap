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

    $Id: ec_curses_plugins.c,v 1.3 2003/12/25 17:19:57 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>
#include <ec_plugins.h>

/* proto */

static void curses_plugin_mgmt(void);
static void curses_plugin_load(void);
static void curses_load_plugin(char *path, char *file);
static void curses_wdg_plugin(char active, struct plugin_ops *ops);
static void curses_plug_destroy(void);

/* globals */

wdg_t *wdg_plugin;

struct wdg_menu menu_plugins[] = { {"Plugins",              "P", NULL},
                                   {"Manage the plugins...", "", curses_plugin_mgmt},
                                   {"Load a plugin...",      "", curses_plugin_load},
                                   {NULL, NULL, NULL},
                                 };

/*******************************************/

/*
 * display the file open dialog
 */
static void curses_plugin_load(void)
{
   wdg_t *fop;
   
   DEBUG_MSG("curses_plugin_load");
   
   wdg_create_object(&fop, WDG_FILE, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   
   wdg_set_title(fop, "Select a plugin...", WDG_ALIGN_LEFT);
   wdg_set_color(fop, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(fop, WDG_COLOR_WINDOW, EC_COLOR_MENU);
   wdg_set_color(fop, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(fop, WDG_COLOR_TITLE, EC_COLOR_TITLE);

   wdg_file_set_callback(fop, curses_load_plugin);
   
   wdg_draw_object(fop);
   
   wdg_set_focus(fop);
}

static void curses_load_plugin(char *path, char *file)
{
   int ret;

   DEBUG_MSG("curses_load_plugin %s/%s", path, file);

   /* load the plugin */
   ret = plugin_load_single(path, file);

   /* check the return code */
   switch (ret) {
      case ESUCCESS:
         curses_message("Plugin loaded successfully");
      case -EDUPLICATE:
         ui_error("plugin %s already loaded...", file);
         break;
      case -EVERSION:
         ui_error("plugin %s was compiled for a different ettercap version...", file);
         break;
      case -EINVALID:
      default:
         ui_error("Cannot load the plugin...\nthe file may be an invalid plugin\nor you don't have the permission to open it");
         break;
   }
}

/*
 * plugin management
 */
static void curses_plugin_mgmt(void)
{
   int res;
   
   DEBUG_MSG("curses_plugin_mgmt");
   
   /* if the object already exist, set the focus to it */
   if (wdg_plugin) {
      wdg_set_focus(wdg_plugin);
      return;
   }
   
   wdg_create_object(&wdg_plugin, WDG_LIST, WDG_OBJ_WANT_FOCUS);
   
   wdg_set_size(wdg_plugin, 1, 2, -1, SYSMSG_WIN_SIZE - 1);
   wdg_set_title(wdg_plugin, "Select a plugin...", WDG_ALIGN_LEFT);
   wdg_set_color(wdg_plugin, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(wdg_plugin, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(wdg_plugin, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(wdg_plugin, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(wdg_plugin, WDG_COLOR_TITLE, EC_COLOR_TITLE);

   /* go thru the list of plugins */
   res = plugin_list_print(PLP_MIN, PLP_MAX, &curses_wdg_plugin);
   if (res == -ENOTFOUND) 
      wdg_list_add(wdg_plugin, "No plugin found !", NULL);
   
   /* add the destroy callback */
   wdg_add_destroy_key(wdg_plugin, CTRL('Q'), curses_plug_destroy);
   
   wdg_draw_object(wdg_plugin);
   
   wdg_set_focus(wdg_plugin);
}

static void curses_plug_destroy(void)
{
   wdg_plugin = NULL;
}

/*
 * callback function for displaying the plugin list 
 */
static void curses_wdg_plugin(char active, struct plugin_ops *ops)
{
   char tmp[80];

   sprintf(tmp, "[%d] %15s %4s  %s", active, ops->name, ops->version, ops->info);  
  
   wdg_list_add(wdg_plugin, tmp, ops->name);
   
}



/* EOF */

// vim:ts=3:expandtab

