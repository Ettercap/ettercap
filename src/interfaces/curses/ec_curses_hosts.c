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

    $Id: ec_curses_hosts.c,v 1.2 2003/12/14 20:57:28 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>
#include <ec_scan.h>

/* proto */

static void curses_scan(void);
static void curses_load_hosts(void);
static void load_hosts(char *path, char *file);
static void curses_save_hosts(void);
static void save_hosts(void);

/* globals */

struct wdg_menu menu_hosts[] = { {"Hosts",            "H", NULL},
                                 {"Host list",         "", NULL},
                                 {"-",                 "", NULL},
                                 {"Scan for hosts",    "", curses_scan},
                                 {"Load from file...", "", curses_load_hosts},
                                 {"Save to file...",   "", curses_save_hosts},
                                 {NULL, NULL, NULL},
                               };

/*******************************************/

/*
 * scan the lan for hosts 
 */
static void curses_scan(void)
{
   /* wipe the current list */
   del_hosts_list();

   /* 
    * no target defined... 
    * force a full scan
    */
   if (GBL_TARGET1->all_ip && GBL_TARGET2->all_ip &&
      !GBL_TARGET1->scan_all && !GBL_TARGET2->scan_all) {
      GBL_TARGET1->scan_all = 1;
      GBL_TARGET2->scan_all = 1;
   }
   
   /* perform a new scan */
   build_hosts_list();
}

/*
 * display the file open dialog
 */
static void curses_load_hosts(void)
{
   wdg_t *fop;
   
   DEBUG_MSG("curses_load_hosts");
   
   wdg_create_object(&fop, WDG_FILE, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   
   wdg_set_title(fop, "Select an hosts file...", WDG_ALIGN_LEFT);
   wdg_set_color(fop, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(fop, WDG_COLOR_WINDOW, EC_COLOR_MENU);
   wdg_set_color(fop, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(fop, WDG_COLOR_TITLE, EC_COLOR_TITLE);

   wdg_file_set_callback(fop, load_hosts);
   
   wdg_draw_object(fop);
   
   wdg_set_focus(fop);
}

static void load_hosts(char *path, char *file)
{
   char *tmp;
   
   DEBUG_MSG("load_hosts %s/%s", path, file);
   
   SAFE_CALLOC(tmp, strlen(path)+strlen(file)+2, sizeof(char));

   sprintf(tmp, "%s/%s", path, file);

   /* wipe the current list */
   del_hosts_list();

   /* load the hosts list */
   scan_load_hosts(tmp);
   
   SAFE_FREE(tmp);
}

/*
 * display the write file menu
 */
static void curses_save_hosts(void)
{
#define FILE_LEN  40
   
   DEBUG_MSG("curses_save_hosts");

   SAFE_FREE(GBL_OPTIONS->hostsfile);
   SAFE_CALLOC(GBL_OPTIONS->hostsfile, FILE_LEN, sizeof(char));
   
   curses_input_call("Output file :", GBL_OPTIONS->hostsfile, FILE_LEN, save_hosts);
}

static void save_hosts(void)
{
   FILE *f;
   
   /* check if the file is writeable */
   f = fopen(GBL_OPTIONS->hostsfile, "w");
   if (f == NULL) {
      ui_error("Cannot write %s", GBL_OPTIONS->hostsfile);
      SAFE_FREE(GBL_OPTIONS->hostsfile);
      return;
   }
 
   /* if ok, delete it */
   fclose(f);
   unlink(GBL_OPTIONS->hostsfile);
   
   GBL_OPTIONS->save_hosts = 1;
}

/* EOF */

// vim:ts=3:expandtab

