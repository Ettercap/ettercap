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

    $Id: ec_curses.c,v 1.15 2003/11/10 16:11:19 alor Exp $
*/

#include <ec.h>
#include <wdg.h>

/* globals */

/* proto */

void set_curses_interface(void);
void curses_interface(void);
static void curses_init(void);
static void curses_cleanup(void);
static void curses_msg(const char *msg);
static void curses_error(const char *msg);
static void curses_fatal_error(const char *msg);
static void curses_input(const char *title, char *input, size_t n);
static void curses_progress(char *title, int value, int max);

void msg(void);
void percent(void);

/*******************************************/


void set_curses_interface(void)
{
   struct ui_ops ops;

   /* wipe the struct */
   memset(&ops, 0, sizeof(ops));

   /* register the functions */
   ops.init = &curses_init;
   ops.start = &curses_interface;
   ops.cleanup = &curses_cleanup;
   ops.msg = &curses_msg;
   ops.error = &curses_error;
   ops.fatal_error = &curses_fatal_error;
   ops.input = &curses_input;
   ops.progress = &curses_progress;
   ops.type = UI_CURSES;
   
   ui_register(&ops);
   
}


/*
 * set the terminal as non blocking 
 */
static void curses_init(void)
{
   DEBUG_MSG("curses_init");

   /* init the widgets library */
   wdg_init();

   DEBUG_MSG("curses_init: screen %dx%d colors: %d", (int)current_screen.cols, (int)current_screen.lines,
                                                     (int)(current_screen.flags & WDG_SCR_HAS_COLORS));

   /* initialize the colors */
   wdg_init_color(EC_COLOR, GBL_CONF->colors.fg, GBL_CONF->colors.bg);
   wdg_init_color(EC_COLOR_BORDER, GBL_CONF->colors.border, GBL_CONF->colors.bg);
   wdg_init_color(EC_COLOR_TITLE, GBL_CONF->colors.title, GBL_CONF->colors.bg);
   wdg_init_color(EC_COLOR_FOCUS, GBL_CONF->colors.focus, GBL_CONF->colors.bg);
   wdg_init_color(EC_COLOR_MENU, GBL_CONF->colors.menu_fg, GBL_CONF->colors.menu_bg);
   wdg_init_color(EC_COLOR_WINDOW, GBL_CONF->colors.window_fg, GBL_CONF->colors.window_bg);
   wdg_init_color(EC_COLOR_SELECTION, GBL_CONF->colors.selection_fg, GBL_CONF->colors.selection_bg);
   wdg_init_color(EC_COLOR_ERROR, GBL_CONF->colors.error_fg, GBL_CONF->colors.error_bg);
   wdg_init_color(EC_COLOR_ERROR_BORDER, GBL_CONF->colors.error_border, GBL_CONF->colors.error_bg);
}


/*
 * reset to the previous state
 */
static void curses_cleanup(void)
{
   DEBUG_MSG("curses_cleanup");

   wdg_cleanup();
}


/*
 * print a USER_MSG()
 */
static void curses_msg(const char *msg)
{
}


/*
 * print an error
 */
static void curses_error(const char *msg)
{
}


/*
 * handle a fatal error and exit
 */
static void curses_fatal_error(const char *msg)
{
}


/*
 * handle a fatal error and exit
 */
static void curses_input(const char *title, char *input, size_t n)
{
}


/* 
 * implement the progress bar 
 */
static void curses_progress(char *title, int value, int max)
{
}


/* the interface */

void curses_interface(void)
{
   wdg_t *win1, *win2, *win3, *menu, *dlg;
   struct wdg_menu file[] = { {"File",    "F",  NULL},
                              {"Open...", "",  NULL},
                              {"Close",   "",  NULL},
                              {"-",       "", NULL},
                              {"Exit",    "Q", wdg_exit},
                              {NULL, NULL, NULL},
                            };
   struct wdg_menu view[] = { {"View",    "V",  NULL},
                              {"Item1",   "1", NULL},
                              {"Item2",   "2", NULL},
                              {"Item3",   "3", NULL},
                              {"Item4",   "4", NULL},
                              {"-",       "", NULL},
                              {"Item5",   "",  NULL},
                              {"Item6",   "",  NULL},
                              {NULL, NULL, NULL},
                            };
   struct wdg_menu mitm[] = { {"Mitm", "M", NULL},
                              {"Arp poisoning", "A", NULL},
                              {"Icmp redirect", "I", NULL},
                              {"Port stealing", "P", NULL},
                              {"Dhcp spoofing", "D", NULL},
                              {NULL, NULL, NULL},
                            };
   
   DEBUG_MSG("curses_interface");

   wdg_create_object(&win1, WDG_SCROLL, WDG_OBJ_WANT_FOCUS);
   ON_ERROR(win1, NULL, "Cannot create object");
   
   wdg_set_title(win1, "Scroll Window number 1:", WDG_ALIGN_RIGHT);
   wdg_set_size(win1, 3, 17, -3, -2);
   wdg_set_color(win1, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(win1, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(win1, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(win1, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(win1, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_scroll_set_lines(win1, 500);
   wdg_draw_object(win1);
   wdg_scroll_print(win1, "this is a scrollig window...\n");

   wdg_create_object(&win2, WDG_WINDOW, WDG_OBJ_WANT_FOCUS);
   ON_ERROR(win2, NULL, "Cannot create object");
   
   wdg_set_title(win2, "Window number 2:", WDG_ALIGN_CENTER);
   wdg_set_size(win2, 3, 3, -3, 10);
   wdg_set_color(win2, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(win2, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(win2, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(win2, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(win2, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_draw_object(win2);
   wdg_window_print(win2, 1, 1, "...test string...\n");
   
   wdg_create_object(&win3, WDG_PANEL, WDG_OBJ_WANT_FOCUS);
   ON_ERROR(win3, NULL, "Cannot create object");
   
   wdg_set_title(win3, "Panel number 3:", WDG_ALIGN_LEFT);
   wdg_set_size(win3, 3, 11, -3, 16);
   wdg_set_color(win3, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(win3, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(win3, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(win3, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(win3, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_draw_object(win3);
   wdg_panel_print(win3, 0, 1, "this is a panel, it may overlap other panels...\n");
   
   wdg_create_object(&menu, WDG_MENU, WDG_OBJ_WANT_FOCUS | WDG_OBJ_ROOT_OBJECT);
   ON_ERROR(menu, NULL, "Cannot create object");
   
   wdg_set_title(menu, "menu", WDG_ALIGN_RIGHT);
   wdg_set_color(menu, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(menu, WDG_COLOR_WINDOW, EC_COLOR_MENU);
   wdg_set_color(menu, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(menu, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_menu_add(menu, file);
   wdg_menu_add(menu, view);
   wdg_menu_add(menu, mitm);
   wdg_draw_object(menu);
   
   wdg_create_object(&dlg, WDG_DIALOG, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   ON_ERROR(dlg, NULL, "Cannot create object");
   
   wdg_set_title(dlg, "dialog", WDG_ALIGN_CENTER);
   wdg_set_color(dlg, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_WINDOW, EC_COLOR_ERROR);
   wdg_set_color(dlg, WDG_COLOR_FOCUS, EC_COLOR_ERROR_BORDER);
   wdg_set_color(dlg, WDG_COLOR_TITLE, EC_COLOR_ERROR);
   wdg_dialog_text(dlg, WDG_YES | WDG_NO | WDG_CANCEL, "Do you like the new widget interface ?\nI hope so.");
   wdg_dialog_add_callback(dlg, WDG_YES, msg);
   wdg_dialog_add_callback(dlg, WDG_NO, percent);
   wdg_draw_object(dlg);
   
   wdg_set_focus(dlg);
  
   /* repaint the whole screen */
   wdg_redraw_all();

   /* 
    * give the control to the event dispatcher
    * with the emergency exit key 'Q'
    */
   wdg_events_handler('Q');

   wdg_destroy_object(&win1);
   wdg_destroy_object(&win2);
   wdg_destroy_object(&win3);
   wdg_destroy_object(&menu);
   wdg_destroy_object(&dlg);
}

void msg(void)
{
   wdg_t *dlg;
   
   wdg_create_object(&dlg, WDG_DIALOG, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   ON_ERROR(dlg, NULL, "Cannot create object");
   
   wdg_set_title(dlg, "dialog", WDG_ALIGN_CENTER);
   wdg_set_color(dlg, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_WINDOW, EC_COLOR_ERROR);
   wdg_set_color(dlg, WDG_COLOR_FOCUS, EC_COLOR_ERROR_BORDER);
   wdg_set_color(dlg, WDG_COLOR_TITLE, EC_COLOR_ERROR);
   wdg_dialog_text(dlg, WDG_OK, "Wow... cool.");
   wdg_draw_object(dlg);
   
   wdg_set_focus(dlg);
}

void percent(void)
{
   wdg_t *per;
   int i;
   
   wdg_create_object(&per, WDG_PERCENTAGE, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   ON_ERROR(per, NULL, "Cannot create object");
   
   wdg_set_title(per, "percentage...", WDG_ALIGN_CENTER);
   wdg_set_color(per, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(per, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(per, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(per, WDG_COLOR_TITLE, EC_COLOR_MENU);
   wdg_draw_object(per);
   
   wdg_set_focus(per);

   for (i = 0; i <= 100; i++) {
      wdg_percentage_set(per, i, 100);
      wdg_update_screen();
      usleep(20000);
   }
   
   wdg_destroy_object(&per);

   wdg_redraw_all();
}

/* EOF */

// vim:ts=3:expandtab

