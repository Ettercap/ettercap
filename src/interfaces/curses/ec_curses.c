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

    $Id: ec_curses.c,v 1.10 2003/10/30 20:55:01 alor Exp $
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

   DEBUG_MSG("curses_init: screen %ux%u colors: %u", current_screen.cols, current_screen.lines,
                                                     (current_screen.flags & WDG_SCR_HAS_COLORS));

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
   wdg_t *win1, *win2, *win3;
   
   DEBUG_MSG("curses_interface");

   wdg_create_object(&win1, WDG_SCROLL, WDG_OBJ_WANT_FOCUS);
   ON_ERROR(win1, NULL, "Cannot create object");
   
   wdg_set_title(win1, "Scroll Window number 1:", WDG_ALIGN_RIGHT);
   wdg_set_size(win1, 3, 17, -3, -2);
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
   wdg_set_color(win3, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(win3, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(win3, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(win3, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_draw_object(win3);
   wdg_panel_print(win3, 0, 1, "this is a panel, it may overlap other panels...\n");
   
   wdg_set_focus(win1);
   
   /* 
    * give the control to the event dispatcher
    * with the emergency exit key 'Q'
    */
   wdg_events_handler('Q');

   wdg_destroy_object(&win1);
   wdg_destroy_object(&win2);
   wdg_destroy_object(&win3);
}


/* EOF */

// vim:ts=3:expandtab

