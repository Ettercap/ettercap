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

    $Id: ec_curses.c,v 1.7 2003/10/25 11:21:53 alor Exp $
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

   DEBUG_MSG("curses_init: screen %dx%d colors: %d", current_screen.cols, current_screen.lines,
                                                     (current_screen.flags & WDG_SCR_HAS_COLORS));
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

   wdg_create_object(&win1, WDG_WINDOW, WDG_OBJ_WANT_FOCUS);
   ON_ERROR(win1, NULL, "Cannot create object");
   
   //wdg_window_set_title(wo, "Title: ");
   //wdg_resize_object(win1, 3, -15, -3, -2);
   wdg_resize_object(win1, 3, -15, -3, -2);
   wdg_draw_object(win1);

   wdg_create_object(&win2, WDG_WINDOW, WDG_OBJ_WANT_FOCUS);
   ON_ERROR(win2, NULL, "Cannot create object");
   
   wdg_resize_object(win2, 3, 3, -3, 10);
   wdg_draw_object(win2);
   
   wdg_create_object(&win3, WDG_WINDOW, WDG_OBJ_WANT_FOCUS);
   ON_ERROR(win3, NULL, "Cannot create object");
   
   wdg_resize_object(win3, 3, 11, -3, 17);
   wdg_draw_object(win3);
   
   wdg_set_focus(win3);
   
   /* 
    * give the control to the event dispatcher
    * with the emergency exit key 'Q'
    */
   wdg_events_handler('Q');

   wdg_destroy_object(&win1);
   wdg_destroy_object(&win2);
}


/* EOF */

// vim:ts=3:expandtab

