/*
    WDG -- window widget

    Copyright (C) ALoR

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

    $Id: wdg_window.c,v 1.2 2003/10/25 11:21:53 alor Exp $
*/

#include <wdg.h>

#include <ncurses.h>

/* GLOBALS */

struct wdg_window {
   WINDOW *win;
   WINDOW *sub;
};

/* PROTOS */

void wdg_create_window(struct wdg_object *wo);

static int wdg_window_destroy(struct wdg_object *wo);
static int wdg_window_resize(struct wdg_object *wo);
static int wdg_window_redraw(struct wdg_object *wo);
static int wdg_window_get_focus(struct wdg_object *wo);
static int wdg_window_lost_focus(struct wdg_object *wo);
static int wdg_window_get_msg(struct wdg_object *wo, int key);

/*******************************************/

void wdg_create_window(struct wdg_object *wo)
{
   /* set the callbacks */
   wo->destroy = wdg_window_destroy;
   wo->resize = wdg_window_resize;
   wo->redraw = wdg_window_redraw;
   wo->get_focus = wdg_window_get_focus;
   wo->lost_focus = wdg_window_lost_focus;
   wo->get_msg = wdg_window_get_msg;

   WDG_SAFE_CALLOC(wo->extend, 1, sizeof(struct wdg_window));
}

static int wdg_window_destroy(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_window, ww);

   delwin(ww->sub);
   delwin(ww->win);
   
   WDG_SAFE_FREE(wo->extend);
   
   return WDG_ESUCCESS;
}

static int wdg_window_resize(struct wdg_object *wo)
{
   wdg_window_redraw(wo);

   return WDG_ESUCCESS;
}

static int wdg_window_redraw(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_window, ww);
   size_t c = wdg_get_ncols(wo);
   size_t l = wdg_get_nlines(wo);
   size_t x = wdg_get_begin_x(wo);
   size_t y = wdg_get_begin_y(wo);
 
   /* the window already exist */
   if (ww->win) {
      /* erase the border */
      werase(ww->win);
      touchwin(ww->win);
      wrefresh(ww->win);
      
      /* resize the window and draw the new border */
      mvwin(ww->win, y, x);
      wresize(ww->win, l, c);
      box(ww->win, 0, 0);
      
      /* resize the actual window and touch it */
      mvwin(ww->sub, y + 1, x + 1);
      wresize(ww->sub, l - 2, c - 2);
      touchwin(ww->sub);

   /* the first time we have to allocate the window */
   } else {

      /* create the outher window */
      if ((ww->win = newwin(l, c, y, x)) == NULL)
         return -WDG_EFATAL;

      /* draw the box */
      box(ww->win, 0, 0);

      /* create the inner (actual) window */
      if ((ww->sub = newwin(l - 2, c - 2, y + 1, x + 1)) == NULL)
         return -WDG_EFATAL;
      
      /* initialize the pointer */
      wmove(ww->sub, 0, 0);

      scrollok(ww->sub, TRUE);

   }
   /* refresh the window */   
   wrefresh(ww->win);
   wrefresh(ww->sub);
   
   wo->flags |= WDG_OBJ_VISIBLE;

   return WDG_ESUCCESS;
}

static int wdg_window_get_focus(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_window, ww);
   wprintw(ww->sub, "WDG WIN: get_focus\n"); 
   wrefresh(ww->sub);
   return WDG_ESUCCESS;
}

static int wdg_window_lost_focus(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_window, ww);
   wprintw(ww->sub, "WDG WIN: lost_focus\n");
   wrefresh(ww->sub);
   return WDG_ESUCCESS;
}

static int wdg_window_get_msg(struct wdg_object *wo, int key)
{
   WDG_WO_EXT(struct wdg_window, ww);
   wprintw(ww->sub, "WDG WIN: char %d\n", key);
   wrefresh(ww->sub);
   return WDG_ESUCCESS;
}


/* EOF */

// vim:ts=3:expandtab

