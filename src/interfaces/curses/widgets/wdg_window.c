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

    $Id: wdg_window.c,v 1.1 2003/10/22 20:36:25 alor Exp $
*/

#include <wdg.h>

#include <ncurses.h>

/* GLOBALS */

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
}

static int wdg_window_destroy(struct wdg_object *wo)
{
   return WDG_ESUCCESS;
}

static int wdg_window_resize(struct wdg_object *wo)
{
   return WDG_ESUCCESS;
}

static int wdg_window_redraw(struct wdg_object *wo)
{
   wo->flags |= WDG_OBJ_VISIBLE;

   return WDG_ESUCCESS;
}

static int wdg_window_get_focus(struct wdg_object *wo)
{
   printw("WDG WIN: get_focus\n"); refresh();
   return WDG_ESUCCESS;
}

static int wdg_window_lost_focus(struct wdg_object *wo)
{
   printw("WDG WIN: lost_focus\n"); refresh();
   return WDG_ESUCCESS;
}

static int wdg_window_get_msg(struct wdg_object *wo, int key)
{
   printw("WDG WIN: char %d\n", key); refresh();
   return -WDG_ENOTHANDLED;
}


/* EOF */

// vim:ts=3:expandtab

