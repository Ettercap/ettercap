/*
    WDG -- menu widget

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

    $Id: wdg_menu.c,v 1.2 2003/11/02 22:08:44 alor Exp $
*/

#include <wdg.h>

#include <ncurses.h>
#include <menu.h>

#include <stdarg.h>

/* GLOBALS */

#define WDG_MENU_LEFT_PAD  1

struct wdg_menu_unit {
   char active;
   char *title;
   size_t nitems;
   MENU *m;
   WINDOW *win;
   ITEM **items;
   TAILQ_ENTRY(wdg_menu_unit) next;
};

struct wdg_menu_unit *focus_unit;

struct wdg_menu_handle {
   WINDOW *menu;
   TAILQ_HEAD(menu_head, wdg_menu_unit) menu_list;
};

/* PROTOS */

void wdg_create_menu(struct wdg_object *wo);

static int wdg_menu_destroy(struct wdg_object *wo);
static int wdg_menu_resize(struct wdg_object *wo);
static int wdg_menu_redraw(struct wdg_object *wo);
static int wdg_menu_get_focus(struct wdg_object *wo);
static int wdg_menu_lost_focus(struct wdg_object *wo);
static int wdg_menu_get_msg(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse);

static void wdg_menu_titles(struct wdg_object *wo);
static void wdg_menu_move(struct wdg_object *wo, int key);
static int wdg_menu_mouse_move(struct wdg_object *wo, struct wdg_mouse_event *mouse);
static void wdg_menu_open(struct wdg_object *wo);
static void wdg_menu_close(struct wdg_object *wo);

static int wdg_menu_virtualize(int key);
static int wdg_menu_driver(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse);

void wdg_menu_add(struct wdg_object *wo, struct wdg_menu *menu);

/*******************************************/

/* 
 * called to create the menu
 */
void wdg_create_menu(struct wdg_object *wo)
{
   /* set the callbacks */
   wo->destroy = wdg_menu_destroy;
   wo->resize = wdg_menu_resize;
   wo->redraw = wdg_menu_redraw;
   wo->get_focus = wdg_menu_get_focus;
   wo->lost_focus = wdg_menu_lost_focus;
   wo->get_msg = wdg_menu_get_msg;

   WDG_SAFE_CALLOC(wo->extend, 1, sizeof(struct wdg_menu_handle));
}

/* 
 * called to destroy the menu
 */
static int wdg_menu_destroy(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_menu_handle, ww);

   /* erase the window */
   wbkgd(ww->menu, COLOR_PAIR(wo->screen_color));
   werase(ww->menu);
   wnoutrefresh(ww->menu);
   
   /* dealloc the structures */
   delwin(ww->menu);

   WDG_SAFE_FREE(wo->extend);

   return WDG_ESUCCESS;
}

/* 
 * called to resize the menu
 */
static int wdg_menu_resize(struct wdg_object *wo)
{
   wdg_menu_redraw(wo);

   return WDG_ESUCCESS;
}

/* 
 * called to redraw the menu
 */
static int wdg_menu_redraw(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_menu_handle, ww);
 
   /* the window already exist */
   if (ww->menu) {
      /* erase the border */
      wbkgd(ww->menu, COLOR_PAIR(wo->screen_color));
      werase(ww->menu);
      touchwin(ww->menu);
      wnoutrefresh(ww->menu);
     
      /* set the menu color */
      wbkgd(ww->menu, COLOR_PAIR(wo->window_color));
     
      /* resize the menu */
      wresize(ww->menu, 1, current_screen.cols);
      
      /* redraw the menu */
      wdg_menu_titles(wo);
      touchwin(ww->menu);

   /* the first time we have to allocate the window */
   } else {

      /* create the menu window (fixed dimensions) */
      if ((ww->menu = newwin(1, current_screen.cols, 0, 0)) == NULL)
         return -WDG_EFATAL;

      /* draw the titles */
      wdg_menu_titles(wo);

      /* set the window color */
      wbkgd(ww->menu, COLOR_PAIR(wo->window_color));
      redrawwin(ww->menu);

      /* no scrolling ro menu */
      scrollok(ww->menu, FALSE);

   }
   
   /* refresh the window */
   touchwin(ww->menu);
   wnoutrefresh(ww->menu);
   
   wo->flags |= WDG_OBJ_VISIBLE;

   return WDG_ESUCCESS;
}

/* 
 * called when the menu gets the focus
 */
static int wdg_menu_get_focus(struct wdg_object *wo)
{
   /* set the flag */
   wo->flags |= WDG_OBJ_FOCUSED;

   /* redraw the window */
   wdg_menu_redraw(wo);
   
   return WDG_ESUCCESS;
}

/* 
 * called when the menu looses the focus
 */
static int wdg_menu_lost_focus(struct wdg_object *wo)
{
   /* set the flag */
   wo->flags &= ~WDG_OBJ_FOCUSED;
  
   /* close any active menu */
   wdg_menu_close(wo);
   
   /* redraw the window */
   wdg_menu_redraw(wo);
   
   return WDG_ESUCCESS;
}

/* 
 * called by the messages dispatcher when the menu is focused
 */
static int wdg_menu_get_msg(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse)
{
   WDG_WO_EXT(struct wdg_menu_handle, ww);

   /* handle the message */
   switch (key) {
         
      case KEY_MOUSE:
         /* is the mouse event within our edges ? */
         if (wenclose(ww->menu, mouse->y, mouse->x)) {
            wdg_set_focus(wo);
            /* close any previously opened menu unit */
            wdg_menu_close(wo);
            /* if the mouse click was over a menu unit title */
            if (wdg_menu_mouse_move(wo, mouse) == WDG_ESUCCESS)
               wdg_menu_open(wo);
            /* redraw the menu */
            wdg_menu_redraw(wo);
         } else if (focus_unit->active && wenclose(focus_unit->win, mouse->y, mouse->x)) {
            wdg_menu_driver(wo, key, mouse);
         } else 
            return -WDG_ENOTHANDLED;
         break;

      case KEY_LEFT:
      case KEY_RIGHT:
         /* move only if focused */
         if (wo->flags & WDG_OBJ_FOCUSED) {
            /* if the menu is open, move and open the neighbor */
            if (focus_unit->active) {
               wdg_menu_close(wo);
               wdg_menu_move(wo, key);
               wdg_menu_open(wo);
            } else
               wdg_menu_move(wo, key);
            
            wdg_menu_redraw(wo);
         } else 
            return -WDG_ENOTHANDLED;
         break;
         
      case KEY_RETURN:
      case KEY_DOWN:
         /* move only if focused */
         if (wo->flags & WDG_OBJ_FOCUSED) {
            /* if the menu is open */
            if (focus_unit->active)
               wdg_menu_driver(wo, key, mouse);
            else
               wdg_menu_open(wo);
            /* repaint */
            wdg_menu_redraw(wo);
         } else
            return -WDG_ENOTHANDLED;
         break;
         
      case KEY_UP:
         /* move only if focused */
         if (wo->flags & WDG_OBJ_FOCUSED) {
            /* if the menu is open */
            if (focus_unit->active)
               if (wdg_menu_driver(wo, key, mouse) != WDG_ESUCCESS)
                  wdg_menu_close(wo);
            /* repaint */
            wdg_menu_redraw(wo);
         }  else 
            return -WDG_ENOTHANDLED;
         break;

      /* message not handled */
      default:
         return -WDG_ENOTHANDLED;
         break;
   }
  
   return WDG_ESUCCESS;
}

/*
 * draw the menu titles
 */
static void wdg_menu_titles(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_menu_handle, ww);
   struct wdg_menu_unit *mu;
      
   /* there is a title: print it */
   if (wo->title) {
      /* the only alignment is RIGHT */
      wmove(ww->menu, 0, current_screen.cols - strlen(wo->title) - 1);
      wbkgdset(ww->menu, COLOR_PAIR(wo->title_color));
      wattron(ww->menu, A_BOLD);
      wprintw(ww->menu, wo->title);
      wattroff(ww->menu, A_BOLD);
      wbkgdset(ww->menu, COLOR_PAIR(wo->window_color));
   }
  
   /* move to the left */
   wmove(ww->menu, 0, WDG_MENU_LEFT_PAD);
   
   /* print the menu unit list */
   TAILQ_FOREACH(mu, &ww->menu_list, next) {
      /* the menu is focused and the unit has the control */
      if ((wo->flags & WDG_OBJ_FOCUSED) && focus_unit == mu) {
         wattron(ww->menu, A_REVERSE);
         wprintw(ww->menu, "%s", mu->title);
         wattroff(ww->menu, A_REVERSE);
      } else
         wprintw(ww->menu, "%s", mu->title);

      /* separator between two unit title */
      wprintw(ww->menu, "  ");
   }
   
}

/*
 * add a menu to the handle
 */
void wdg_menu_add(struct wdg_object *wo, struct wdg_menu *menu)
{
   WDG_WO_EXT(struct wdg_menu_handle, ww);
   struct wdg_menu_unit *mu;
   int i = 0;

   WDG_SAFE_CALLOC(mu, 1, sizeof(struct wdg_menu_unit));
   
   mu->title = strdup(menu[i].name);
   
   while (menu[++i].name != NULL) {
   
      /* count the items added */
      mu->nitems++;

      WDG_SAFE_REALLOC(mu->items, mu->nitems * sizeof(ITEM *));
      
      /* create the item */
      mu->items[mu->nitems - 1] = new_item(menu[i].name, menu[i].shortcut);

      /* this is a separator */
      if (!strcmp(menu[i].name, "-"))
         item_opts_off(mu->items[mu->nitems - 1], O_SELECTABLE);
      /* set the callback */
      else
         set_item_userptr(mu->items[mu->nitems - 1], menu[i].callback);
   }
   
   /* add the null termination to the array */
   WDG_SAFE_REALLOC(mu->items, (mu->nitems + 1) * sizeof(ITEM *));
   mu->items[mu->nitems] = NULL;

   /* add the menu to the list */
   if (TAILQ_FIRST(&ww->menu_list) == TAILQ_END(&ww->menu_list)) {
      TAILQ_INSERT_HEAD(&ww->menu_list, mu, next);
      /* set the focus on the first unit */
      focus_unit = mu;
   } else
      TAILQ_INSERT_TAIL(&ww->menu_list, mu, next);
}

/*
 * move the focus thru menu units 
 */
static void wdg_menu_move(struct wdg_object *wo, int key)
{
   WDG_WO_EXT(struct wdg_menu_handle, ww);
   
   switch(key) {
      case KEY_RIGHT:
         if (focus_unit != TAILQ_LAST(&ww->menu_list, menu_head))
            focus_unit = TAILQ_NEXT(focus_unit, next);
         break;
         
      case KEY_LEFT:
         if (focus_unit != TAILQ_FIRST(&ww->menu_list))
            focus_unit = TAILQ_PREV(focus_unit, menu_head, next);
         break;
   }
}

/*
 * select the focus with a mouse event
 */
static int wdg_menu_mouse_move(struct wdg_object *wo, struct wdg_mouse_event *mouse)
{
   WDG_WO_EXT(struct wdg_menu_handle, ww);
   struct wdg_menu_unit *mu;
   size_t x = WDG_MENU_LEFT_PAD;
  
   TAILQ_FOREACH(mu, &ww->menu_list, next) {
      /* if the mouse is over a title */
      if (mouse->x >= x && mouse->x < x + strlen(mu->title) ) {
         focus_unit = mu;
         return WDG_ESUCCESS;
      }
      /* move the pointer */   
      x += strlen(mu->title) + 2;
   }    
   
   return -WDG_ENOTHANDLED;
}

/*
 * stransform keys into menu commands 
 */
static int wdg_menu_virtualize(int key)
{
   switch (key) {
      case KEY_RETURN:
      case KEY_EXIT:
         return (MAX_COMMAND + 1);
      case KEY_NPAGE:
         return (REQ_SCR_UPAGE);
      case KEY_PPAGE:
         return (REQ_SCR_DPAGE);
      case KEY_DOWN:
         return (REQ_NEXT_ITEM);
      case KEY_UP:
         return (REQ_PREV_ITEM);
      default:
         if (key != KEY_MOUSE)
            beep();
         return (key);
   }
}

/*
 * sends command to the active menu 
 */
static int wdg_menu_driver(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse)
{
   int c;
   void (*func)(void);
   
   c = menu_driver(focus_unit->m, wdg_menu_virtualize(key) );
   
   move(1, 35); printw("%02d ", c);

   /* skip non selectable items */
   if ( !(item_opts(current_item(focus_unit->m)) & O_SELECTABLE) )
      c = menu_driver(focus_unit->m, wdg_menu_virtualize(key) );

   if (c == E_UNKNOWN_COMMAND) {
      /* the item is not selectable (probably selected with mouse */
      if ( !(item_opts(current_item(focus_unit->m)) & O_SELECTABLE) )
         return WDG_ESUCCESS;
         
      /* XXX - handle the menu selection */
      func = item_userptr(current_item(focus_unit->m));
      
      printw("%s %p", item_name(current_item(focus_unit->m)), func);

      /* close the menu */
      wdg_menu_close(wo);

      /* execute the callback */
      if (func != NULL)
         func();
   }

   /* tring to go outside edges */
   if (c == E_REQUEST_DENIED)
      return -WDG_ENOTHANDLED;

   wnoutrefresh(focus_unit->win);
      
   return WDG_ESUCCESS;
}

/*
 * open a menu unit
 */
static void wdg_menu_open(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_menu_handle, ww);
   struct wdg_menu_unit *mu;
   size_t x = WDG_MENU_LEFT_PAD;
   int mrows, mcols;
  
   WDG_BUG_IF(focus_unit == NULL);
   
   /* already displayed */
   if (focus_unit->active == 1)
      return;

   /* calculate the x placement of the menu */
   TAILQ_FOREACH(mu, &ww->menu_list, next) {
      /* search the curren focused unit */
      if (!strcmp(mu->title, focus_unit->title))
         break;
      /* move the pointer */   
      x += strlen(mu->title) + 2;
   }
   
   /* create the menu */
   focus_unit->m = new_menu(focus_unit->items);

   /* set the dimensions */
   set_menu_format(focus_unit->m, focus_unit->nitems, 1);

   /* get the geometry to make a window */
   scale_menu(focus_unit->m, &mrows, &mcols);

   /* create the window for the menu */
   focus_unit->win = newwin(mrows + 2, mcols + 2, 1, x);
   /* set the color */
   wbkgd(focus_unit->win, COLOR_PAIR(wo->window_color));
   keypad(focus_unit->win, TRUE);
   box(focus_unit->win, 0, 0);
  
   /* associate with the menu */
   set_menu_win(focus_unit->m, focus_unit->win);
   
   /* the subwin for the menu */
   set_menu_sub(focus_unit->m, derwin(focus_unit->win, mrows + 1, mcols, 1, 1));

   /* menu attributes */
   set_menu_mark(focus_unit->m, "");
   set_menu_grey(focus_unit->m, COLOR_PAIR(wo->window_color));
   set_menu_back(focus_unit->m, COLOR_PAIR(wo->window_color));
   set_menu_fore(focus_unit->m, COLOR_PAIR(wo->window_color) | A_REVERSE);
   
   /* display the menu */
   post_menu(focus_unit->m);

   /* set the active state */
   focus_unit->active = 1;

   wnoutrefresh(focus_unit->win);
}

/*
 * close a menu unit
 */
static void wdg_menu_close(struct wdg_object *wo)
{
   WDG_BUG_IF(focus_unit == NULL);
   
   /* nothing to clear */
   if (focus_unit->active == 0)
      return;
   
   /* hide the menu */
   unpost_menu(focus_unit->m);
   
   /* set the active state */
   focus_unit->active = 0;

   /* erase the menu */
   wbkgd(focus_unit->win, COLOR_PAIR(wo->screen_color));
   werase(focus_unit->win);
   wnoutrefresh(focus_unit->win);

   /* delete the memory */
   delwin(focus_unit->win);
   free_menu(focus_unit->m);
  
   /* repaint the whole screen since a menu might have overlapped something */
   wdg_redraw_all();
}

/* EOF */

// vim:ts=3:expandtab

