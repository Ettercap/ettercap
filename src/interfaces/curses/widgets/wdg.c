/*
    WDG -- widgets helper for ncurses

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

    $Id: wdg.c,v 1.5 2003/10/22 08:05:43 alor Exp $
*/

#include <wdg.h>

#include <ncurses.h>

/* not defined in curses.h */
#define KEY_TAB   '\t'

/* GLOBALS */

/* informations about the current screen */
struct wdg_scr current_screen;
/* called when idle */
static void (*wdg_idle_callback)(void);
/* the root object (usually the menu) */
static struct wdg_object *wdg_root_obj;
/* the focus list */
struct wdg_obj_list {
   struct wdg_object *wo;
   CIRCLEQ_ENTRY(wdg_obj_list) next;
};
static CIRCLEQ_HEAD(, wdg_obj_list) wdg_focus_list = CIRCLEQ_HEAD_INITIALIZER(wdg_focus_list);
/* the currently focused object */
static struct wdg_obj_list *wdg_focused_obj;

/* PROTO */

void wdg_init(void);
void wdg_cleanup(void);

int wdg_events_handler(int exit_key);
void wdg_set_idle_callback(void (*callback)(void));
static void wdg_dispatch_msg(int key);
static void wdg_switch_focus(void);

int wdg_create_object(struct wdg_object **wo, size_t type, size_t flags);
int wdg_destroy_object(struct wdg_object **wo);

int wdg_resize_object(struct wdg_object *wo, size_t x1, size_t y1, size_t x2, size_t y2);

/*******************************************/

/*
 * init the widgets interface
 */
void wdg_init(void)
{
   /* initialize the curses interface */
   initscr(); 

   /* disable buffering until carriage return */
   cbreak(); 

   /* set the non-blocking timeout (10th of seconds) */
   halfdelay(WDG_INPUT_TIMEOUT);
   
   /* disable echo of typed chars */
   noecho();
  
   /* better compatibility with return key */
   nonl();

   /* don't flush input on break */
   intrflush(stdscr, FALSE);
  
   /* enable function and arrow keys */ 
   keypad(stdscr, TRUE);
  
   /* activate colors if available */
   if (has_colors()) {
      current_screen.colors = TRUE;
      start_color();
   }

   /* hide the cursor */
   curs_set(FALSE);

   /* remember the current screen size */
   current_screen.lines = LINES;
   current_screen.cols = COLS;

   /* the wdg is initialized */
   current_screen.initialized = TRUE;

   /* clear the screen */
   clear();

   /* sync the virtual and the physical screen */
   refresh();
}


/*
 * cleanup the widgets interface
 */
void wdg_cleanup(void)
{
   /* can only cleanup if it was initialized */
   if (current_screen.initialized == FALSE)
      return;
   
   /* show the cursor */
   curs_set(TRUE);

   /* clear the screen */
   clear();

   /* do the refresh */
   refresh();

   /* end the curses interface */
   endwin();

   /* wdg is not initialized */
   current_screen.initialized = FALSE;
}


/*
 * this function handles all the inputed keys 
 * from the user and dispatches them to the
 * wdg objects
 */
int wdg_events_handler(int exit_key)
{
   int key;
   
   /* infinite loop */
   WDG_LOOP {

      /* get the input from user */
      key = wgetch(stdscr);

      switch (key) {
            
         case KEY_TAB:
            /* switch focus between objects */
            wdg_switch_focus();
            break;
            
         case ERR:
            /* 
             * non-blockin input reached the timeout:
             * call the idle function if present, else
             * sleep to not eat up all the cpu
             */
            if (wdg_idle_callback != NULL)
               wdg_idle_callback();
            else
               usleep(WDG_INPUT_TIMEOUT * 1000);
            break;
            
         default:
            /* emergency exit key */
            if (key == exit_key)
               return WDG_ESUCCESS;
            
            /* dispatch the user input */
            wdg_dispatch_msg(key);
            break;
      }
   }
   
   /* NOT REACHED */
   
   return WDG_ESUCCESS;
}

/*
 * set the function to be called when idle 
 */
void wdg_set_idle_callback(void (*callback)(void))
{
   /* set the global pointer */
   wdg_idle_callback = callback;
}

/*
 * dispatch the user input to the list of objects.
 * first dispatch to the root_obj, if not handled
 * dispatch to the focused object.
 */
static void wdg_dispatch_msg(int key)
{
   /* first dispatch to the root object */
   if (wdg_root_obj != NULL) {
      if (wdg_root_obj->get_msg(key) == WDG_ESUCCESS)
         /* the root object handled the message */
         return;
   }

   /* 
    * the root_object has not handled it.
    * dispatch to the focused one
    */
   if (wdg_focused_obj != NULL) {
      if (wdg_focused_obj->wo->get_msg(key) == WDG_ESUCCESS)
         /* the root object handled the message */
         return;
   }
   
   /* reached if noone handle the message */
   
   printw("NOT HANDLED: char %d (%c)\n", key, (char)key); refresh();
}

/*
 * move the focus to the next object.
 * only WDG_WANT_FOCUS could get the focus
 */
static void wdg_switch_focus(void)
{
   struct wdg_obj_list *wl;

   printw("WDG: switch focus\n"); refresh();

   /* if there is not a focused object, create it */
   if (wdg_focused_obj == NULL) {
      CIRCLEQ_FOREACH(wl, &wdg_focus_list, next) {
         if (wl->wo->flags & WDG_WANT_FOCUS) {
            /* set the focused object */
            wdg_focused_obj = wl;
            /* focus current object */
            wdg_focused_obj->wo->get_focus();
         }
      }
      return;
   }
  
   /* unfocus the current object */
   wdg_focused_obj->wo->lost_focus();
   
   /* 
    * focus the next element in the list.
    * only focus objects that have the WDG_WANT_FOCUS flag
    */
   do {
      wdg_focused_obj = CIRCLEQ_NEXT(wdg_focused_obj, next);
   } while (wdg_focused_obj->wo->flags & WDG_WANT_FOCUS);

   /* focus current object */
   wdg_focused_obj->wo->get_focus();
   
}

/*
 * create a wdg object 
 */
int wdg_create_object(struct wdg_object **wo, size_t type, size_t flags)
{
   WDG_NOT_IMPLEMENTED();
   return WDG_ESUCCESS;
}

/*
 * destroy a wdg object by calling the callback function
 */
int wdg_destroy_object(struct wdg_object **wo)
{
   WDG_NOT_IMPLEMENTED();
   return WDG_ESUCCESS;
}

/*
 * set or reset the size of an object
 */
int wdg_resize_object(struct wdg_object *wo, size_t x1, size_t y1, size_t x2, size_t y2)
{
   WDG_NOT_IMPLEMENTED();
   return WDG_ESUCCESS;
}

/* EOF */

// vim:ts=3:expandtab

