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

    $Id: wdg.c,v 1.10 2003/10/25 21:57:42 alor Exp $
*/

#include <wdg.h>

#include <ncurses.h>

/* not defined in curses.h */
#define KEY_TAB   '\t'

/* GLOBALS */

/* informations about the current screen */
struct wdg_scr current_screen;

/* called when idle */
struct wdg_call_list {
   void (*idle_callback)(void);
   SLIST_ENTRY(wdg_call_list) next;
};
static SLIST_HEAD(, wdg_call_list) wdg_callbacks_list;

/* the root object (usually the menu) */
static struct wdg_object *wdg_root_obj;

/* the focus list */
struct wdg_obj_list {
   struct wdg_object *wo;
   TAILQ_ENTRY(wdg_obj_list) next;
};
static TAILQ_HEAD(, wdg_obj_list) wdg_objects_list = TAILQ_HEAD_INITIALIZER(wdg_objects_list);

/* the currently focused object */
static struct wdg_obj_list *wdg_focused_obj;

/* PROTOS */

void wdg_init(void);
void wdg_cleanup(void);
static void wdg_resize(void);

void wdg_add_idle_callback(void (*callback)(void));
void wdg_del_idle_callback(void (*callback)(void));

int wdg_events_handler(int exit_key);
static void wdg_dispatch_msg(int key);
static void wdg_switch_focus(void);
void wdg_set_focus(struct wdg_object *wo);

int wdg_create_object(struct wdg_object **wo, size_t type, size_t flags);
int wdg_destroy_object(struct wdg_object **wo);

void wdg_resize_object(struct wdg_object *wo, int x1, int y1, int x2, int y2);
void wdg_draw_object(struct wdg_object *wo);
size_t wdg_get_type(struct wdg_object *wo);
void wdg_init_color(u_char pair, u_char fg, u_char bg);
void wdg_set_color(wdg_t *wo, size_t part, u_char pair);

size_t wdg_get_nlines(struct wdg_object *wo);
size_t wdg_get_ncols(struct wdg_object *wo);
size_t wdg_get_begin_x(struct wdg_object *wo);
size_t wdg_get_begin_y(struct wdg_object *wo);

/* creation function from other widgets */
extern void wdg_create_window(struct wdg_object *wo);
extern void wdg_create_panel(struct wdg_object *wo);

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
      current_screen.flags |= WDG_SCR_HAS_COLORS;
      start_color();
   }

   /* hide the cursor */
   curs_set(FALSE);

   /* remember the current screen size */
   current_screen.lines = LINES;
   current_screen.cols = COLS;

   /* the wdg is initialized */
   current_screen.flags |= WDG_SCR_INITIALIZED;

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
   if (!(current_screen.flags & WDG_SCR_INITIALIZED))
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
   current_screen.flags &= ~WDG_SCR_INITIALIZED;
}


/* 
 * called upone screen resize
 */
static void wdg_resize(void)
{
   struct wdg_obj_list *wl;
   
   /* remember the current screen size */
   current_screen.lines = LINES;
   current_screen.cols = COLS;

   /* call the redraw function upon all the objects */
   TAILQ_FOREACH(wl, &wdg_objects_list, next) {
      WDG_BUG_IF(wl->wo->redraw == NULL);
      WDG_EXECUTE(wl->wo->redraw, wl->wo);
   }

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
           
         case KEY_RESIZE:
            /* the screen has been resized */
            wdg_resize();
            break;
              
         case ERR:
            /* 
             * non-blocking input reached the timeout:
             * call the idle function if present, else
             * sleep to not eat up all the cpu
             */
            if (SLIST_EMPTY(&wdg_callbacks_list)) {
               /* sleep for milliseconds */
               napms(WDG_INPUT_TIMEOUT * 10);
               /* XXX - too many refresh ? */
               refresh();
            } else {
               struct wdg_call_list *cl;
               SLIST_FOREACH(cl, &wdg_callbacks_list, next)
                  cl->idle_callback();
            }
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
 * add a function to the idle callbacks list 
 */
void wdg_add_idle_callback(void (*callback)(void))
{
   struct wdg_call_list *cl;

   WDG_SAFE_CALLOC(cl, 1, sizeof(struct wdg_call_list));

   /* store the callback */
   cl->idle_callback = callback;

   /* insert in the list */
   SLIST_INSERT_HEAD(&wdg_callbacks_list, cl, next);
}

/*
 * delete a function from the callbacks list
 */
void wdg_del_idle_callback(void (*callback)(void))
{
   struct wdg_call_list *cl;

   SLIST_FOREACH(cl, &wdg_callbacks_list, next) {
      if (cl->idle_callback == callback) {
         SLIST_REMOVE(&wdg_callbacks_list, cl, wdg_call_list, next);
         WDG_SAFE_FREE(cl);
         return;
      }
   }
}

/*
 * dispatch the user input to the list of objects.
 * first dispatch to the root_obj, if not handled
 * dispatch to the focused object.
 */
static void wdg_dispatch_msg(int key)
{
   /* the focused object is modal ! send only to it */
   if (wdg_focused_obj && (wdg_focused_obj->wo->flags & WDG_OBJ_FOCUS_MODAL)) {
      wdg_focused_obj->wo->get_msg(wdg_focused_obj->wo, key);
      /* other objects must not receive the msg */
      return;
   }
   
   /* first dispatch to the root object */
   if (wdg_root_obj != NULL) {
      if (wdg_root_obj->get_msg(wdg_root_obj, key) == WDG_ESUCCESS)
         /* the root object handled the message */
         return;
   }

   /* 
    * the root_object has not handled it.
    * dispatch to the focused one
    */
   if (wdg_focused_obj != NULL) {
      if (wdg_focused_obj->wo->get_msg(wdg_focused_obj->wo, key) == WDG_ESUCCESS)
         /* the focused object handled the message */
         return;
   }
   
   /* reached if noone handle the message */
   
   printw("WDG: NOT HANDLED: char %d (%c)\n", key, (char)key); refresh();
}

/*
 * move the focus to the next object.
 * only WDG_OBJ_WANT_FOCUS could get the focus
 */
static void wdg_switch_focus(void)
{
   struct wdg_obj_list *wl;

   /* the focused object is modal ! don't switch */
   if (wdg_focused_obj && (wdg_focused_obj->wo->flags & WDG_OBJ_FOCUS_MODAL))
      return;
  
   /* if there is not a focused object, create it */
   if (wdg_focused_obj == NULL) {
   
      /* search the first "focusable" object */
      TAILQ_FOREACH(wl, &wdg_objects_list, next) {
         if ((wl->wo->flags & WDG_OBJ_WANT_FOCUS) && (wl->wo->flags & WDG_OBJ_VISIBLE) ) {
            /* set the focused object */
            wdg_focused_obj = wl;
            /* focus current object */
            WDG_BUG_IF(wdg_focused_obj->wo->get_focus == NULL);
            WDG_EXECUTE(wdg_focused_obj->wo->get_focus, wdg_focused_obj->wo);
         }
      }
      return;
   }
  
   /* unfocus the current object */
   WDG_BUG_IF(wdg_focused_obj->wo->lost_focus == NULL);
   WDG_EXECUTE(wdg_focused_obj->wo->lost_focus, wdg_focused_obj->wo);
   
   /* 
    * focus the next element in the list.
    * only focus objects that have the WDG_OBJ_WANT_FOCUS flag
    */
   do {
      wdg_focused_obj = TAILQ_NEXT(wdg_focused_obj, next);
      /* we are on the head, move to the first element */
      if (wdg_focused_obj == TAILQ_END(&wdg_objects_list))
         wdg_focused_obj = TAILQ_FIRST(&wdg_objects_list);
   } while ( !(wdg_focused_obj->wo->flags & WDG_OBJ_WANT_FOCUS) || !(wdg_focused_obj->wo->flags & WDG_OBJ_VISIBLE) );

   /* focus current object */
   WDG_BUG_IF(wdg_focused_obj->wo->get_focus == NULL);
   WDG_EXECUTE(wdg_focused_obj->wo->get_focus, wdg_focused_obj->wo);
   
}

/*
 * set focus to the given object
 */
void wdg_set_focus(struct wdg_object *wo)
{
   struct wdg_obj_list *wl;

   /* search the object and focus it */
   TAILQ_FOREACH(wl, &wdg_objects_list, next) {
      if ( wl->wo == wo ) {
         /* unfocus the current object */
         if (wdg_focused_obj)
            WDG_EXECUTE(wdg_focused_obj->wo->lost_focus, wdg_focused_obj->wo);
         /* set the focused object */
         wdg_focused_obj = wl;
         /* focus current object */
         WDG_BUG_IF(wdg_focused_obj->wo->get_focus == NULL);
         WDG_EXECUTE(wdg_focused_obj->wo->get_focus, wdg_focused_obj->wo);
      }
   }
}

/*
 * create a wdg object 
 */
int wdg_create_object(struct wdg_object **wo, size_t type, size_t flags)
{
   struct wdg_obj_list *wl;
   
   /* alloc the struct */
   WDG_SAFE_CALLOC(*wo, 1, sizeof(struct wdg_object));

   /* set the flags */
   (*wo)->flags = flags;
   (*wo)->type = type;
  
   /* call the specific function */
   switch (type) {
      case WDG_WINDOW:
         wdg_create_window(*wo);
         break;
         
      case WDG_PANEL:
         wdg_create_panel(*wo);
         break;
         
      default:
         WDG_SAFE_FREE(*wo);
         return -WDG_EFATAL;
         break;
   }
   
   /* alloc the element in the object list */
   WDG_SAFE_CALLOC(wl, 1, sizeof(struct wdg_obj_list));

   /* link the object */
   wl->wo = *wo;

   /* insert it in the list */
   TAILQ_INSERT_HEAD(&wdg_objects_list, wl, next);
   
   /* this is the root object */
   if (flags & WDG_OBJ_ROOT_OBJECT)
      wdg_root_obj = *wo;
   
   return WDG_ESUCCESS;
}

/*
 * destroy a wdg object by calling the callback function
 */
int wdg_destroy_object(struct wdg_object **wo)
{
   struct wdg_obj_list *wl;
  
   /* sanity check */
   if (*wo == NULL)
      return -WDG_ENOTHANDLED;
   
   /* was it the root object ? */
   if ((*wo)->flags & WDG_OBJ_ROOT_OBJECT)
      wdg_root_obj = NULL;
  
   /* it was the focused one */
   if (wdg_focused_obj && wdg_focused_obj->wo == *wo)
      wdg_switch_focus();
  
   /* delete it from the obj_list */
   TAILQ_FOREACH(wl, &wdg_objects_list, next) {
      if (wl->wo == *wo) {
         /* 
          * check if it was the only object in the list
          * and it has gained the focus with the previous
          * call to wdg_switch_focus();
          */
         if (wl == wdg_focused_obj)
            wdg_focused_obj = NULL;

         /* remove the object */
         TAILQ_REMOVE(&wdg_objects_list, wl, next);
         WDG_SAFE_FREE(wl);
         
         /* call the specialized destroy function */
         WDG_BUG_IF((*wo)->destroy == NULL);
         WDG_EXECUTE((*wo)->destroy, *wo);
   
         /* then free the object */
         WDG_SAFE_FREE(*wo);
         
         return WDG_ESUCCESS;
      }
   }

   return -WDG_ENOTHANDLED;
}

/*
 * set or reset the size of an object
 */
void wdg_resize_object(struct wdg_object *wo, int x1, int y1, int x2, int y2)
{
   /* set the new object cohordinates */
   wo->x1 = x1;
   wo->y1 = y1;
   wo->x2 = x2;
   wo->y2 = y2;

   /* call the specialized function */
   WDG_BUG_IF(wo->resize == NULL);
   WDG_EXECUTE(wo->resize, wo);
}

/*
 * display the object by calling the redraw function
 */
void wdg_draw_object(struct wdg_object *wo)
{
   /* display the object */
   WDG_BUG_IF(wo->redraw == NULL);
   WDG_EXECUTE(wo->redraw, wo);
}

/*
 * return the type of the object
 */
size_t wdg_get_type(struct wdg_object *wo)
{
   return wo->type;
}

/* 
 * set the color of an object
 */
void wdg_set_color(wdg_t *wo, size_t part, u_char pair)
{
   switch (part) {
      case WDG_COLOR_TITLE:
         wo->title_color = pair;
         break;
      case WDG_COLOR_BORDER:
         wo->border_color = pair;
         break;
      case WDG_COLOR_FOCUS:
         wo->focus_color = pair;
         break;
      case WDG_COLOR_WINDOW:
         wo->window_color = pair;
         break;
      case WDG_COLOR_SELECT:
         wo->select_color = pair;
         break;
   }
}

/*
 * init a color pair
 */
void wdg_init_color(u_char pair, u_char fg, u_char bg)
{
   init_pair(pair, fg, bg);
}

/* 
 * functions to calculate real dimensions
 * from the given relative cohordinates 
 */

size_t wdg_get_nlines(struct wdg_object *wo)
{
   size_t a, b;
   int c = current_screen.lines;
   
   if (wo->y1 >= 0)
      a = wo->y1;
   else 
      a = (c + wo->y1 > 0) ? (c + wo->y1) : 0;

   if (wo->y2 >= 0)
      b = wo->y2;
   else
      b = (c + wo->y2 > 0) ? (c + wo->y2) : 0;
   
   /* only return positive values */
   return (b > a) ? b - a : 0;
}

size_t wdg_get_ncols(struct wdg_object *wo)
{
   size_t a, b;
   int c = current_screen.cols;
   
   if (wo->x1 >= 0)
      a = wo->x1;
   else 
      a = (c + wo->x1 > 0) ? (c + wo->x1) : 0;

   if (wo->x2 >= 0)
      b = wo->x2;
   else
      b = (c + wo->x2 > 0) ? (c + wo->x2) : 0;
   
   /* only return positive values */
   return (b > a) ? b - a : 0;
}

size_t wdg_get_begin_x(struct wdg_object *wo)
{
   int c = current_screen.cols;

   if (wo->x1 >= 0)
      return wo->x1;
   else
      return (c + wo->x1 >= 0) ? (c + wo->x1) : 0;
}

size_t wdg_get_begin_y(struct wdg_object *wo)
{
   int c = current_screen.lines;

   if (wo->y1 >= 0)
      return wo->y1;
   else
      return (c + wo->y1 >= 0) ? (c + wo->y1) : 0;
}

/* EOF */

// vim:ts=3:expandtab

