/*
    WDG -- user input widget

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

    $Id: wdg_input.c,v 1.1 2003/12/06 18:45:51 alor Exp $
*/

#include <wdg.h>

#include <ncurses.h>
#include <form.h>

#include <stdarg.h>

/* GLOBALS */

struct wdg_input_handle {
   WINDOW *win;
   FORM *form;
   WINDOW *fwin;
   FIELD **fields;
   size_t nfields;
};

/* PROTOS */

void wdg_create_input(struct wdg_object *wo);

static int wdg_input_destroy(struct wdg_object *wo);
static int wdg_input_resize(struct wdg_object *wo);
static int wdg_input_redraw(struct wdg_object *wo);
static int wdg_input_get_focus(struct wdg_object *wo);
static int wdg_input_lost_focus(struct wdg_object *wo);
static int wdg_input_get_msg(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse);

static void wdg_input_borders(struct wdg_object *wo);

static int wdg_input_virtualize(struct wdg_object *wo, int key);
static int wdg_input_driver(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse);
static void wdg_input_form_destroy(struct wdg_object *wo);
static void wdg_input_form_create(struct wdg_object *wo);

void wdg_input_size(wdg_t *wo, size_t x, size_t y);
void wdg_input_add(wdg_t *wo, size_t x, size_t y, char *caption, char *buf, size_t len);

/*******************************************/

/* 
 * called to create the menu
 */
void wdg_create_input(struct wdg_object *wo)
{
   /* set the callbacks */
   wo->destroy = wdg_input_destroy;
   wo->resize = wdg_input_resize;
   wo->redraw = wdg_input_redraw;
   wo->get_focus = wdg_input_get_focus;
   wo->lost_focus = wdg_input_lost_focus;
   wo->get_msg = wdg_input_get_msg;

   WDG_SAFE_CALLOC(wo->extend, 1, sizeof(struct wdg_input_handle));
}

/* 
 * called to destroy the menu
 */
static int wdg_input_destroy(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);
   size_t i = 0;

   /* erase the window */
   wbkgd(ww->win, COLOR_PAIR(wo->screen_color));
   werase(ww->win);
   wnoutrefresh(ww->win);

   /* destroy the internal form */
   wdg_input_form_destroy(wo);
   
   /* dealloc the structures */
   delwin(ww->win);
   
   /* free all the items */
   while(ww->fields[i] != NULL) 
      free_field(ww->fields[i++]);

   /* free the array */
   WDG_SAFE_FREE(ww->fields);
   
   WDG_SAFE_FREE(wo->extend);

   return WDG_ESUCCESS;
}

/* 
 * called to resize the menu
 */
static int wdg_input_resize(struct wdg_object *wo)
{
   wdg_input_redraw(wo);

   return WDG_ESUCCESS;
}

/* 
 * called to redraw the menu
 */
static int wdg_input_redraw(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);
   size_t c = wdg_get_ncols(wo);
   size_t l = wdg_get_nlines(wo);
   size_t x = wdg_get_begin_x(wo);
   size_t y = wdg_get_begin_y(wo);
 
   /* the window already exist */
   if (ww->win) {
      /* erase the border */
      wbkgd(ww->win, COLOR_PAIR(wo->screen_color));
      werase(ww->win);
      /* destroy the internal form */
      wdg_input_form_destroy(wo);
      
      touchwin(ww->win);
      wnoutrefresh(ww->win);
     
      /* set the menu color */
      wbkgd(ww->win, COLOR_PAIR(wo->window_color));
     
      /* resize the menu */
      mvwin(ww->win, y, x);
      wresize(ww->win, l, c);
      
      /* redraw the menu */
      wdg_input_borders(wo);
      
      /* create the internal form */
      wdg_input_form_create(wo);
      
      touchwin(ww->win);

   /* the first time we have to allocate the window */
   } else {

      /* create the menu window (fixed dimensions) */
      if ((ww->win = newwin(l, c, y, x)) == NULL)
         return -WDG_EFATAL;

      /* set the window color */
      wbkgd(ww->win, COLOR_PAIR(wo->window_color));
      redrawwin(ww->win);
      
      /* draw the titles */
      wdg_input_borders(wo);

      /* create the internal form */
      wdg_input_form_create(wo);

      /* no scrolling for menu */
      scrollok(ww->win, FALSE);

   }
   
   /* refresh the window */
   touchwin(ww->win);
   wnoutrefresh(ww->win);
   
   touchwin(ww->fwin);
   wnoutrefresh(ww->fwin);

   wo->flags |= WDG_OBJ_VISIBLE;

   return WDG_ESUCCESS;
}

/* 
 * called when the menu gets the focus
 */
static int wdg_input_get_focus(struct wdg_object *wo)
{
   /* set the flag */
   wo->flags |= WDG_OBJ_FOCUSED;

   /* hide the cursor */
   curs_set(TRUE);
   
   /* redraw the window */
   wdg_input_redraw(wo);
   
   return WDG_ESUCCESS;
}

/* 
 * called when the menu looses the focus
 */
static int wdg_input_lost_focus(struct wdg_object *wo)
{
   /* set the flag */
   wo->flags &= ~WDG_OBJ_FOCUSED;
   
   /* hide the cursor */
   curs_set(FALSE);
  
   /* redraw the window */
   wdg_input_redraw(wo);
   
   return WDG_ESUCCESS;
}

/* 
 * called by the messages dispatcher when the menu is focused
 */
static int wdg_input_get_msg(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);

   /* handle the message */
   switch (key) {
         
      case KEY_MOUSE:
         /* is the mouse event within our edges ? */
         if (wenclose(ww->win, mouse->y, mouse->x)) {
            wdg_set_focus(wo);
            /* redraw the menu */
            wdg_input_redraw(wo);
         } else 
            return -WDG_ENOTHANDLED;
         break;
         
      case CTRL('Q'):
         wdg_destroy_object(&wo);
         wdg_redraw_all();
         break;

      /* message not handled */
      default:
         if (wo->flags & WDG_OBJ_FOCUSED) {
            if (wdg_input_driver(wo, key, mouse) != WDG_ESUCCESS)
               wdg_input_redraw(wo);
         } else
            return -WDG_ENOTHANDLED;
         break;
   }
  
   return WDG_ESUCCESS;
}

/*
 * draw the menu titles
 */
static void wdg_input_borders(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);
   size_t c = wdg_get_ncols(wo);
      
   /* the object was focused */
   if (wo->flags & WDG_OBJ_FOCUSED) {
      wattron(ww->win, A_BOLD);
      wbkgdset(ww->win, COLOR_PAIR(wo->focus_color));
   } else
      wbkgdset(ww->win, COLOR_PAIR(wo->border_color));

   /* draw the borders */
   box(ww->win, 0, 0);
   
   /* set the title color */
   wbkgdset(ww->win, COLOR_PAIR(wo->title_color));
   
   /* there is a title: print it */
   if (wo->title) {
      switch (wo->align) {
         case WDG_ALIGN_LEFT:
            wmove(ww->win, 0, 3);
            break;
         case WDG_ALIGN_CENTER:
            wmove(ww->win, 0, (c - strlen(wo->title)) / 2);
            break;
         case WDG_ALIGN_RIGHT:
            wmove(ww->win, 0, c - strlen(wo->title) - 3);
            break;
      }
      wprintw(ww->win, wo->title);
   }
   
   /* restore the attribute */
   if (wo->flags & WDG_OBJ_FOCUSED)
      wattroff(ww->win, A_BOLD);
   
}


/*
 * stransform keys into menu commands 
 */
static int wdg_input_virtualize(struct wdg_object *wo, int key)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);
   int c;
   
   switch (key) {
      case KEY_RETURN:
      case KEY_EXIT:
         c = MAX_FORM_COMMAND + 1;
         break;
      case KEY_UP:
      case KEY_LEFT:
         c =  REQ_PREV_FIELD;
         break;
      case KEY_DOWN:
      case KEY_RIGHT:
         c =  REQ_NEXT_FIELD;
         break;
      case KEY_BACKSPACE:
         c = REQ_DEL_PREV;
         break;
      default:
         c = key;
         break;
   }
   
   /*    
    * Force the field that the user is typing into to be in reverse video,
    * while the other fields are shown underlined.
    */   
   if (c <= KEY_MAX)
      set_field_back(current_field(ww->form), A_REVERSE);
   else if (c <= MAX_FORM_COMMAND)
      set_field_back(current_field(ww->form), A_UNDERLINE);
   
   return c;
}

/*
 * sends command to the form
 */
static int wdg_input_driver(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);
   int c;
 
   c = form_driver(ww->form, wdg_input_virtualize(wo, key) );
  
   /* one item has been selected */
   if (c == E_UNKNOWN_COMMAND) {
      wdg_destroy_object(&wo);   
      return WDG_ESUCCESS;
   }

   wnoutrefresh(ww->fwin);
      
   return WDG_ESUCCESS;
}

/*
 * delete the internal form 
 */
static void wdg_input_form_destroy(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);
  
   /* delete the form */
   unpost_form(ww->form);
   free_form(ww->form);
   ww->form = NULL;

}

/*
 * create the internal form
 */
static void wdg_input_form_create(struct wdg_object *wo)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);
   int mrows, mcols;
   size_t c = wdg_get_ncols(wo);
   size_t x = wdg_get_begin_x(wo);
   size_t y = wdg_get_begin_y(wo);

   /* the form is already posted */
   if (ww->form)
      return;
  
   /* create the form */
   ww->form = new_form(ww->fields);

   /* get the geometry to make a window */
   scale_form(ww->form, &mrows, &mcols);

   /* 
    * if the menu is larger than the main window
    * adapt to the new dimensions
    */
   if (mcols > (int)c - 4) {
      wo->x1 = (current_screen.cols - (mcols + 4)) / 2;
      wo->x2 = -wo->x1;
      wdg_input_redraw(wo);
      return;
   }
   /* create the window for the form */
   ww->fwin = newwin(mrows, MAX(mcols, (int)c - 4), y + 1, x + 2);
   /* set the color */
   wbkgd(ww->fwin, COLOR_PAIR(wo->window_color));
   keypad(ww->fwin, TRUE);
  
   /* associate with the form */
   set_form_win(ww->form, ww->fwin);
   
   /* the subwin for the form */
   set_form_sub(ww->form, derwin(ww->fwin, mrows + 1, mcols, 1, 1));

   /* display the form */
   post_form(ww->form);

   wnoutrefresh(ww->fwin);
}


/*
 * set the size of the dialog 
 */
void wdg_input_size(wdg_t *wo, size_t x, size_t y)
{
   /* center the window on the screen */
   wo->x1 = (current_screen.cols - (x + 2)) / 2;
   wo->y1 = (current_screen.lines - (y + 2)) / 2;
   wo->x2 = -wo->x1;
   wo->y2 = -wo->y1;
   
}

/* 
 * add a field to the form 
 */
void wdg_input_add(wdg_t *wo, size_t x, size_t y, char *caption, char *buf, size_t len)
{
   WDG_WO_EXT(struct wdg_input_handle, ww);
   
   ww->nfields += 2;
   WDG_SAFE_REALLOC(ww->fields, ww->nfields * sizeof(FIELD *));

   /* create the caption */
   ww->fields[ww->nfields - 2] = new_field(1, strlen(caption), y, x, 0, 0);
   set_field_buffer(ww->fields[ww->nfields - 2], 0, caption);
   field_opts_off(ww->fields[ww->nfields - 2], O_ACTIVE);
   set_field_fore(ww->fields[ww->nfields - 2], COLOR_PAIR(wo->focus_color));

   /* and the modifiable field */
   ww->fields[ww->nfields - 1] = new_field(1, len, y, x + strlen(caption) + 2, 0, 0);
   set_field_back(ww->fields[ww->nfields - 1], A_UNDERLINE);
   field_opts_off(ww->fields[ww->nfields - 1], O_WRAP);
   set_field_buffer(ww->fields[ww->nfields - 1], 0, buf);
   set_field_fore(ww->fields[ww->nfields - 1], COLOR_PAIR(wo->window_color));
   set_field_pad(ww->fields[ww->nfields - 1], 0);
   
   /* null terminate the array */
   WDG_SAFE_REALLOC(ww->fields, (ww->nfields + 1) * sizeof(FIELD *));
   ww->fields[ww->nfields] = NULL;

}

/* EOF */

// vim:ts=3:expandtab

