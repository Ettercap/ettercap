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

    $Id: wdg.c,v 1.2 2003/10/20 14:41:52 alor Exp $
*/

#include <wdg.h>

#include <curses.h>

/* globals */

/* informations about the current screen */
struct wdg_scr current_screen;

/* proto */

void wdg_init(void);
void wdg_cleanup(void);

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
}


/*
 * cleanup the widgets interface
 */
void wdg_cleanup(void)
{

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

/* EOF */

// vim:ts=3:expandtab

