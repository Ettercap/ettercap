
/* $Id: ec_interfaces.h,v 1.12 2003/10/25 21:57:42 alor Exp $ */

#ifndef EC_INTERFACES_H
#define EC_INTERFACES_H

/* colors for curses interface */
struct curses_color {
   int bg;
   int fg;
   int border;
   int title;
   int focus;
   int menu_bg;
   int menu_fg;
   int window_bg;
   int window_fg;
   int selection_bg;
   int selection_fg;
   int error_bg;
   int error_fg;
   int error_border;
};

/* color pairs */
#define EC_COLOR              0
#define EC_COLOR_BORDER       1
#define EC_COLOR_TITLE        2
#define EC_COLOR_FOCUS        3
#define EC_COLOR_MENU         4
#define EC_COLOR_WINDOW       5
#define EC_COLOR_SELECTION    6
#define EC_COLOR_ERROR        7
#define EC_COLOR_ERROR_BORDER 8

/* exported functions */

extern void select_daemon_interface(void);
extern void select_text_interface(void);
extern void select_curses_interface(void);

#endif

/* EOF */

// vim:ts=3:expandtab

