
/* $Id: ec_curses.h,v 1.3 2003/12/13 18:41:11 alor Exp $ */

#ifndef EC_CURSES_H
#define EC_CURSES_H

#include <wdg.h>

#define SYSMSG_WIN_SIZE -8

extern void curses_input_call(const char *title, char *input, size_t n, void (*callback)(void));
extern void curses_message(const char *msg);

extern void curses_flush_msg(void);
extern void curses_sniff_offline(void);
extern void curses_sniff_live(void);

/* menus */
extern struct wdg_menu menu_start[]; 
extern struct wdg_menu menu_target[]; 
extern struct wdg_menu menu_view[]; 

#endif

/* EOF */

// vim:ts=3:expandtab

