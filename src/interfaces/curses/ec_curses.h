
/* $Id: ec_curses.h,v 1.2 2003/12/09 22:32:54 alor Exp $ */

#ifndef EC_CURSES_H
#define EC_CURSES_H

#include <wdg.h>

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

