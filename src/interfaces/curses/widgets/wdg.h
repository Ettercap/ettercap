
/* $Id: wdg.h,v 1.2 2003/10/20 14:41:52 alor Exp $ */

#ifndef WDG_H
#define WDG_H

#ifdef HAVE_CONFIG_H
   #include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

/* informations about the current screen */
struct wdg_scr {
   size_t lines;
   size_t cols;
   char colors;
   char initialized;
};

/* global scruct for current screen */
extern struct wdg_scr current_screen;



/* EXPORTED FUNCTIONS */

extern void wdg_init(void);
extern void wdg_cleanup(void);

#endif 

/* EOF */

// vim:ts=3:expandtab

