/*
    ettercap -- curses GUI

    Copyright (C) ALoR & NaGA

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

    $Id: ec_curses_target.c,v 1.2 2003/12/13 18:41:11 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>

/* proto */

static void toggle_reverse(void);
static void curses_select_protocol(void);
static void set_protocol(void);
static void wipe_targets(void);
static void curses_select_targets(void);
static void set_targets(void);

/* globals */

static char tag_reverse[] = " ";

struct wdg_menu menu_target[] = { {"Targets",         "T", NULL},
                                  {"Current Targets",  "", NULL},
                                  {"Select TARGET(s)", "", curses_select_targets},
                                  {"-",                "", NULL},
                                  {"Protocol...",      "", curses_select_protocol},
                                  {"Reverse matching", tag_reverse, toggle_reverse},
                                  {"-",                "", NULL},
                                  {"Wipe targets",     "", wipe_targets},
                                  {NULL, NULL, NULL},
                                };


/*******************************************/

static void toggle_reverse(void)
{
   if (GBL_OPTIONS->reversed) {
      tag_reverse[0] = ' ';
      GBL_OPTIONS->reversed = 0;
   } else {
      tag_reverse[0] = '*';
      GBL_OPTIONS->reversed = 1;
   }
}

/*
 * wipe the targets struct setting both T1 and T2 to ANY/ANY/ANY
 */
static void wipe_targets(void)
{
   DEBUG_MSG("wipe_targets");
   
   reset_display_filter(GBL_TARGET1);
   reset_display_filter(GBL_TARGET2);

   /* display the message */
   curses_message("TARGETS were reset to ANY/ANY/ANY");
}

/*
 * display the protocol dialog
 */
static void curses_select_protocol(void)
{
   DEBUG_MSG("curses_select_protocol");

   /* this will contain 'all', 'tcp' or 'udp' */
   if (!GBL_OPTIONS->proto) {
      SAFE_CALLOC(GBL_OPTIONS->proto, 4, sizeof(char));
      strcpy(GBL_OPTIONS->proto, "all");
   }

   curses_input_call("Protocol :", GBL_OPTIONS->proto, 3, set_protocol);
}

static void set_protocol(void)
{
   if (strcasecmp(GBL_OPTIONS->proto, "all") &&
       strcasecmp(GBL_OPTIONS->proto, "tcp") &&
       strcasecmp(GBL_OPTIONS->proto, "udp")) {
      ui_error("Invalid protocol");
      SAFE_FREE(GBL_OPTIONS->proto);
   }
}

/*
 * display the TARGET(s) dialog
 */
static void curses_select_targets(void)
{
   wdg_t *in;
   
#define TARGET_LEN 50
   
   DEBUG_MSG("curses_select_target1");

   /* alloc the buffer if it does not exist */
   SAFE_REALLOC(GBL_OPTIONS->target1, TARGET_LEN * sizeof(char));
   SAFE_REALLOC(GBL_OPTIONS->target2, TARGET_LEN * sizeof(char));
   
   wdg_create_object(&in, WDG_INPUT, WDG_OBJ_WANT_FOCUS | WDG_OBJ_FOCUS_MODAL);
   wdg_set_color(in, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(in, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(in, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(in, WDG_COLOR_TITLE, EC_COLOR_MENU);
   wdg_input_size(in, strlen("TARGET1 :") + TARGET_LEN, 4);
   wdg_input_add(in, 1, 1, "TARGET1 :", GBL_OPTIONS->target1, TARGET_LEN);
   wdg_input_add(in, 1, 2, "TARGET2 :", GBL_OPTIONS->target2, TARGET_LEN);
   wdg_input_set_callback(in, set_targets);
   
   wdg_draw_object(in);
      
   wdg_set_focus(in);
}

/*
 * set the targets 
 */
static void set_targets(void)
{
   reset_display_filter(GBL_TARGET1);
   reset_display_filter(GBL_TARGET2);
   /* this will reset the both the targets */
   compile_display_filter();
}


/* EOF */

// vim:ts=3:expandtab

