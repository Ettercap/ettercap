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

    $Id: ec_curses_mitm.c,v 1.4 2004/02/29 17:37:21 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>
#include <ec_mitm.h>

/* proto */

static void curses_arp_poisoning(void);
static void curses_icmp_redir(void);
static void curses_port_stealing(void);
static void curses_dhcp_spoofing(void);
static void curses_start_mitm(void);
static void curses_mitm_stop(void);

/* globals */

#define PARAMS_LEN   50

static char params[PARAMS_LEN];

struct wdg_menu menu_mitm[] = { {"Mitm",                'M', "", NULL},
                                {"Arp poisoning...",    0,   "", curses_arp_poisoning},
                                {"Icmp redirect...",    0,   "", curses_icmp_redir},
                                {"Port stealing...",    0,   "", curses_port_stealing},
                                {"Dhcp spoofing...",    0,   "", curses_dhcp_spoofing},
                                {"-",                   0,   "", NULL},
                                {"Stop mitm attack(s)", 0,   "", curses_mitm_stop},
                                {NULL, 0, NULL, NULL},
                              };

/*******************************************/

static void curses_arp_poisoning(void)
{
   DEBUG_MSG("curses_arp_poisoning");

   sprintf(params, "arp:");

   curses_input("Parameters :", params + strlen("arp:"), PARAMS_LEN - strlen("arp:"), curses_start_mitm);
}

static void curses_icmp_redir(void)
{
   DEBUG_MSG("curses_icmp_redir");

   sprintf(params, "icmp:");
   
   curses_input("Parameters :", params + strlen("icmp:"), PARAMS_LEN - strlen("icmp:"), curses_start_mitm);
}

static void curses_port_stealing(void)
{
   DEBUG_MSG("curses_port_stealing");

   sprintf(params, "port:");
   
   curses_input("Parameters :", params + strlen("port:"), PARAMS_LEN - strlen("port:"), curses_start_mitm);
}

static void curses_dhcp_spoofing(void)
{
   DEBUG_MSG("curses_dhcp_spoofing");

   sprintf(params, "dhcp:");
   
   curses_input("Parameters :", params + strlen("dhcp:"), PARAMS_LEN - strlen("dhcp:"), curses_start_mitm);
}


/* 
 * start the mitm attack by passing the name and parameters 
 */
static void curses_start_mitm(void)
{
   DEBUG_MSG("curses_start_mitm");
   
   mitm_set(params);
   mitm_start();
}


/*
 * stop all the mitm attack(s)
 */
static void curses_mitm_stop(void)
{
   wdg_t *dlg;
   
   DEBUG_MSG("curses_mitm_stop");

   /* create the dialog */
   wdg_create_object(&dlg, WDG_DIALOG, WDG_OBJ_WANT_FOCUS);
   
   wdg_set_color(dlg, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(dlg, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(dlg, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_dialog_text(dlg, WDG_NO_BUTTONS, "Stopping the mitm attack...");
   wdg_draw_object(dlg);
   
   wdg_set_focus(dlg);
  
   wdg_update_screen();
   
   /* stop the mitm process */
   mitm_stop();

   wdg_destroy_object(&dlg);
   
   curses_message("MITM attack(s) stopped");
}

/* EOF */

// vim:ts=3:expandtab

