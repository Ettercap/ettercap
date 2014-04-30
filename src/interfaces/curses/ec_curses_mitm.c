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
#ifdef WITH_IPV6
static void curses_ndp_poisoning(void);
#endif
static void curses_start_mitm(void);
static void curses_mitm_stop(void);

/* globals */

#define PARAMS_LEN   64

static char params[PARAMS_LEN];

struct wdg_menu menu_mitm[] = { {"Mitm",                'M', "", NULL},
                                {"ARP poisoning...",    0,   "", curses_arp_poisoning},
                                {"ICMP redirect...",    0,   "", curses_icmp_redir},
                                {"PORT stealing...",    0,   "", curses_port_stealing},
                                {"DHCP spoofing...",    0,   "", curses_dhcp_spoofing},
#ifdef WITH_IPV6
                                {"NDP poisoning...",    0,   "", curses_ndp_poisoning},
#endif
                                {"-",                   0,   "", NULL},
                                {"Stop mitm attack(s)", 0,   "", curses_mitm_stop},
                                {NULL, 0, NULL, NULL},
                              };

/*******************************************/

static void curses_arp_poisoning(void)
{
   char *method = "arp:";
   size_t len = strlen(method);
   
   DEBUG_MSG("curses_arp_poisoning");

   strncpy(params, method, len);

   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}

static void curses_icmp_redir(void)
{
   char *method = "icmp:";
   size_t len = strlen(method);

   DEBUG_MSG("curses_icmp_redir");

   strncpy(params, method, len);
   
   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}

static void curses_port_stealing(void)
{
   char *method = "port:";
   size_t len = strlen(method);

   DEBUG_MSG("curses_port_stealing");

   strncpy(params, method, len);
   
   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}

static void curses_dhcp_spoofing(void)
{
   char *method = "dhcp:";
   size_t len = strlen(method);

   DEBUG_MSG("curses_dhcp_spoofing");

   strncpy(params, method, len);
   
   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}

#ifdef WITH_IPV6
static void curses_ndp_poisoning(void)
{
   char *method = "ndp:";
   size_t len = strlen(method);

   DEBUG_MSG("curses_ndp_poisoning");

   strncpy(params, method, len);

   curses_input("Parameters :", params + len, PARAMS_LEN - len - 1, curses_start_mitm);
}
#endif

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

