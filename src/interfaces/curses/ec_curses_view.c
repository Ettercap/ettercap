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

    $Id: ec_curses_view.c,v 1.13 2004/02/02 22:28:29 alor Exp $
*/

#include <ec.h>
#include <wdg.h>
#include <ec_curses.h>
#include <ec_format.h>
#include <ec_profiles.h>
#include <ec_conntrack.h>
#include <ec_manuf.h>
#include <ec_services.h>

/* proto */

static void toggle_resolve(void);
static void curses_show_stats(void);
static void curses_stop_stats(void);
static void refresh_stats(void);
static void curses_vis_method(void);
static void set_method(void);
static void curses_show_profiles(void);
static void curses_kill_profiles(void);
static void refresh_profiles(void);
static void curses_profile_detail(void *profile);
static void curses_profiles_local(void *dummy);
static void curses_profiles_remote(void *dummy);
static void curses_profiles_convert(void *dummy);
static void curses_show_connections(void);
static void curses_kill_connections(void);
static void refresh_connections(void);

/* globals */

static char tag_resolve[] = " ";
static wdg_t *wdg_stats, *wdg_profiles, *wdg_details, *wdg_connections;
#define VLEN 8
static char vmethod[VLEN];

struct wdg_menu menu_view[] = { {"View",                 'V', "",  NULL},
                                {"Connections",          'C', "C", curses_show_connections},
                                {"Profiles",             'O', "O", curses_show_profiles},
                                {"Statistics",           's', "s", curses_show_stats},
                                {"-",                     0,  "",  NULL},
                                {"Resolve IP addresses",  0, tag_resolve,   toggle_resolve},
                                {"Visualization method...", 'v', "v", curses_vis_method},
                                {NULL, 0, NULL, NULL},
                              };


/*******************************************/


static void toggle_resolve(void)
{
   if (GBL_OPTIONS->resolve) {
      tag_resolve[0] = ' ';
      GBL_OPTIONS->resolve = 0;
   } else {
      tag_resolve[0] = '*';
      GBL_OPTIONS->resolve = 1;
   }
}

/*
 * display the statistics windows
 */
static void curses_show_stats(void)
{
   DEBUG_MSG("curses_show_stats");

   /* if the object already exist, set the focus to it */
   if (wdg_stats) {
      wdg_set_focus(wdg_stats);
      return;
   }
   
   wdg_create_object(&wdg_stats, WDG_WINDOW, WDG_OBJ_WANT_FOCUS);
   
   wdg_set_title(wdg_stats, "Statistics:", WDG_ALIGN_LEFT);
   wdg_set_size(wdg_stats, 1, 2, 70, 21);
   wdg_set_color(wdg_stats, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(wdg_stats, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(wdg_stats, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(wdg_stats, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(wdg_stats, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_draw_object(wdg_stats);
 
   wdg_set_focus(wdg_stats);
  
   /* display the stats */
   refresh_stats(); 

   /* add the callback on idle to refresh the stats */
   wdg_add_idle_callback(refresh_stats);

   /* add the destroy callback */
   wdg_add_destroy_key(wdg_stats, CTRL('Q'), curses_stop_stats);
}

static void curses_stop_stats(void)
{
   DEBUG_MSG("curses_stop_stats");
   wdg_del_idle_callback(refresh_stats);

   /* the object does not exist anymore */
   wdg_stats = NULL;
}

static void refresh_stats(void)
{
   /* if not focused don't refresh it */
   if (!(wdg_stats->flags & WDG_OBJ_FOCUSED))
      return;
   
   wdg_window_print(wdg_stats, 1, 1, "Received packets    : %8lld", GBL_STATS->ps_recv);
   wdg_window_print(wdg_stats, 1, 2, "Dropped packets     : %8lld  %.2f %%", GBL_STATS->ps_drop, 
          (GBL_STATS->ps_recv) ? (float)GBL_STATS->ps_drop * 100 / GBL_STATS->ps_recv : 0 );
   wdg_window_print(wdg_stats, 1, 3, "Forwarded packets   : %8lld  bytes: %8lld ", GBL_STATS->ps_sent, GBL_STATS->bs_sent);
  
   wdg_window_print(wdg_stats, 1, 5, "Current queue len   : %d/%d", GBL_STATS->queue_curr, GBL_STATS->queue_max);
   wdg_window_print(wdg_stats, 1, 6, "Sampling rate       : %d", GBL_CONF->sampling_rate);
   
   wdg_window_print(wdg_stats, 1, 8, "Bottom Half received packet : pck: %8lld  bytes: %8lld", 
         GBL_STATS->bh.pck_recv, GBL_STATS->bh.pck_size);
   wdg_window_print(wdg_stats, 1, 9, "Top Half received packet    : pck: %8lld  bytes: %8lld", 
         GBL_STATS->th.pck_recv, GBL_STATS->th.pck_size);
   wdg_window_print(wdg_stats, 1, 10, "Interesting packets         : %.2f %%",
         (GBL_STATS->bh.pck_recv) ? (float)GBL_STATS->th.pck_recv * 100 / GBL_STATS->bh.pck_recv : 0 );

   wdg_window_print(wdg_stats, 1, 12, "Bottom Half packet rate : worst: %8d  adv: %8d p/s", 
         GBL_STATS->bh.rate_worst, GBL_STATS->bh.rate_adv);
   wdg_window_print(wdg_stats, 1, 13, "Top Half packet rate    : worst: %8d  adv: %8d p/s", 
         GBL_STATS->th.rate_worst, GBL_STATS->th.rate_adv);
   
   wdg_window_print(wdg_stats, 1, 14, "Bottom Half thruoutput  : worst: %8d  adv: %8d b/s", 
         GBL_STATS->bh.thru_worst, GBL_STATS->bh.thru_adv);
   wdg_window_print(wdg_stats, 1, 15, "Top Half thruoutput     : worst: %8d  adv: %8d b/s", 
         GBL_STATS->th.thru_worst, GBL_STATS->th.thru_adv);
}

/*
 * change the visualization method 
 */
static void curses_vis_method(void)
{
   DEBUG_MSG("curses_vis_method");

   curses_input_call("Visualization method :", vmethod, VLEN, set_method);
}

static void set_method(void)
{
   set_format(vmethod);
}

/*
 * the auto-refreshing list of profiles 
 */
static void curses_show_profiles(void)
{
   DEBUG_MSG("curses_show_profiles");

   /* if the object already exist, set the focus to it */
   if (wdg_profiles) {
      wdg_set_focus(wdg_profiles);
      return;
   }
   
   wdg_create_object(&wdg_profiles, WDG_DYNLIST, WDG_OBJ_WANT_FOCUS);
   
   wdg_set_title(wdg_profiles, "Collected passive profiles:", WDG_ALIGN_LEFT);
   wdg_set_size(wdg_profiles, 1, 2, -1, SYSMSG_WIN_SIZE - 1);
   wdg_set_color(wdg_profiles, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(wdg_profiles, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(wdg_profiles, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(wdg_profiles, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(wdg_profiles, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_draw_object(wdg_profiles);
 
   wdg_set_focus(wdg_profiles);

   /* set the list print callback */
   wdg_dynlist_print_callback(wdg_profiles, profile_print);
   
   /* set the select callback */
   wdg_dynlist_select_callback(wdg_profiles, curses_profile_detail);
  
   /* add the callback on idle to refresh the profile list */
   wdg_add_idle_callback(refresh_profiles);

   /* add the destroy callback */
   wdg_add_destroy_key(wdg_profiles, CTRL('Q'), curses_kill_profiles);

   wdg_dynlist_add_callback(wdg_profiles, 'l', curses_profiles_local);
   wdg_dynlist_add_callback(wdg_profiles, 'r', curses_profiles_remote);
   wdg_dynlist_add_callback(wdg_profiles, 'c', curses_profiles_convert);
}

static void curses_kill_profiles(void)
{
   DEBUG_MSG("curses_kill_profiles");
   wdg_del_idle_callback(refresh_profiles);

   /* the object does not exist anymore */
   wdg_profiles = NULL;
}

static void refresh_profiles(void)
{
   /* if not focused don't refresh it */
   if (!(wdg_profiles->flags & WDG_OBJ_FOCUSED))
      return;
   
   wdg_dynlist_refresh(wdg_profiles);
}

/*
 * display details for a profile
 */
static void curses_profile_detail(void *profile)
{
   struct host_profile *h = (struct host_profile *)profile;
   struct open_port *o;
   struct active_user *u;
   char tmp[MAX_ASCII_ADDR_LEN];
   char os[OS_LEN+1];
   
   DEBUG_MSG("curses_profile_detail");

   /* if the object already exist, set the focus to it */
   if (wdg_details) {
      wdg_destroy_object(&wdg_details);
      wdg_details = NULL;
   }
   
   wdg_create_object(&wdg_details, WDG_SCROLL, WDG_OBJ_WANT_FOCUS);
   
   wdg_set_title(wdg_details, "Profile details:", WDG_ALIGN_LEFT);
   wdg_set_size(wdg_details, 1, 2, -1, SYSMSG_WIN_SIZE - 1);
   wdg_set_color(wdg_details, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(wdg_details, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(wdg_details, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(wdg_details, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(wdg_details, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_draw_object(wdg_details);
 
   wdg_set_focus(wdg_details);

   wdg_add_destroy_key(wdg_details, CTRL('Q'), NULL);
   wdg_scroll_set_lines(wdg_details, 50);

   memset(os, 0, sizeof(os));
   
   wdg_scroll_print(wdg_details, " IP address   : %s \n", ip_addr_ntoa(&h->L3_addr, tmp));
   if (strcmp(h->hostname, ""))
      wdg_scroll_print(wdg_details, " Hostname     : %s \n\n", h->hostname);
   else
      wdg_scroll_print(wdg_details, "\n");   
      
   if (h->type & FP_HOST_LOCAL || h->type == FP_UNKNOWN) {
      wdg_scroll_print(wdg_details, " MAC address  : %s \n", mac_addr_ntoa(h->L2_addr, tmp));
      wdg_scroll_print(wdg_details, " MANUFACTURER : %s \n\n", manuf_search(h->L2_addr));
   }

   wdg_scroll_print(wdg_details, " DISTANCE     : %d   \n", h->distance);
   if (h->type & FP_GATEWAY)
      wdg_scroll_print(wdg_details, " TYPE         : GATEWAY\n\n");
   else if (h->type & FP_HOST_LOCAL)
      wdg_scroll_print(wdg_details, " TYPE         : LAN host\n\n");
   else if (h->type & FP_ROUTER)
      wdg_scroll_print(wdg_details, " TYPE         : REMOTE ROUTER\n\n");
   else if (h->type & FP_HOST_NONLOCAL)
      wdg_scroll_print(wdg_details, " TYPE         : REMOTE host\n\n");
   else if (h->type == FP_UNKNOWN)
      wdg_scroll_print(wdg_details, " TYPE         : unknown\n\n");
      
   
   wdg_scroll_print(wdg_details, " FINGERPRINT      : %s\n", h->fingerprint);
   if (fingerprint_search(h->fingerprint, os) == ESUCCESS)
      wdg_scroll_print(wdg_details, " OPERATING SYSTEM : %s \n\n", os);
   else {
      wdg_scroll_print(wdg_details, " OPERATING SYSTEM : unknown fingerprint (please submit it) \n");
      wdg_scroll_print(wdg_details, " NEAREST ONE IS   : %s \n\n", os);
   }
      
   
   LIST_FOREACH(o, &(h->open_ports_head), next) {
      
      wdg_scroll_print(wdg_details, "   PORT     : %s %d | %s \t[%s]\n", 
                  (o->L4_proto == NL_TYPE_TCP) ? "TCP" : "UDP" , 
                  ntohs(o->L4_addr),
                  service_search(o->L4_addr, o->L4_proto), 
                  (o->banner) ? o->banner : "");
      
      LIST_FOREACH(u, &(o->users_list_head), next) {
        
         if (u->failed)
            wdg_scroll_print(wdg_details, "      ACCOUNT : * %s / %s  (%s)\n", u->user, u->pass, ip_addr_ntoa(&u->client, tmp));
         else
            wdg_scroll_print(wdg_details, "      ACCOUNT : %s / %s  (%s)\n", u->user, u->pass, ip_addr_ntoa(&u->client, tmp));
         if (u->info)
            wdg_scroll_print(wdg_details, "      INFO    : %s\n\n", u->info);
         else
            wdg_scroll_print(wdg_details, "\n");
      }
      wdg_scroll_print(wdg_details, "\n");
   }
}

static void curses_profiles_local(void *dummy)
{
   profile_purge_remote();
   wdg_dynlist_reset(wdg_profiles);
   wdg_dynlist_refresh(wdg_profiles);
}

static void curses_profiles_remote(void *dummy)
{
   profile_purge_local();
   wdg_dynlist_reset(wdg_profiles);
   wdg_dynlist_refresh(wdg_profiles);
}

static void curses_profiles_convert(void *dummy)
{
   profile_convert_to_hostlist();
   curses_message("The hosts list was populated with local profiles");
}

/*
 * the auto-refreshing list of connections
 */
static void curses_show_connections(void)
{
   DEBUG_MSG("curses_show_connections");

   /* if the object already exist, set the focus to it */
   if (wdg_connections) {
      wdg_set_focus(wdg_connections);
      return;
   }
   
   wdg_create_object(&wdg_connections, WDG_DYNLIST, WDG_OBJ_WANT_FOCUS);
   
   wdg_set_title(wdg_connections, "Live connections:", WDG_ALIGN_LEFT);
   wdg_set_size(wdg_connections, 1, 2, -1, SYSMSG_WIN_SIZE - 1);
   wdg_set_color(wdg_connections, WDG_COLOR_SCREEN, EC_COLOR);
   wdg_set_color(wdg_connections, WDG_COLOR_WINDOW, EC_COLOR);
   wdg_set_color(wdg_connections, WDG_COLOR_BORDER, EC_COLOR_BORDER);
   wdg_set_color(wdg_connections, WDG_COLOR_FOCUS, EC_COLOR_FOCUS);
   wdg_set_color(wdg_connections, WDG_COLOR_TITLE, EC_COLOR_TITLE);
   wdg_draw_object(wdg_connections);
 
   wdg_set_focus(wdg_connections);

   /* set the list print callback */
   wdg_dynlist_print_callback(wdg_connections, conntrack_print);
   
   /* set the select callback */
   //wdg_dynlist_select_callback(wdg_connections, curses_profile_detail);
  
   /* add the callback on idle to refresh the profile list */
   wdg_add_idle_callback(refresh_connections);

   /* add the destroy callback */
   wdg_add_destroy_key(wdg_connections, CTRL('Q'), curses_kill_connections);

   //wdg_dynlist_add_callback(wdg_connections, 'l', curses_profiles_local);
   //wdg_dynlist_add_callback(wdg_connections, 'r', curses_profiles_remote);
   //wdg_dynlist_add_callback(wdg_connections, 'c', curses_profiles_convert);
}

static void curses_kill_connections(void)
{
   DEBUG_MSG("curses_kill_connections");
   wdg_del_idle_callback(refresh_connections);

   /* the object does not exist anymore */
   wdg_connections = NULL;
}

static void refresh_connections(void)
{
   /* if not focused don't refresh it */
   if (!(wdg_connections->flags & WDG_OBJ_FOCUSED))
      return;
   
   wdg_dynlist_refresh(wdg_connections);
}

/* EOF */

// vim:ts=3:expandtab

