/*
    ettercap -- GTK+ GUI

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

    $Id: ec_gtk_menus.c,v 1.1 2004/02/27 03:34:33 daten Exp $
*/

#include <ec.h>
#include <ec_gtk.h>

/* globals */

GtkItemFactoryEntry gmenu_start[] = {
   {"/_Start",                NULL,          NULL,               0, "<Branch>" },
   {"/Start/Start sniffing",  "<control>w",  gui_start_sniffing, 0, "<Item>" },
   {"/Start/Stop sniffing",   "<control>e",  gui_stop_sniffing,  0, "<Item>" },
   {"/Start/sep1",            NULL,          NULL,               0, "<Separator>" },
   {"/Start/E_xit",           "<control>x",  gtk_main_quit,      0, "<Item>" }
};

GtkItemFactoryEntry gmenu_targets[] = {
   {"/_Targets",                 NULL,          NULL,                0, "<Branch>" },
   {"/Targets/Current _Targets", "t",           gui_current_targets, 0, "<Item>" },
   {"/Targets/Select TARGET(s)", "<control>t",  gui_select_targets,  0, "<Item>" },
   {"/Targets/sep1",             NULL,          NULL,                0, "<Separator>" },
   {"/Targets/_Protocol...",     "p",           gui_select_protocol, 0, "<Item>" },
   {"/Targets/Reverse matching", NULL,          toggle_reverse,      0, "<ToggleItem>" },
   {"/Targets/sep2",             NULL,          NULL,                0, "<Separator>" },
   {"/Targets/_Wipe targets",    "W",           wipe_targets,        0, "<Item>" }
};

GtkItemFactoryEntry gmenu_hosts[] = {
   {"/_Hosts",                  NULL,         NULL,           0, "<Branch>" },
   {"/Hosts/_Hosts list",       "h",          gui_host_list,  0, "<Item>" },
   {"/Hosts/sep1",              NULL,         NULL,           0, "<Separator>" },
   {"/Hosts/_Scan for hosts",   "<control>s", gui_scan,       0, "<Item>" },
   {"/Hosts/Load from file...", NULL,         gui_load_hosts, 0, "<Item>" },
   {"/Hosts/Save to file...",   NULL,         gui_save_hosts, 0, "<Item>" }
};

GtkItemFactoryEntry gmenu_view[] = {
   {"/_View",                        NULL, NULL,                 0, "<Branch>" },
   {"/View/_Connections",            "C", gui_show_connections, 0, "<Item>" },
   {"/View/Pr_ofiles",               "O", gui_show_profiles,    0, "<Item>" },
   {"/View/_Statistics",             "s", gui_show_stats,       0, "<Item>" },
   {"/View/sep1",                    NULL, NULL,                 0, "<Separator>" },
   {"/View/Resolve IP addresses",    NULL, toggle_resolve,       0, "<ToggleItem>" },
   {"/View/_Visualization method...","v",gui_vis_method,0, "<Item>" }
};

GtkItemFactoryEntry gmenu_mitm[] = {
   {"/_Mitm",                    NULL, NULL,              0, "<Branch>" },
   {"/Mitm/Arp poisoning...",    NULL, gui_arp_poisoning, 0, "<Item>" },
   {"/Mitm/Icmp redirect...",    NULL, gui_icmp_redir,    0, "<Item>" },
   {"/Mitm/Port stealing...",    NULL, gui_port_stealing, 0, "<Item>" },
   {"/Mitm/Dhcp spoofing...",    NULL, gui_dhcp_spoofing, 0, "<Item>" },
   {"/Mitm/sep1",                NULL, NULL,              0, "<Separator>" },
   {"/Mitm/Stop mitm attack(s)", NULL, gui_mitm_stop,     0, "<Item>" }
};

GtkItemFactoryEntry gmenu_filters[] = {
   {"/_Filters",                 NULL,         NULL,            0, "<Branch>" },
   {"/Filters/Load a filter...", "<control>f", gui_load_filter, 0, "<Item>" },
   {"/Filters/Stop _filtering",  "f",          gui_stop_filter, 0, "<Item>" }
};

GtkItemFactoryEntry gmenu_logging[] = {
   {"/_Logging",                             NULL, NULL,            0, "<Branch>" },
   {"/Logging/Log all packets and infos...", "I",  gui_log_all,     0, "<Item>" },
   {"/Logging/Log only infos...",   "<control>i",  gui_log_info,    0, "<Item>" },
   {"/Logging/Stop logging infos",           NULL, gui_stop_log,    0, "<Item>" },
   {"/Logging/sep1",                         NULL, NULL,            0, "<Separator>" },
   {"/Logging/Log user messages...",         "m",  gui_log_msg,     0, "<Item>" },
   {"/Logging/Stop logging messages",        NULL, gui_stop_msg,    0, "<Item>" },
   {"/Logging/sep2",                         NULL, NULL,            0, "<Separator>" },
   {"/Logging/Compressed file",              NULL, toggle_compress, 0, "<ToggleItem>" }
};

GtkItemFactoryEntry gmenu_plugins[] = {
   {"/_Plugins",                   NULL,         NULL,            0, "<Branch>" },
   {"/Plugins/Manage the plugins", "<control>p", gui_plugin_mgmt, 0, "<Item>" },
   {"/Plugins/Load a plugin...",   NULL,         gui_plugin_load, 0, "<Item>" }
};

/* proto */

void gui_create_menu(int live);


/*******************************************/


void gui_create_menu(int live)
{
   GtkAccelGroup *accel_group;
   GtkWidget *vbox;
   GtkItemFactory *root_menu;
   int num_items = 0;
   
   DEBUG_MSG("gtk_create_menu");

   /* remove old menu, it will be automatically destroyed by gtk_main */
   vbox = gtk_bin_get_child(GTK_BIN (window));
   gtk_container_remove(GTK_CONTAINER (vbox), main_menu);

   /* Prepare to generate menus from the definitions in ec_gtk.h */
   accel_group = gtk_accel_group_new ();
   root_menu = gtk_item_factory_new (GTK_TYPE_MENU_BAR, "<main>", accel_group);
   gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);
   
   /* Start Menu */
   num_items = sizeof (gmenu_start) / sizeof (gmenu_start[0]);
   gtk_item_factory_create_items (root_menu, num_items, gmenu_start, NULL);
   
   /* Targets Menu */
   num_items = sizeof (gmenu_targets) / sizeof (gmenu_targets[0]);
   gtk_item_factory_create_items (root_menu, num_items, gmenu_targets, NULL);
   
   /* Hosts Menu */
   if (live > 0 && GBL_SNIFF->type != SM_BRIDGED) {
      num_items = sizeof (gmenu_hosts) / sizeof (gmenu_hosts[0]);
      gtk_item_factory_create_items (root_menu, num_items, gmenu_hosts, NULL);
   }
   
   /* View Menu */
   num_items = sizeof (gmenu_view) / sizeof (gmenu_view[0]);
   gtk_item_factory_create_items (root_menu, num_items, gmenu_view, NULL);
   
   /* MITM Menu */
   if (live > 0 && GBL_SNIFF->type != SM_BRIDGED) {
      num_items = sizeof (gmenu_mitm) / sizeof (gmenu_mitm[0]);
      gtk_item_factory_create_items (root_menu, num_items, gmenu_mitm, NULL);
   }
   
   /* Filters Menu */
   num_items = sizeof (gmenu_filters) / sizeof (gmenu_filters[0]);
   gtk_item_factory_create_items (root_menu, num_items, gmenu_filters, NULL);
   
   /* Logging Menu */
   num_items = sizeof (gmenu_logging) / sizeof (gmenu_logging[0]);
   gtk_item_factory_create_items (root_menu, num_items, gmenu_logging, NULL);

#ifdef HAVE_PLUGINS
   /* Plugins Menu */
   if(live > 0) {
      num_items = sizeof (gmenu_plugins) / sizeof (gmenu_plugins[0]);
      gtk_item_factory_create_items (root_menu, num_items, gmenu_plugins, NULL);
   }
#endif

   /* get the menu widget and add it to the window */
   main_menu = gtk_item_factory_get_widget (root_menu, "<main>");
   gtk_box_pack_start(GTK_BOX(vbox), main_menu, FALSE, FALSE, 0);
   gtk_widget_show(main_menu);
}


/* EOF */

// vim:ts=3:expandtab

