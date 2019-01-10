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

*/

#include <ec.h>
#include <ec_gtk3.h>
#include <ec_version.h>

/* globals */
#define ENABLED "true"
#define DISABLED "false"

/* proto */
static void toggle_sniffing(GtkToggleButton *button, gpointer data);
static void scanbutton_clicked(GtkButton *button, gpointer data);
static void hostlistbutton_clicked(GtkButton *button, gpointer data);
static void mitmstopbutton_clicked(GtkButton *button, gpointer data);

/*******************************************/


void gtkui_create_menu(GApplication *app, gpointer data)
{
   GtkWidget *header, *menubutton, *logo, *content, *vpaned, *scroll, *box;
   GtkTextIter iter;
   GtkBuilder *builder;
   GMenu *menu;
   gchar *title, *path;
   guint i, live = GPOINTER_TO_INT(data);

   /* accelerators */
   // TODO shortcuts for start/stop sniffing
   static gtkui_accel_map_t app_accels[] = {
#ifndef OS_WINDOWS
      {"app.help", {"F1", NULL}},
#endif
      {"app.quit", {"<Primary>q", "<Primary>x", NULL}}
   };
   static gtkui_accel_map_t targets_accels[] = {
      {"app.current_targets", {"<Primary>t", NULL}},
      {"app.select_targets", {"<Primary><Shift>t", NULL}},
      {"app.set_protocol", {"<Primary>p", NULL}},
      {"app.wipe_targets", {"<Primary>w", NULL}}
   };
   static gtkui_accel_map_t hosts_accels[] = {
      {"app.hosts_list", {"<Primary>h", NULL}},
      {"app.scan_hosts", {"<Primary>s", NULL}}
   };
   static gtkui_accel_map_t view_accels[] = {
      {"app.view_connections", {"<Primary><Shift>c", NULL}},
      {"app.view_profiles", {"<Primary>o", NULL}},
      {"app.visualization_method", {"<Primary><Shift>v", NULL}},
      {"app.visualization_regex", {"<Primary>r", NULL}}
   };
   static gtkui_accel_map_t filter_accels[] = {
      {"app.filter_load", {"<Primary>f", NULL}},
      {"app.filter_stop", {"<Primary><Shift>f", NULL}}
   };
   static gtkui_accel_map_t logging_accels[] = {
      {"app.log_all", {"<Primary><Shift>i", NULL}},
      {"app.log_info", {"<Primary>i", NULL}},
      {"app.log_msg", {"<Primary>m", NULL}}
   };
#ifdef HAVE_PLUGINS
   static gtkui_accel_map_t plugins_accels[] = {
      {"app.plugin_manage", {"<Primary>p", NULL}}
   };
#endif

   /* actions */
   static GActionEntry app_actions[] = {
      /* app menu */
      {"about", gtkui_about, NULL, NULL, NULL, {}},
      {"shortcuts", gtkui_show_shortcuts, "s", NULL, NULL, {}},
#ifndef OS_WINDOWS
      {"help",  gtkui_help, NULL, NULL, NULL, {}},
#endif
      {"quit",  gtkui_exit, NULL, NULL, NULL, {}}
   };
   static GActionEntry targets_actions[] = {
      /* targets menu */
      {"current_targets",  gtkui_current_targets, NULL, NULL, NULL, {}},
      {"select_targets",  gtkui_select_targets, NULL, NULL, NULL, {}},
      {"set_protocol",  gtkui_select_protocol, NULL, NULL, NULL, {}},
      {"reverse_matching",  NULL, NULL, DISABLED, toggle_reverse, {}},
      {"wipe_targets",  wipe_targets, NULL, NULL, NULL, {}}
   };
   static GActionEntry hosts_actions[] = {
      /* hosts menu */
      {"hosts_list",  gtkui_host_list, NULL, NULL, NULL, {}},
#ifdef WITH_IPV6
      {"enable_ipv6scan",  NULL, NULL, DISABLED, toggle_ip6scan, {}},
#endif
      {"scan_hosts",  gtkui_scan, NULL, NULL, NULL, {}},
      {"load_hosts",  gtkui_load_hosts, NULL, NULL, NULL, {}},
      {"save_hosts",  gtkui_save_hosts, NULL, NULL, NULL, {}}
   };
   static GActionEntry view_actions[] = {
      /* view menu */
      {"view_connections",  gtkui_show_connections, NULL, NULL, NULL, {}},
      {"view_profiles",  gtkui_show_profiles, NULL, NULL, NULL, {}},
      {"view_statistics",  gtkui_show_stats, NULL, NULL, NULL, {}},
      {"resolve_ipaddresses",  NULL, NULL, DISABLED, toggle_resolve, {}},
      {"visualization_method",  gtkui_vis_method, NULL, NULL, NULL, {}},
      {"visualization_regex",  gtkui_vis_regex, NULL, NULL, NULL, {}},
      {"wifi_key",  gtkui_wifi_key, NULL, NULL, NULL, {}}
   };
   static GActionEntry mitm_actions[] = {
      /* MITM menu */
      {"arp_poisoning",  gtkui_arp_poisoning, NULL, NULL, NULL, {}},
#ifdef WITH_IPV6
      {"ndp_poisoning",  gtkui_ndp_poisoning, NULL, NULL, NULL, {}},
#endif
      {"icmp_redirect",  gtkui_icmp_redir, NULL, NULL, NULL, {}},
      {"port_stealing",  gtkui_port_stealing, NULL, NULL, NULL, {}},
      {"dhcp_spoofing",  gtkui_dhcp_spoofing, NULL, NULL, NULL, {}},
      {"mitm_stop",  gtkui_mitm_stop, NULL, NULL, NULL, {}},
      {"sslredir",  gtkui_sslredir_show, NULL, NULL, NULL, {}}
   };
   static GActionEntry filter_actions[] = {
      /* filters menu */
      {"filter_load",  gtkui_load_filter, NULL, NULL, NULL, {}},
      {"filter_stop",  gtkui_stop_filter, NULL, NULL, NULL, {}}
   };
   static GActionEntry logging_actions[] = {
      /* logging menu */
      {"log_all",  gtkui_log_all, NULL, NULL, NULL, {}},
      {"log_info",  gtkui_log_info, NULL, NULL, NULL, {}},
      {"log_stop",  gtkui_stop_log, NULL, NULL, NULL, {}},
      {"log_msg",  gtkui_log_msg, NULL, NULL, NULL, {}},
      {"log_stop_msg",  gtkui_stop_msg, NULL, NULL, NULL, {}},
      {"log_compress",  NULL, NULL, DISABLED, toggle_compress, {}}
   };
#ifdef HAVE_PLUGINS
   static GActionEntry plugins_actions[] = {
      /* plugins menu */
      {"plugin_manage",  gtkui_plugin_mgmt, NULL, NULL, NULL, {}},
      {"plugin_load",  gtkui_plugin_load, NULL, NULL, NULL, {}}
   };
#endif

   DEBUG_MSG("gtkui_create_menu - live: %d", live);

   /* honor CLI options */
   if (EC_GBL_OPTIONS->reversed)
      targets_actions[3].state = ENABLED;

   if (EC_GBL_OPTIONS->resolve)
      view_actions[3].state = ENABLED;

   if (EC_GBL_OPTIONS->compress)
      logging_actions[5].state = ENABLED;

#ifdef WITH_IPV6
   if (EC_GBL_OPTIONS->ip6scan)
      hosts_actions[1].state = ENABLED;
#endif

   /* add actions to the application */
   g_action_map_add_action_entries(G_ACTION_MAP(app), app_actions,
         G_N_ELEMENTS(app_actions), app);

   g_action_map_add_action_entries(G_ACTION_MAP(app), targets_actions,
         G_N_ELEMENTS(targets_actions), app);

   /* some things doesn't apply when in bridge mode */
   if (live == 1 && EC_GBL_SNIFF->type == SM_UNIFIED)
      g_action_map_add_action_entries(G_ACTION_MAP(app), hosts_actions,
            G_N_ELEMENTS(hosts_actions), app);

   g_action_map_add_action_entries(G_ACTION_MAP(app), view_actions,
         G_N_ELEMENTS(view_actions), app);

   /* some things doesn't apply when in bridge mode */
   if (live == 1 && EC_GBL_SNIFF->type == SM_UNIFIED)
      g_action_map_add_action_entries(G_ACTION_MAP(app), mitm_actions,
            G_N_ELEMENTS(mitm_actions), app);

   g_action_map_add_action_entries(G_ACTION_MAP(app), filter_actions,
         G_N_ELEMENTS(filter_actions), app);

   g_action_map_add_action_entries(G_ACTION_MAP(app), logging_actions,
         G_N_ELEMENTS(logging_actions), app);

#ifdef HAVE_PLUGINS
   g_action_map_add_action_entries(G_ACTION_MAP(app), plugins_actions,
         G_N_ELEMENTS(plugins_actions), app);
#endif

   /* map accelerators to actions */
   for (i=0; i < G_N_ELEMENTS(app_accels); i++)
      gtk_application_set_accels_for_action(GTK_APPLICATION(app),
            app_accels[i].action, app_accels[i].accel);

   for (i=0; i < G_N_ELEMENTS(targets_accels); i++)
      gtk_application_set_accels_for_action(GTK_APPLICATION(app),
            targets_accels[i].action, targets_accels[i].accel);

   /* some things doesn't apply when in bridge mode */
   if (live == 1 && EC_GBL_SNIFF->type == SM_UNIFIED)
      for (i=0; i < G_N_ELEMENTS(hosts_accels); i++)
         gtk_application_set_accels_for_action(GTK_APPLICATION(app),
               hosts_accels[i].action, hosts_accels[i].accel);

   for (i=0; i < G_N_ELEMENTS(view_accels); i++)
      gtk_application_set_accels_for_action(GTK_APPLICATION(app),
            view_accels[i].action, view_accels[i].accel);

   for (i=0; i < G_N_ELEMENTS(filter_accels); i++)
      gtk_application_set_accels_for_action(GTK_APPLICATION(app),
            filter_accels[i].action, filter_accels[i].accel);

   for (i=0; i < G_N_ELEMENTS(logging_accels); i++)
      gtk_application_set_accels_for_action(GTK_APPLICATION(app),
            logging_accels[i].action, logging_accels[i].accel);

#ifdef HAVE_PLUGINS
   for (i=0; i < G_N_ELEMENTS(plugins_accels); i++)
      gtk_application_set_accels_for_action(GTK_APPLICATION(app),
            plugins_accels[i].action, plugins_accels[i].accel);
#endif


   /* menu structures */
   builder = gtk_builder_new();
   gtk_builder_add_from_string(builder,
         "<interface>"
         "  <menu id='app-menu'>"
         "    <section>"
#ifndef OS_WINDOWS
         "      <item>"
         "        <attribute name='label' translatable='yes'>Help</attribute>"
         "        <attribute name='action'>app.help</attribute>"
         "        <attribute name='icon'>help-browser</attribute>"
         "      </item>"
#endif
         "      <item>"
         "        <attribute name='label' translatable='yes'>Shortcuts</attribute>"
         "        <attribute name='action'>app.shortcuts</attribute>"
         "        <attribute name='target'>main-shortcuts</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>_About Ettercap</attribute>"
         "        <attribute name='action'>app.about</attribute>"
         "        <attribute name='icon'>help-about</attribute>"
         "      </item>"
         "    </section>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>_Quit</attribute>"
         "        <attribute name='action'>app.quit</attribute>"
         "        <attribute name='icon'>application-exit</attribute>"
         "      </item>"
         "    </section>"
         "  </menu>"

         "  <menu id='ettercap-menu'>"
         "    <submenu id='targets-menu'>"
         "      <attribute name='label' translatable='yes'>_Targets</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Current targets</attribute>"
         "          <attribute name='action'>app.current_targets</attribute>"
         "          <attribute name='icon'>edit-find</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Select targets</attribute>"
         "          <attribute name='action'>app.select_targets</attribute>"
         "          <attribute name='icon'>list-add</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>_Protocol</attribute>"
         "          <attribute name='action'>app.set_protocol</attribute>"
         "          <attribute name='icon'>go-jump</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Reverse matching</attribute>"
         "          <attribute name='action'>app.reverse_matching</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>_Wipe targets</attribute>"
         "          <attribute name='action'>app.wipe_targets</attribute>"
         "          <attribute name='icon'>edit-clear</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"

         "    <submenu id='hosts-menu'>"
         "      <attribute name='label' translatable='yes'>_Hosts</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>_Hosts list</attribute>"
         "          <attribute name='action'>app.hosts_list</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
#ifdef WITH_IPV6
         "        <item>"
         "          <attribute name='label' translatable='yes'>Enable IPv6 Scan</attribute>"
         "          <attribute name='action'>app.enable_ipv6scan</attribute>"
         "        </item>"
#endif
         "        <item>"
         "          <attribute name='label' translatable='yes'>_Scan for hosts</attribute>"
         "          <attribute name='action'>app.scan_hosts</attribute>"
         "          <attribute name='icon'>edit-find</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Load hosts from file ...</attribute>"
         "          <attribute name='action'>app.load_hosts</attribute>"
         "          <attribute name='icon'>document-open</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Save hosts to file ...</attribute>"
         "          <attribute name='action'>app.save_hosts</attribute>"
         "          <attribute name='icon'>document-save</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"

         "    <submenu id='view-menu'>"
         "      <attribute name='label' translatable='yes'>_View</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>_Connections</attribute>"
         "          <attribute name='action'>app.view_connections</attribute>"
         "          <attribute name='icon'>format-justify-fill</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Pr_ofiles</attribute>"
         "          <attribute name='action'>app.view_profiles</attribute>"
         "          <attribute name='icon'>format-justify-left</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>_Statistics</attribute>"
         "          <attribute name='action'>app.view_statistics</attribute>"
         "          <attribute name='icon'>document-properties</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Resolve IP addresses</attribute>"
         "          <attribute name='action'>app.resolve_ipaddresses</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>_Visualization method...</attribute>"
         "          <attribute name='action'>app.visualization_method</attribute>"
         "          <attribute name='icon'>preferences-system</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Visualization _regex...</attribute>"
         "          <attribute name='action'>app.visualization_regex</attribute>"
         "          <attribute name='icon'>edit-find</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Set the _WiFi key...</attribute>"
         "          <attribute name='action'>app.wifi_key</attribute>"
         "          <attribute name='icon'>edit-find</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"

         "    <submenu id='filters-menu'>"
         "      <attribute name='label' translatable='yes'>_Filters</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Load a filter...</attribute>"
         "          <attribute name='action'>app.filter_load</attribute>"
         "          <attribute name='icon'>document-open</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Stop _filtering</attribute>"
         "          <attribute name='action'>app.filter_stop</attribute>"
         "          <attribute name='icon'>process-stop</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"

         "    <submenu id='logging-menu'>"
         "      <attribute name='label' translatable='yes'>_Logging</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Logging all packets and infos</attribute>"
         "          <attribute name='action'>app.log_all</attribute>"
         "          <attribute name='icon'>document-save</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Logging only infos</attribute>"
         "          <attribute name='action'>app.log_info</attribute>"
         "          <attribute name='icon'>document-save-as</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Stop logging infos</attribute>"
         "          <attribute name='action'>app.log_stop</attribute>"
         "          <attribute name='icon'>process-stop</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Log user messages</attribute>"
         "          <attribute name='action'>app.log_msg</attribute>"
         "          <attribute name='icon'>document-revert</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Stop logging messages</attribute>"
         "          <attribute name='action'>app.log_stop_msg</attribute>"
         "          <attribute name='icon'>process-stop</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Compressed logfile</attribute>"
         "          <attribute name='action'>app.log_compress</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"

#ifdef HAVE_PLUGINS
         "    <submenu id='plugins-menu'>"
         "      <attribute name='label' translatable='yes'>_Plugins</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Manage plugins</attribute>"
         "          <attribute name='action'>app.plugin_manage</attribute>"
         "          <attribute name='icon'>system-run</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Load a plugin...</attribute>"
         "          <attribute name='action'>app.plugin_load</attribute>"
         "          <attribute name='icon'>document-open</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"
#endif
         "  </menu>"
         "  <menu id='mitm-menu'>"
         "    <section>"
         "      <attribute name='label' translatable='no'>MITM</attribute>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>ARP poisoning...</attribute>"
         "        <attribute name='action'>app.arp_poisoning</attribute>"
         "      </item>"
#ifdef WITH_IPV6
         "      <item>"
         "        <attribute name='label' translatable='yes'>NDP poisoning</attribute>"
         "        <attribute name='action'>app.ndp_poisoning</attribute>"
         "      </item>"
#endif
         "      <item>"
         "        <attribute name='label' translatable='yes'>ICMP redirect...</attribute>"
         "        <attribute name='action'>app.icmp_redirect</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Port stealing...</attribute>"
         "        <attribute name='action'>app.port_stealing</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>DHCP spoofing...</attribute>"
         "        <attribute name='action'>app.dhcp_spoofing</attribute>"
         "      </item>"
         "    </section>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Stop MITM attack(s)</attribute>"
         "        <attribute name='action'>app.mitm_stop</attribute>"
         "      </item>"
         "    </section>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>SSL Intercept</attribute>"
         "        <attribute name='action'>app.sslredir</attribute>"
         "      </item>"
         "    </section>"
         "  </menu>"

         "</interface>", -1, NULL);

   /* set app menu */
   gtk_application_set_app_menu(GTK_APPLICATION(app),
         G_MENU_MODEL(gtk_builder_get_object(builder, "app-menu")));

   if (g_getenv("APP_MENU_FALLBACK"))
      g_object_set(gtk_settings_get_default(), "gtk-shell-shows-app-menu", FALSE, NULL);


   /* Adjust titel formatting */
   title = g_strdup(PROGRAM);
   *title = g_ascii_toupper(*title);


   /* reuse main window */
   gtk_application_add_window(GTK_APPLICATION(app), GTK_WINDOW(window));
   
   /* create header bar and menubuttons */
   header = gtk_header_bar_new();
   gtk_header_bar_set_title(GTK_HEADER_BAR(header), title);
   gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), EC_VERSION " (EB)");
   gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
   gtk_window_set_titlebar(GTK_WINDOW(window), header);

   /* start/stop sniffing button */
   menubutton = gtk_toggle_button_new();
   gtk_widget_set_tooltip_text(menubutton, "Start / Stop Sniffing");
   if (EC_GBL_CONF->sniffing_at_startup) {
      gtk_button_set_image(GTK_BUTTON(menubutton), 
            gtk_image_new_from_icon_name("media-playback-stop-symbolic", GTK_ICON_SIZE_BUTTON));
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(menubutton), TRUE);
   }
   else
      gtk_button_set_image(GTK_BUTTON(menubutton), 
            gtk_image_new_from_icon_name("media-playback-start-symbolic", GTK_ICON_SIZE_BUTTON));
   gtk_header_bar_pack_start(GTK_HEADER_BAR(header), menubutton);
   g_signal_connect(G_OBJECT(menubutton), "toggled", G_CALLBACK(toggle_sniffing), NULL);

   /* menu button for Ettercap menu */
   menubutton = gtk_menu_button_new();
   menu = G_MENU(gtk_builder_get_object(builder, "ettercap-menu"));
   gtk_widget_set_tooltip_text(menubutton, "Ettercap Menu");
   if (live == 0 || EC_GBL_SNIFF->type == SM_BRIDGED)
      g_menu_remove(menu, 1); // Remove Hosts Menu
   gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(menubutton), G_MENU_MODEL(menu));
   gtk_button_set_image(GTK_BUTTON(menubutton),
         gtk_image_new_from_icon_name("open-menu-symbolic", GTK_ICON_SIZE_BUTTON));
   gtk_header_bar_pack_end(GTK_HEADER_BAR(header), menubutton);


   /* some things doesn't apply when in bridge mode */
   if (live == 1 && EC_GBL_SNIFF->type == SM_UNIFIED) {
      /* button for host scan */
      menubutton = gtk_button_new();
      gtk_widget_set_tooltip_text(menubutton, "Scan for hosts");
      gtk_button_set_image(GTK_BUTTON(menubutton),
            gtk_image_new_from_icon_name("edit-find-symbolic", GTK_ICON_SIZE_BUTTON));
      gtk_header_bar_pack_start(GTK_HEADER_BAR(header), menubutton);
      g_signal_connect(G_OBJECT(menubutton), "clicked", G_CALLBACK(scanbutton_clicked), NULL);

      /* menu button for hosts menu */
      menubutton = gtk_button_new();
      gtk_widget_set_tooltip_text(menubutton, "Hosts List");
      gtk_button_set_image(GTK_BUTTON(menubutton),
            gtk_image_new_from_icon_name("network-server-symbolic", GTK_ICON_SIZE_BUTTON));
      gtk_header_bar_pack_start(GTK_HEADER_BAR(header), menubutton);
      g_signal_connect(G_OBJECT(menubutton), "clicked", G_CALLBACK(hostlistbutton_clicked), NULL);


      /* menu button to stop MITM */
      menubutton = gtk_button_new();
      gtk_widget_set_tooltip_text(menubutton, "Stop MITM");
      gtk_button_set_image(GTK_BUTTON(menubutton),
            gtk_image_new_from_icon_name("process-stop-symbolic", GTK_ICON_SIZE_BUTTON));
      gtk_header_bar_pack_end(GTK_HEADER_BAR(header), menubutton);
      g_signal_connect(G_OBJECT(menubutton), "clicked", G_CALLBACK(mitmstopbutton_clicked), NULL);

      /* menu button for MITM menu */
      menubutton = gtk_menu_button_new();
      gtk_widget_set_tooltip_text(menubutton, "MITM menu");
      gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(menubutton),
            G_MENU_MODEL(gtk_builder_get_object(builder, "mitm-menu")));
      gtk_button_set_image(GTK_BUTTON(menubutton),
            gtk_image_new_from_icon_name("network-workgroup-symbolic", GTK_ICON_SIZE_BUTTON));
      gtk_header_bar_pack_end(GTK_HEADER_BAR(header), menubutton);

   }


   /* fetch and replace main content area */
   content = gtk_bin_get_child(GTK_BIN(window));
   gtk_container_remove(GTK_CONTAINER(window), content);

   box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_container_add(GTK_CONTAINER(window), box);

   /* prepare infobar for later notifications */
   infobar = gtk_info_bar_new();
   gtk_widget_set_no_show_all(infobar, TRUE);
   infolabel = gtk_label_new("");
   gtk_widget_show(infolabel);
   gtk_container_add(GTK_CONTAINER(
            gtk_info_bar_get_content_area(GTK_INFO_BAR(infobar))), infolabel);
   gtk_info_bar_add_button(GTK_INFO_BAR(infobar), "_OK", GTK_RESPONSE_OK);
   infoframe = gtk_frame_new(NULL);
   gtk_widget_set_no_show_all(infoframe, TRUE);
   gtk_frame_set_shadow_type(GTK_FRAME(infoframe), GTK_SHADOW_NONE);
   gtk_container_add(GTK_CONTAINER(infoframe), infobar);
   g_signal_connect(G_OBJECT(infobar), "response", G_CALLBACK(gtkui_infobar_hide), NULL);
   gtk_box_pack_start(GTK_BOX(box), infoframe, FALSE, FALSE, 0);

   vpaned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
   gtk_box_pack_start(GTK_BOX(box), vpaned, TRUE, TRUE, 0);

   notebook_frame = gtk_frame_new(NULL);
   gtk_frame_set_shadow_type(GTK_FRAME(notebook_frame), GTK_SHADOW_IN);
   gtk_paned_pack1(GTK_PANED(vpaned), notebook_frame, TRUE, TRUE);
   
   path = INSTALL_DATADIR "/" PROGRAM "/" LOGO_FILE;
   if(g_file_test(path, G_FILE_TEST_EXISTS))
      logo = gtk_image_new_from_file(path);
   else /* if neither path is valid gtk will use a broken image icon */
      logo = gtk_image_new_from_file("./share/" LOGO_FILE);

   gtk_widget_set_halign(logo, GTK_ALIGN_CENTER);
   gtk_widget_set_valign(logo, GTK_ALIGN_CENTER);
   gtk_container_add(GTK_CONTAINER(notebook_frame), logo);
 
   /* messages */
   scroll = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scroll),
                                  GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);
   gtk_widget_set_size_request(scroll, -1, 140);
   gtk_paned_pack2(GTK_PANED (vpaned), scroll, FALSE, TRUE);
   gtk_widget_show(scroll);

   textview = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (textview), GTK_WRAP_WORD_CHAR);
   gtk_text_view_set_editable(GTK_TEXT_VIEW (textview), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview), FALSE);
   gtk_container_add(GTK_CONTAINER (scroll), textview);
   gtk_widget_show(textview);

   msgbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW (textview));
   gtk_text_buffer_get_end_iter(msgbuffer, &iter);
   endmark = gtk_text_buffer_create_mark(msgbuffer, "end", &iter, FALSE);

 

   gtk_widget_show_all(window);

}

void gtkui_create_tab_menu(void)
{
   GtkWidget *context;
   GtkBuilder *builder;
   GSimpleActionGroup *actiongroup;
   guint i;

   static GActionEntry tab_actions[] = {
      {"detach_page", gtkui_page_detach_current, NULL, NULL, NULL, {}},
      {"close_page",  gtkui_page_close_current, NULL, NULL, NULL, {}},
      {"next_page",   gtkui_page_right, NULL, NULL, NULL, {}},
      {"prev_page",   gtkui_page_left, NULL, NULL, NULL, {}}
   };

   static gtkui_accel_map_t tab_accels[] = {
      {"tab.detach_page", {"<Primary>d", NULL}},
      {"tab.close_page", {"<Primary>w", NULL}},
      {"tab.next_page", {"<Primary>Tab", "<Primary>Right", NULL}},
      {"tab.prev_page", {"<Primary><Shift>Tab", "<Primary>Left", NULL}}
   };

   /* build menu structure */
   builder = gtk_builder_new();
   gtk_builder_add_from_string(builder,
         "<interface>"
         "  <menu id='tab-menu'>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Detach page</attribute>"
         "        <attribute name='action'>tab.detach_page</attribute>"
         "        <attribute name='icon'>go-up</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Close page</attribute>"
         "        <attribute name='action'>tab.close_page</attribute>"
         "        <attribute name='icon'>window-close</attribute>"
         "      </item>"
         "    </section>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Next page</attribute>"
         "        <attribute name='action'>tab.next_page</attribute>"
         "        <attribute name='icon'>go-next</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Previous page</attribute>"
         "        <attribute name='action'>tab.prev_page</attribute>"
         "        <attribute name='icon'>go-previous</attribute>"
         "      </item>"
         "    </section>"
         "  </menu>"
         "</interface>", -1, NULL);

   /* create dedicated action group and attach to menu widget */
   actiongroup = g_simple_action_group_new();
   g_action_map_add_action_entries(G_ACTION_MAP(actiongroup), tab_actions,
         G_N_ELEMENTS(tab_actions), NULL);

   /* map accelerators to actions */ // FIXME doesn't work yet
   for (i = 0; i < G_N_ELEMENTS(tab_accels); i++)
      gtk_application_set_accels_for_action(GTK_APPLICATION(etterapp),
            tab_accels[i].action, tab_accels[i].accel);

   /* connect tab menu to right-click handler of notebook */
   context = gtk_menu_new_from_model(G_MENU_MODEL(gtk_builder_get_object(builder, "tab-menu")));
   gtk_widget_insert_action_group(context, "tab", G_ACTION_GROUP(actiongroup));
   g_signal_connect(G_OBJECT(notebook), "button-press-event", G_CALLBACK(gtkui_context_menu), context);

   g_object_unref(builder);

}

/*
 * callback to start and stop sniffing and swaping play-button
 */
static void toggle_sniffing(GtkToggleButton *button, gpointer data)
{
   (void) data;
   if (gtk_toggle_button_get_active(button)) {
      /* start sniffing */
      gtkui_start_sniffing();
      /* replace button image with stop icon */
      gtk_button_set_image(GTK_BUTTON(button),
            gtk_image_new_from_icon_name("media-playback-stop-symbolic",
               GTK_ICON_SIZE_BUTTON));
   }
   else  {
      /* stop sniffing */
      gtkui_stop_sniffing();
      /* replace button image with start icon */
      gtk_button_set_image(GTK_BUTTON(button),
            gtk_image_new_from_icon_name("media-playback-start-symbolic", 
               GTK_ICON_SIZE_BUTTON));
   }
}


/*
 * callback when scan button is clicked
 * - wrapper due to different callback function signatures
 */
static void scanbutton_clicked(GtkButton *button, gpointer data)
{
   (void) button;
   (void) data;

   gtkui_scan(NULL, NULL, NULL);
}


/*
 * callback when hostlist button is clicked
 * - wrapper due to different callback function signatures
 */
static void hostlistbutton_clicked(GtkButton *button, gpointer data)
{
   (void) button;
   (void) data;

   gtkui_host_list(NULL, NULL, NULL);
}

/*
 * callback when scan button is clicked
 * - wrapper due to different callback function signatures
 */
static void mitmstopbutton_clicked(GtkButton *button, gpointer data)
{
   (void) button;
   (void) data;

   gtkui_mitm_stop(NULL, NULL, NULL);
}



/* EOF */

// vim:ts=3:expandtab

