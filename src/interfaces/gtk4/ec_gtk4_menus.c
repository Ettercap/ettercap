/*
    ettercap -- GTK4 GUI -- menus and the sniffing window's header bar

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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include <ec.h>
#include <ec_gtk4.h>
#include <ec_version.h>

/* globals */
#define ENABLED "true"
#define DISABLED "false"

/* proto */
static void toggle_sniffing(GtkToggleButton *button, gpointer data);
static void scanbutton_clicked(GtkButton *button, gpointer data);
static void hostlistbutton_clicked(GtkButton *button, gpointer data);
static void mitmstopbutton_clicked(GtkButton *button, gpointer data);

/*
 * Menus are built with GMenu, exactly as the GTK3 interface did -- that part
 * needed no porting. What changed:
 *
 *  - gtk_application_set_app_menu() is gone. GNOME retired the shell app menu
 *    and GTK4 removed the API, so its entries are folded into the primary
 *    menu where users now expect to find them.
 *  - GtkHeaderBar has no subtitle in GTK4; AdwWindowTitle carries the
 *    title/subtitle pair instead.
 *  - gtk_button_set_image() is gone -- buttons take an icon name directly.
 *  - The tab context menu no longer needs a GtkMenu and a button-press-event
 *    handler: AdwTabView takes a menu model and handles the gesture itself.
 */

/*******************************************/

void gtkui_create_menu(GApplication *app, gpointer data)
{
   GtkWidget *header, *menubutton, *button, *logo, *box, *vpaned, *scroll;
   GtkWidget *toolbar, *tabbox;
   GtkTextIter iter;
   GtkBuilder *builder;
   GMenu *menu;
   gchar *title, *path;
   guint live = GPOINTER_TO_INT(data);
   gboolean unified;

   /*
    * Accelerators. Each row carries the human-readable title and group used
    * by gtkui_show_shortcuts() to render the shortcuts window, so adding a
    * shortcut here is all that is needed for it to be documented.
    */
   static gtkui_accel_map_t app_accels[] = {
#ifndef OS_WINDOWS
      {"app.help", {"F1", NULL}, "Show the manual page", "General"},
#endif
      {"app.shortcuts", {"<Primary>question", NULL},
         "Show keyboard shortcuts", "General"},
      {"app.quit", {"<Primary>q", "<Primary>x", NULL},
         "Quit ettercap", "General"}
   };
   static gtkui_accel_map_t targets_accels[] = {
      {"app.current_targets", {"<Primary>t", NULL},
         "Show current targets", "Targets"},
      {"app.select_targets", {"<Primary><Shift>t", NULL},
         "Select targets", "Targets"},
      {"app.set_protocol", {"<Primary>p", NULL},
         "Set the protocol", "Targets"},
      {"app.wipe_targets", {"<Primary>w", NULL},
         "Reset targets to ANY", "Targets"}
   };
   static gtkui_accel_map_t hosts_accels[] = {
      {"app.hosts_list", {"<Primary>h", NULL}, "Show the host list", "Hosts"},
      {"app.scan_hosts", {"<Primary>s", NULL}, "Scan for hosts", "Hosts"}
   };
   static gtkui_accel_map_t view_accels[] = {
      {"app.view_connections", {"<Primary><Shift>c", NULL},
         "Show connections", "View"},
      {"app.view_profiles", {"<Primary>o", NULL}, "Show profiles", "View"},
      {"app.visualization_method", {"<Primary><Shift>v", NULL},
         "Set the visualization method", "View"},
      {"app.visualization_regex", {"<Primary>r", NULL},
         "Set the visualization regex", "View"}
   };
   static gtkui_accel_map_t filter_accels[] = {
      {"app.filter_load", {"<Primary>f", NULL}, "Load a filter", "Filters"},
      {"app.filter_stop", {"<Primary><Shift>f", NULL},
         "Stop filtering", "Filters"}
   };
   static gtkui_accel_map_t logging_accels[] = {
      {"app.log_all", {"<Primary><Shift>i", NULL},
         "Log all packets and infos", "Logging"},
      {"app.log_info", {"<Primary>i", NULL}, "Log only infos", "Logging"},
      {"app.log_msg", {"<Primary>m", NULL}, "Log user messages", "Logging"}
   };
#ifdef HAVE_PLUGINS
   static gtkui_accel_map_t plugins_accels[] = {
      /*
       * The GTK3 table bound this to <Primary>p, which app.set_protocol
       * already claimed -- so whichever action GTK resolved last silently
       * won and the other shortcut did nothing. Generating the shortcuts
       * window from this table is what surfaced the clash.
       */
      {"app.plugin_manage", {"<Primary><Shift>p", NULL},
         "Manage plugins", "Plugins"}
   };
#endif

   /* actions */
   static GActionEntry app_actions[] = {
      {"about", gtkui_about, NULL, NULL, NULL, {}},
      {"shortcuts", gtkui_show_shortcuts, NULL, NULL, NULL, {}},
#ifndef OS_WINDOWS
      {"help",  gtkui_help, NULL, NULL, NULL, {}},
#endif
      {"quit",  gtkui_exit, NULL, NULL, NULL, {}}
   };
   static GActionEntry targets_actions[] = {
      {"current_targets",   gtkui_current_targets, NULL, NULL, NULL, {}},
      {"select_targets",    gtkui_select_targets, NULL, NULL, NULL, {}},
      {"set_protocol",      gtkui_select_protocol, NULL, NULL, NULL, {}},
      {"reverse_matching",  NULL, NULL, DISABLED, toggle_reverse, {}},
      {"wipe_targets",      wipe_targets, NULL, NULL, NULL, {}}
   };
   static GActionEntry hosts_actions[] = {
      {"hosts_list",  gtkui_host_list, NULL, NULL, NULL, {}},
#ifdef WITH_IPV6
      {"enable_ipv6scan",  NULL, NULL, DISABLED, toggle_ip6scan, {}},
#endif
      {"scan_hosts",  gtkui_scan, NULL, NULL, NULL, {}},
      {"load_hosts",  gtkui_load_hosts, NULL, NULL, NULL, {}},
      {"save_hosts",  gtkui_save_hosts, NULL, NULL, NULL, {}}
   };
   static GActionEntry view_actions[] = {
      {"view_connections",     gtkui_show_connections, NULL, NULL, NULL, {}},
      {"view_profiles",        gtkui_show_profiles, NULL, NULL, NULL, {}},
      {"view_statistics",      gtkui_show_stats, NULL, NULL, NULL, {}},
      {"resolve_ipaddresses",  NULL, NULL, DISABLED, toggle_resolve, {}},
      {"visualization_method", gtkui_vis_method, NULL, NULL, NULL, {}},
      {"visualization_regex",  gtkui_vis_regex, NULL, NULL, NULL, {}},
      {"wifi_key",             gtkui_wifi_key, NULL, NULL, NULL, {}}
   };
   static GActionEntry mitm_actions[] = {
      {"arp_poisoning",  gtkui_arp_poisoning, NULL, NULL, NULL, {}},
#ifdef WITH_IPV6
      {"ndp_poisoning",  gtkui_ndp_poisoning, NULL, NULL, NULL, {}},
#endif
      {"icmp_redirect",  gtkui_icmp_redir, NULL, NULL, NULL, {}},
      {"port_stealing",  gtkui_port_stealing, NULL, NULL, NULL, {}},
      {"dhcp_spoofing",  gtkui_dhcp_spoofing, NULL, NULL, NULL, {}},
      {"mitm_stop",      gtkui_mitm_stop, NULL, NULL, NULL, {}},
      {"sslredir",       gtkui_sslredir_show, NULL, NULL, NULL, {}}
   };
   static GActionEntry filter_actions[] = {
      {"filter_load",  gtkui_load_filter, NULL, NULL, NULL, {}},
      {"filter_stop",  gtkui_stop_filter, NULL, NULL, NULL, {}}
   };
   static GActionEntry logging_actions[] = {
      {"log_all",       gtkui_log_all, NULL, NULL, NULL, {}},
      {"log_info",      gtkui_log_info, NULL, NULL, NULL, {}},
      {"log_stop",      gtkui_stop_log, NULL, NULL, NULL, {}},
      {"log_msg",       gtkui_log_msg, NULL, NULL, NULL, {}},
      {"log_stop_msg",  gtkui_stop_msg, NULL, NULL, NULL, {}},
      {"log_compress",  NULL, NULL, DISABLED, toggle_compress, {}}
   };
#ifdef HAVE_PLUGINS
   static GActionEntry plugins_actions[] = {
      {"plugin_manage",  gtkui_plugin_mgmt, NULL, NULL, NULL, {}},
      {"plugin_load",    gtkui_plugin_load, NULL, NULL, NULL, {}}
   };
#endif

   DEBUG_MSG("gtkui_create_menu - live: %d", live);

   /* host discovery and MITM do not apply when bridging */
   unified = (live == 1 && EC_GBL_SNIFF->type == SM_UNIFIED);

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
   if (unified)
      g_action_map_add_action_entries(G_ACTION_MAP(app), hosts_actions,
            G_N_ELEMENTS(hosts_actions), app);
   g_action_map_add_action_entries(G_ACTION_MAP(app), view_actions,
         G_N_ELEMENTS(view_actions), app);
   if (unified)
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

   /*
    * Install accelerators. gtkui_install_accels() both binds them and
    * records the table, so the shortcuts window stays in step -- including
    * only offering the Hosts shortcuts when the Hosts actions exist.
    */
   gtkui_install_accels(GTK_APPLICATION(app), app_accels,
         G_N_ELEMENTS(app_accels));
   gtkui_install_accels(GTK_APPLICATION(app), targets_accels,
         G_N_ELEMENTS(targets_accels));
   if (unified)
      gtkui_install_accels(GTK_APPLICATION(app), hosts_accels,
            G_N_ELEMENTS(hosts_accels));
   gtkui_install_accels(GTK_APPLICATION(app), view_accels,
         G_N_ELEMENTS(view_accels));
   gtkui_install_accels(GTK_APPLICATION(app), filter_accels,
         G_N_ELEMENTS(filter_accels));
   gtkui_install_accels(GTK_APPLICATION(app), logging_accels,
         G_N_ELEMENTS(logging_accels));
#ifdef HAVE_PLUGINS
   gtkui_install_accels(GTK_APPLICATION(app), plugins_accels,
         G_N_ELEMENTS(plugins_accels));
#endif

   /* menu structures */
   builder = gtk_builder_new();
   gtk_builder_add_from_string(builder,
         "<interface>"
         "  <menu id='ettercap-menu'>"
         "    <submenu>"
         "      <attribute name='label' translatable='yes'>_Targets</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Current targets</attribute>"
         "          <attribute name='action'>app.current_targets</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Select targets</attribute>"
         "          <attribute name='action'>app.select_targets</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Protocol</attribute>"
         "          <attribute name='action'>app.set_protocol</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Reverse matching</attribute>"
         "          <attribute name='action'>app.reverse_matching</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Wipe targets</attribute>"
         "          <attribute name='action'>app.wipe_targets</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"
         "    <submenu>"
         "      <attribute name='label' translatable='yes'>_Hosts</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Hosts list</attribute>"
         "          <attribute name='action'>app.hosts_list</attribute>"
         "        </item>"
#ifdef WITH_IPV6
         "        <item>"
         "          <attribute name='label' translatable='yes'>Enable IPv6 scan</attribute>"
         "          <attribute name='action'>app.enable_ipv6scan</attribute>"
         "        </item>"
#endif
         "        <item>"
         "          <attribute name='label' translatable='yes'>Scan for hosts</attribute>"
         "          <attribute name='action'>app.scan_hosts</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Load from file</attribute>"
         "          <attribute name='action'>app.load_hosts</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Save to file</attribute>"
         "          <attribute name='action'>app.save_hosts</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"
         "    <submenu>"
         "      <attribute name='label' translatable='yes'>_View</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Connections</attribute>"
         "          <attribute name='action'>app.view_connections</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Profiles</attribute>"
         "          <attribute name='action'>app.view_profiles</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Statistics</attribute>"
         "          <attribute name='action'>app.view_statistics</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Resolve IP addresses</attribute>"
         "          <attribute name='action'>app.resolve_ipaddresses</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Visualization method</attribute>"
         "          <attribute name='action'>app.visualization_method</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Visualization regex</attribute>"
         "          <attribute name='action'>app.visualization_regex</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Set WiFi key</attribute>"
         "          <attribute name='action'>app.wifi_key</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"
         "    <submenu>"
         "      <attribute name='label' translatable='yes'>_Filters</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Load a filter</attribute>"
         "          <attribute name='action'>app.filter_load</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Stop filtering</attribute>"
         "          <attribute name='action'>app.filter_stop</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"
         "    <submenu>"
         "      <attribute name='label' translatable='yes'>_Logging</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Log all packets and infos</attribute>"
         "          <attribute name='action'>app.log_all</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Log only infos</attribute>"
         "          <attribute name='action'>app.log_info</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Stop logging</attribute>"
         "          <attribute name='action'>app.log_stop</attribute>"
         "        </item>"
         "      </section>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Log user messages</attribute>"
         "          <attribute name='action'>app.log_msg</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Stop logging messages</attribute>"
         "          <attribute name='action'>app.log_stop_msg</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Compress log file</attribute>"
         "          <attribute name='action'>app.log_compress</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"
#ifdef HAVE_PLUGINS
         "    <submenu>"
         "      <attribute name='label' translatable='yes'>_Plugins</attribute>"
         "      <section>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Manage plugins</attribute>"
         "          <attribute name='action'>app.plugin_manage</attribute>"
         "        </item>"
         "        <item>"
         "          <attribute name='label' translatable='yes'>Load a plugin</attribute>"
         "          <attribute name='action'>app.plugin_load</attribute>"
         "        </item>"
         "      </section>"
         "    </submenu>"
#endif
         /*
          * GTK4 removed gtk_application_set_app_menu(), so what used to be
          * the shell's app menu becomes the tail of the primary menu.
          */
         "    <section>"
#ifndef OS_WINDOWS
         "      <item>"
         "        <attribute name='label' translatable='yes'>_Help</attribute>"
         "        <attribute name='action'>app.help</attribute>"
         "      </item>"
#endif
         "      <item>"
         "        <attribute name='label' translatable='yes'>_Keyboard Shortcuts</attribute>"
         "        <attribute name='action'>app.shortcuts</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>_About Ettercap</attribute>"
         "        <attribute name='action'>app.about</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>_Quit</attribute>"
         "        <attribute name='action'>app.quit</attribute>"
         "      </item>"
         "    </section>"
         "  </menu>"
         "  <menu id='mitm-menu'>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>ARP poisoning</attribute>"
         "        <attribute name='action'>app.arp_poisoning</attribute>"
         "      </item>"
#ifdef WITH_IPV6
         "      <item>"
         "        <attribute name='label' translatable='yes'>NDP poisoning</attribute>"
         "        <attribute name='action'>app.ndp_poisoning</attribute>"
         "      </item>"
#endif
         "      <item>"
         "        <attribute name='label' translatable='yes'>ICMP redirect</attribute>"
         "        <attribute name='action'>app.icmp_redirect</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Port stealing</attribute>"
         "        <attribute name='action'>app.port_stealing</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>DHCP spoofing</attribute>"
         "        <attribute name='action'>app.dhcp_spoofing</attribute>"
         "      </item>"
         "    </section>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>SSL intercept</attribute>"
         "        <attribute name='action'>app.sslredir</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Stop MITM attack(s)</attribute>"
         "        <attribute name='action'>app.mitm_stop</attribute>"
         "      </item>"
         "    </section>"
         "  </menu>"
         "</interface>", -1, NULL);

   /* Adjust title formatting */
   title = g_strdup(PROGRAM);
   *title = g_ascii_toupper(*title);

   /* reuse main window */
   gtk_application_add_window(GTK_APPLICATION(app), GTK_WINDOW(window));

   header = adw_header_bar_new();
   /*
    * GtkHeaderBar lost set_subtitle() in GTK4. AdwWindowTitle is the
    * replacement and keeps the version visible under the program name.
    */
   adw_header_bar_set_title_widget(ADW_HEADER_BAR(header),
         adw_window_title_new(title, EC_VERSION));

   /* start/stop sniffing button */
   button = gtk_toggle_button_new();
   gtk_widget_set_tooltip_text(button, "Start / Stop Sniffing");
   if (EC_GBL_CONF->sniffing_at_startup) {
      gtk_button_set_icon_name(GTK_BUTTON(button),
            "media-playback-stop-symbolic");
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button), TRUE);
   } else {
      gtk_button_set_icon_name(GTK_BUTTON(button),
            "media-playback-start-symbolic");
   }
   adw_header_bar_pack_start(ADW_HEADER_BAR(header), button);
   g_signal_connect(button, "toggled", G_CALLBACK(toggle_sniffing), NULL);

   /* menu button for the Ettercap menu */
   menubutton = gtk_menu_button_new();
   menu = G_MENU(gtk_builder_get_object(builder, "ettercap-menu"));
   gtk_widget_set_tooltip_text(menubutton, "Ettercap Menu");
   if (!unified)
      g_menu_remove(menu, 1); /* remove the Hosts submenu */
   gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(menubutton),
         G_MENU_MODEL(menu));
   gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(menubutton),
         "open-menu-symbolic");
   adw_header_bar_pack_end(ADW_HEADER_BAR(header), menubutton);

   if (unified) {
      button = gtk_button_new_from_icon_name("edit-find-symbolic");
      gtk_widget_set_tooltip_text(button, "Scan for hosts");
      adw_header_bar_pack_start(ADW_HEADER_BAR(header), button);
      g_signal_connect(button, "clicked", G_CALLBACK(scanbutton_clicked), NULL);

      button = gtk_button_new_from_icon_name("network-server-symbolic");
      gtk_widget_set_tooltip_text(button, "Hosts List");
      adw_header_bar_pack_start(ADW_HEADER_BAR(header), button);
      g_signal_connect(button, "clicked",
            G_CALLBACK(hostlistbutton_clicked), NULL);

      button = gtk_button_new_from_icon_name("process-stop-symbolic");
      gtk_widget_set_tooltip_text(button, "Stop MITM");
      adw_header_bar_pack_end(ADW_HEADER_BAR(header), button);
      g_signal_connect(button, "clicked",
            G_CALLBACK(mitmstopbutton_clicked), NULL);

      menubutton = gtk_menu_button_new();
      gtk_widget_set_tooltip_text(menubutton, "MITM menu");
      gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(menubutton),
            G_MENU_MODEL(gtk_builder_get_object(builder, "mitm-menu")));
      gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(menubutton),
            "network-workgroup-symbolic");
      adw_header_bar_pack_end(ADW_HEADER_BAR(header), menubutton);
   }

   /*
    * Replace the setup screen's content.
    *
    * The GTK3 code reached in with gtk_bin_get_child()/gtk_container_remove()
    * to swap the window's child. AdwApplicationWindow has an explicit
    * content property, so setting it is the whole operation.
    */

   /* the MDI area: an AdwTabView with its bar above it */
   notebook = GTK_WIDGET(adw_tab_view_new());
   tabbar = GTK_WIDGET(adw_tab_bar_new());
   adw_tab_bar_set_view(ADW_TAB_BAR(tabbar), ADW_TAB_VIEW(notebook));
   adw_tab_bar_set_autohide(ADW_TAB_BAR(tabbar), TRUE);

   /*
    * The logo shows through as the tab view's background until the first
    * page is opened, which is what the GTK3 interface used the empty
    * notebook frame for.
    */
   path = INSTALL_DATADIR "/" PROGRAM "/" LOGO_FILE;
   if (!g_file_test(path, G_FILE_TEST_EXISTS))
      path = "./share/" LOGO_FILE;
   logo = gtk_picture_new_for_filename(path);
   gtk_widget_set_halign(logo, GTK_ALIGN_CENTER);
   gtk_widget_set_valign(logo, GTK_ALIGN_CENTER);
   gtk_picture_set_can_shrink(GTK_PICTURE(logo), TRUE);

   tabbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_box_append(GTK_BOX(tabbox), tabbar);
   gtk_box_append(GTK_BOX(tabbox), logo);
   gtk_widget_set_vexpand(logo, TRUE);
   gtk_box_append(GTK_BOX(tabbox), notebook);
   gtk_widget_set_vexpand(notebook, TRUE);

   /* messages */
   textview = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(textview), GTK_WRAP_WORD_CHAR);
   gtk_text_view_set_editable(GTK_TEXT_VIEW(textview), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(textview), FALSE);
   gtk_text_view_set_monospace(GTK_TEXT_VIEW(textview), TRUE);

   msgbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
   gtk_text_buffer_get_end_iter(msgbuffer, &iter);
   endmark = gtk_text_buffer_create_mark(msgbuffer, "end", &iter, FALSE);

   scroll = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), textview);
   gtk_widget_set_size_request(scroll, -1, 140);

   vpaned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
   gtk_paned_set_start_child(GTK_PANED(vpaned), tabbox);
   gtk_paned_set_resize_start_child(GTK_PANED(vpaned), TRUE);
   gtk_paned_set_end_child(GTK_PANED(vpaned), scroll);
   gtk_paned_set_resize_end_child(GTK_PANED(vpaned), FALSE);

   /*
    * Notifications go through the toast overlay rather than the GtkInfoBar
    * the GTK3 interface built here -- GtkInfoBar is deprecated in GTK4, and
    * AdwToast queues, expires and dismisses itself without the manual
    * show/hide/no-show-all bookkeeping the old code needed.
    */
   toastoverlay = adw_toast_overlay_new();
   adw_toast_overlay_set_child(ADW_TOAST_OVERLAY(toastoverlay), vpaned);

   box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_box_append(GTK_BOX(box), toastoverlay);
   gtk_widget_set_vexpand(toastoverlay, TRUE);

   toolbar = adw_toolbar_view_new();
   adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
   adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), box);

   adw_application_window_set_content(ADW_APPLICATION_WINDOW(window), toolbar);

   gtkui_create_tab_menu();

   gtk_window_present(GTK_WINDOW(window));

   g_object_unref(builder);
   g_free(title);
}

/*
 * The tab context menu.
 *
 * The GTK3 version instantiated a GtkMenu from the model and hung it off a
 * button-press-event handler on the notebook -- both of which GTK4 removed.
 * AdwTabView takes the menu model directly and raises it on right-click and
 * on the tab's own menu button, so there is no gesture handling left to do.
 */
void gtkui_create_tab_menu(void)
{
   GtkBuilder *builder;
   GSimpleActionGroup *actiongroup;

   static GActionEntry tab_actions[] = {
      {"detach_page", gtkui_page_detach_current, NULL, NULL, NULL, {}},
      {"close_page",  gtkui_page_close_current, NULL, NULL, NULL, {}},
      {"next_page",   gtkui_page_right, NULL, NULL, NULL, {}},
      {"prev_page",   gtkui_page_left, NULL, NULL, NULL, {}}
   };

   static gtkui_accel_map_t tab_accels[] = {
      {"tab.detach_page", {"<Primary>d", NULL}, "Detach the current page", "Pages"},
      {"tab.close_page", {"<Primary>w", NULL}, "Close the current page", "Pages"},
      {"tab.next_page", {"<Primary>Tab", "<Primary>Right", NULL},
         "Go to the next page", "Pages"},
      {"tab.prev_page", {"<Primary><Shift>Tab", "<Primary>Left", NULL},
         "Go to the previous page", "Pages"}
   };

   builder = gtk_builder_new();
   gtk_builder_add_from_string(builder,
         "<interface>"
         "  <menu id='tab-menu'>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Detach page</attribute>"
         "        <attribute name='action'>tab.detach_page</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Close page</attribute>"
         "        <attribute name='action'>tab.close_page</attribute>"
         "      </item>"
         "    </section>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Next page</attribute>"
         "        <attribute name='action'>tab.next_page</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Previous page</attribute>"
         "        <attribute name='action'>tab.prev_page</attribute>"
         "      </item>"
         "    </section>"
         "  </menu>"
         "</interface>", -1, NULL);

   actiongroup = g_simple_action_group_new();
   g_action_map_add_action_entries(G_ACTION_MAP(actiongroup), tab_actions,
         G_N_ELEMENTS(tab_actions), NULL);

   /*
    * The action group is inserted on the window rather than on the menu
    * widget. Under GTK3 it went on the GtkMenu, which is why the accelerators
    * here never fired (the GTK3 source says as much: "FIXME doesn't work
    * yet") -- an accelerator is dispatched from the focused widget up through
    * the window, and a popup menu that is not showing is on nobody's path.
    */
   gtk_widget_insert_action_group(window, "tab", G_ACTION_GROUP(actiongroup));

   gtkui_install_accels(GTK_APPLICATION(etterapp), tab_accels,
         G_N_ELEMENTS(tab_accels));

   adw_tab_view_set_menu_model(ADW_TAB_VIEW(notebook),
         G_MENU_MODEL(gtk_builder_get_object(builder, "tab-menu")));

   g_object_unref(actiongroup);
   g_object_unref(builder);
}

/*
 * callback to start and stop sniffing, swapping the play button's icon
 */
static void toggle_sniffing(GtkToggleButton *button, gpointer data)
{
   (void) data;

   if (gtk_toggle_button_get_active(button)) {
      gtkui_start_sniffing();
      gtk_button_set_icon_name(GTK_BUTTON(button),
            "media-playback-stop-symbolic");
   } else {
      gtkui_stop_sniffing();
      gtk_button_set_icon_name(GTK_BUTTON(button),
            "media-playback-start-symbolic");
   }
}

/*
 * callbacks for the header bar buttons
 * - wrappers due to different callback function signatures
 */
static void scanbutton_clicked(GtkButton *button, gpointer data)
{
   (void) button;
   (void) data;

   gtkui_scan(NULL, NULL, NULL);
}

static void hostlistbutton_clicked(GtkButton *button, gpointer data)
{
   (void) button;
   (void) data;

   gtkui_host_list(NULL, NULL, NULL);
}

static void mitmstopbutton_clicked(GtkButton *button, gpointer data)
{
   (void) button;
   (void) data;

   gtkui_mitm_stop(NULL, NULL, NULL);
}

/* EOF */

// vim:ts=3:expandtab
