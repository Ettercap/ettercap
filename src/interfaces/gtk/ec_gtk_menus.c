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
#include <ec_gtk.h>

/* globals */

/*******************************************/

void gtkui_create_menu(int live)
{
   GtkAccelGroup *accel_group;
   GtkWidget *vbox, *main_menu;
   GtkActionGroup *menuactions;
   GtkAction *action;
   GError *error = NULL;
   GClosure *closure = NULL;
   gint keyval;
   GdkModifierType mods;
   
   const gchar *menu_structure = 
      "<ui>"
      "  <menubar name='MenuBar'>"
      "     <menu name='StartMenu' action='StartMenuAction'>"
      "        <menuitem name='SniffStart' action='SniffStartAction' />"
      "        <menuitem name='SniffStop' action='SniffStopAction' />"
      "        <separator />"
      "        <menuitem name='Exit' action='ExitAction' />"
      "     </menu>"
      "     <menu name='TargetsMenu' action='TargetsMenuAction'>"
      "        <menuitem name='CurrentTargets' action='CurrentTargetsAction' />"
      "        <menuitem name='SelectTargets' action='SelectTargetsAction' />"
      "        <separator />"
      "        <menuitem name='Protocol' action='ProtocolAction' />"
      "        <menuitem name='ReverseMatching' action='ReverseMatchingAction' />"
      "        <separator />"
      "        <menuitem name='WipeTargets' action='WipeTargetsAction' />"
      "     </menu>"
      "     <menu name='HostsMenu' action='HostsMenuAction'>"
      "        <menuitem name='HostsList' action='HostsListAction' />"
      "        <separator />"
#ifdef WITH_IPV6
      "        <menuitem name='EnableIPv6Scan' action='EnableIPv6ScanAction' />"
#endif
      "        <menuitem name='ScanHosts' action='ScanHostsAction' />"
      "        <menuitem name='LoadHosts' action='LoadHostsAction' />"
      "        <menuitem name='SaveHosts' action='SaveHostsAction' />"
      "     </menu>"
      "     <menu name='ViewMenu' action='ViewMenuAction'>"
      "        <menuitem name='ViewConnections' action='ViewConnectionsAction' />"
      "        <menuitem name='ViewProfiles' action='ViewProfilesAction' />"
      "        <menuitem name='ViewStatistics' action='ViewStatisticsAction' />"
      "        <separator />"
      "        <menuitem name='ResolveIpAddresses' action='ResolveIpAddressesAction' />"
      "        <menuitem name='VisualisationMethod' action='VisualisationMethodAction' />"
      "        <menuitem name='VisualisationRegex' action='VisualisationRegexAction' />"
      "        <separator />"
      "        <menuitem name='SetWifiKey' action='SetWifiKeyAction' />"
      "     </menu>"
      "     <menu name='MitmMenu' action='MitmMenuAction'>"
      "        <menuitem name='ArpPoisoning' action='ArpPoisoningAction' />"
      "        <menuitem name='IcmpRedirect' action='IcmpRedirectAction' />"
      "        <menuitem name='PortStealing' action='PortStealingAction' />"
      "        <menuitem name='DhcpSpoofing' action='DhcpSpoofingAction' />"
#ifdef WITH_IPV6
      "        <menuitem name='NdpPoisoning' action='NdpPoisoningAction' />"
#endif
      "        <separator />"
      "        <menuitem name='StopMitmAttacks' action='StopMitmAttacksAction' />"
      "        <separator />"
      "        <menuitem name='SSLRedirects' action='SSLRedirectsAction' />"
      "     </menu>"
      "     <menu name='FiltersMenu' action='FiltersMenuAction'>"
      "        <menuitem name='LoadFilter' action='LoadFilterAction' />"
      "        <menuitem name='StopFilter' action='StopFilterAction' />"
      "     </menu>"
      "     <menu name='LoggingMenu' action='LoggingMenuAction'>"
      "        <menuitem name='LoggingAll' action='LoggingAllAction' />"
      "        <menuitem name='LoggingInfo' action='LoggingInfoAction' />"
      "        <menuitem name='LoggingStop' action='LoggingStopAction' />"
      "        <separator />"
      "        <menuitem name='LogMessages' action='LogMessagesAction' />"
      "        <menuitem name='LogMessagesStop' action='LogMessagesStopAction' />"
      "        <separator />"
      "        <menuitem name='LogCompressed' action='LogCompressedAction' />"
      "     </menu>"
#ifdef HAVE_PLUGINS
      "     <menu name='PluginsMenu' action='PluginsMenuAction'>"
      "        <menuitem name='ManagePlugins' action='ManagePluginsAction' />"
      "        <menuitem name='LoadPlugin' action='LoadPluginAction' />"
      "     </menu>"
#endif
      "     <menu name='HelpMenu' action='HelpMenuAction'>"
#ifndef OS_WINDOWS
      "        <menuitem name='Help' action='HelpAction' />"
#endif
      "        <menuitem name='About' action='AboutDialogAction' />"
      "     </menu>"
      "  </menubar>"
      "</ui>";


   GtkActionEntry start_menu_items[] = {
      /* Start Menu */
      {
         "StartMenuAction", NULL, 
         "_Start", NULL, 
         NULL, NULL
      },

      {
         "SniffStartAction", GTK_STOCK_YES,
         "Start sniffing", "<control><shift>w",
         NULL, G_CALLBACK(gtkui_start_sniffing)
      },

      {
         "SniffStopAction", GTK_STOCK_NO,
         "Stop sniffing", "<control><shift>e",
         NULL, G_CALLBACK(gtkui_stop_sniffing)
      },

      {
         "ExitAction", GTK_STOCK_QUIT,
         "E_xit", "<control>q",
         NULL, G_CALLBACK(gtkui_exit)
      }
   };

   GtkActionEntry targets_menu_items[] = {
      /* Targets Menu */
      {
         "TargetsMenuAction", NULL,
         "_Targets", NULL,
         NULL, NULL
      },

      {
         "CurrentTargetsAction", GTK_STOCK_FIND,
         "Current targets", "<control>t",
         NULL, G_CALLBACK(gtkui_current_targets)
      },

      {
         "SelectTargetsAction", GTK_STOCK_ADD,
         "Select target(s)", "<control><shift>t",
         NULL, G_CALLBACK(gtkui_select_targets)
      },

      {
         "ProtocolAction", GTK_STOCK_JUMP_TO,
         "_Protocol...", "<control>p",
         NULL, G_CALLBACK(gtkui_select_protocol)
      },

      {
         "WipeTargetsAction", GTK_STOCK_CLEAR,
         "_Wipe targets", "<control>W",
         NULL, G_CALLBACK(wipe_targets)
      }
   };

   GtkActionEntry hosts_menu_items[] = {
      /* Hosts Menu */
      {
         "HostsMenuAction", NULL,
         "_Hosts", NULL,
         NULL, NULL
      },

      {
         "HostsListAction", GTK_STOCK_INDEX,
         "_Hosts list", "<control>h",
         NULL, G_CALLBACK(gtkui_host_list)
      },

      {
         "ScanHostsAction", GTK_STOCK_FIND,
         "_Scan for hosts", "<control>s",
         NULL, G_CALLBACK(gtkui_scan)
      },

      {
         "LoadHostsAction", GTK_STOCK_OPEN,
         "Load from file...", "",
         NULL, G_CALLBACK(gtkui_load_hosts)
      },

      {
         "SaveHostsAction", GTK_STOCK_SAVE,
         "Save to file...", "",
         NULL, G_CALLBACK(gtkui_save_hosts)
      }
   };

   GtkActionEntry view_menu_items[] = {
      /* View Menu */
      {
         "ViewMenuAction", NULL,
         "_View", NULL,
         NULL, NULL
      },

      {
         "ViewConnectionsAction", GTK_STOCK_JUSTIFY_FILL,
         "_Connections", "<control><shift>c",
         NULL, G_CALLBACK(gtkui_show_connections)
      },

      {
         "ViewProfilesAction", GTK_STOCK_JUSTIFY_LEFT,
         "Pr_ofiles", "<control>o",
         NULL, G_CALLBACK(gtkui_show_profiles)
      },

      {
         "ViewStatisticsAction", GTK_STOCK_PROPERTIES,
         "_Statistics", NULL,
         NULL, G_CALLBACK(gtkui_show_stats)
      },

      {
         "VisualisationMethodAction", GTK_STOCK_PREFERENCES,
         "_Visualisation method...", "<control><shift>v",
         NULL, G_CALLBACK(gtkui_vis_method)
      },

      {
         "VisualisationRegexAction", GTK_STOCK_FIND,
         "Visualisation _regex...", "<control>R",
         NULL, G_CALLBACK(gtkui_vis_regex)
      },

      {
         "SetWifiKeyAction", GTK_STOCK_FIND,
         "Set the _WiFi key...", NULL,
         NULL, G_CALLBACK(gtkui_wifi_key)
      }
   };

   GtkActionEntry mitm_menu_items[] = {
      /* Mitm Menu */
      {
         "MitmMenuAction", NULL,
         "_Mitm", NULL,
         NULL, NULL
      },

      {
         "ArpPoisoningAction", NULL,
         "ARP poisoning...", NULL,
         NULL, G_CALLBACK(gtkui_arp_poisoning)
      },

      {
         "IcmpRedirectAction", NULL,
         "ICMP redirect...", NULL,
         NULL, G_CALLBACK(gtkui_icmp_redir)
      },

      {
         "PortStealingAction", NULL,
         "Port stealing...", NULL,
         NULL, G_CALLBACK(gtkui_port_stealing)
      },

      {
         "DhcpSpoofingAction", NULL,
         "DHCP spoofing...", NULL,
         NULL, G_CALLBACK(gtkui_dhcp_spoofing)
      },

#ifdef WITH_IPV6
      {
         "NdpPoisoningAction", NULL,
         "NDP poisoning...", NULL,
         NULL, G_CALLBACK(gtkui_ndp_poisoning)
      },
#endif

      { 
         "StopMitmAttacksAction", NULL,
         "Stop mitm attack(s)", NULL,
         NULL, G_CALLBACK(gtkui_mitm_stop)
      },

      {
         "SSLRedirectsAction", NULL,
         "SSL Intercept", NULL,
         NULL, G_CALLBACK(gtkui_sslredir_show)
      }
   };

   GtkActionEntry filters_menu_items[] = {
      /* Filters Menu */
      {
         "FiltersMenuAction", NULL,
         "_Filters", NULL,
         NULL, NULL
      },

      {
         "LoadFilterAction", GTK_STOCK_OPEN,
         "Load a filter...", "<control>f",
         NULL, G_CALLBACK(gtkui_load_filter)
      },

      {
         "StopFilterAction", GTK_STOCK_STOP,
         "Stop _filtering", "<control><shift>f",
         NULL, G_CALLBACK(gtkui_stop_filter)
      }
   };

   GtkActionEntry logging_menu_items[] = {
      /* Logging Menu */
      {
         "LoggingMenuAction", NULL,
         "_Logging", NULL,
         NULL, NULL
      },

      {
         "LoggingAllAction", GTK_STOCK_SAVE,
         "Logging all packets and infos...", "<control><shift>i",
         NULL, G_CALLBACK(gtkui_log_all)
      },

      {
         "LoggingInfoAction", GTK_STOCK_SAVE_AS,
         "Logging only infos...", "<control>i",
         NULL, G_CALLBACK(gtkui_log_info)
      },

      {
         "LoggingStopAction", GTK_STOCK_STOP,
         "Stop logging infos", NULL,
         NULL, G_CALLBACK(gtkui_stop_log)
      },

      {
         "LogMessagesAction", GTK_STOCK_REVERT_TO_SAVED,
         "Log user messages...", "<control>m",
         NULL, G_CALLBACK(gtkui_log_msg)
      },

      {
         "LogMessagesStopAction", GTK_STOCK_STOP,
         "Stop logging messages", NULL,
         NULL, G_CALLBACK(gtkui_stop_msg)
      }
   };

#ifdef HAVE_PLUGINS
   GtkActionEntry plugins_menu_items[] = {
      /* Plugins Menu */
      {
         "PluginsMenuAction", NULL,
         "_Plugins", NULL,
         NULL, NULL
      },

      {
         "ManagePluginsAction", GTK_STOCK_EXECUTE,
         "Manage the plugins", "<control>p",
         NULL, G_CALLBACK(gtkui_plugin_mgmt)
      },

      {
         "LoadPluginAction", GTK_STOCK_OPEN,
         "Load a plugin...", NULL,
         NULL, G_CALLBACK(gtkui_plugin_load)
      }
   };
#endif

   GtkActionEntry help_menu_items[] = {
      /* Help Menu */
      {
         "HelpMenuAction", NULL,
         "_Info", NULL,
         NULL, NULL
      },

#ifndef OS_WINDOWS
      {
         "HelpAction", GTK_STOCK_HELP,
         "Help", "F1",
         NULL, G_CALLBACK(gtkui_help)
      },
#endif
      {
         "AboutDialogAction", GTK_STOCK_ABOUT,
         "About", NULL,
         NULL, G_CALLBACK(gtkui_about)
      }
   };

   GtkToggleActionEntry toggle_items[] = {
      {
         "ReverseMatchingAction", NULL,
         "Reverse matching", NULL,
         NULL, G_CALLBACK(toggle_reverse),
         FALSE
      },

#ifdef WITH_IPV6
      {
         "EnableIPv6ScanAction", NULL,
         "Enable IPv6 scan", NULL,
         NULL, G_CALLBACK(toggle_ip6scan),
         FALSE
      },
#endif

      {
         "ResolveIpAddressesAction", NULL,
         "Resolve IP addresses", NULL,
         NULL, G_CALLBACK(toggle_resolve),
         FALSE
      },

      {
         "LogCompressedAction", NULL,
         "Compressed file", NULL,
         NULL, G_CALLBACK(toggle_compress),
         FALSE
      }
   };

   DEBUG_MSG("gtk_create_menu");

   /* remove old menu, it will be automatically destroyed by gtk_main */
   vbox = gtk_bin_get_child(GTK_BIN (window));
   main_menu = gtk_ui_manager_get_widget(menu_manager, "/MenuBar");
   gtk_widget_hide(main_menu);
   gtk_ui_manager_remove_ui(menu_manager, merge_id);

   menuactions = gtk_action_group_new("MenuActions");
   /* Start Menu */
   gtk_action_group_add_actions(menuactions, start_menu_items, G_N_ELEMENTS(start_menu_items), NULL);
   /* Targets Menu */
   gtk_action_group_add_actions(menuactions, targets_menu_items, G_N_ELEMENTS(targets_menu_items), NULL);
   /* Hosts Menu */
   gtk_action_group_add_actions(menuactions, hosts_menu_items, G_N_ELEMENTS(hosts_menu_items), NULL);
   /* View Menu */
   gtk_action_group_add_actions(menuactions, view_menu_items, G_N_ELEMENTS(view_menu_items), NULL);
   /* MITM Menu */
   gtk_action_group_add_actions(menuactions, mitm_menu_items, G_N_ELEMENTS(mitm_menu_items), NULL);
   /* Filters Menu */
   gtk_action_group_add_actions(menuactions, filters_menu_items, G_N_ELEMENTS(filters_menu_items), NULL);
   /* Logging Menu */
   gtk_action_group_add_actions(menuactions, logging_menu_items, G_N_ELEMENTS(logging_menu_items), NULL);
#ifdef HAVE_PLUGINS
   /* Plugins Menu */
   gtk_action_group_add_actions(menuactions, plugins_menu_items, G_N_ELEMENTS(plugins_menu_items), NULL);
#endif
#ifndef OS_WINDOWS
   /* Help Menu */
   gtk_action_group_add_actions(menuactions, help_menu_items, G_N_ELEMENTS(help_menu_items), NULL);
#endif

   gtk_action_group_add_toggle_actions(menuactions, toggle_items, G_N_ELEMENTS(toggle_items), NULL);

   menu_manager = gtk_ui_manager_new();
   gtk_ui_manager_insert_action_group(menu_manager, menuactions, 0);

   merge_id = gtk_ui_manager_add_ui_from_string(menu_manager, menu_structure, -1, &error);
   if (error) {
      g_message("building menu failed: %s", error->message);
      g_error_free(error);
      error = NULL;
   }

   /* Some hidden accellerators */
   accel_group = gtk_accel_group_new ();
   closure = g_cclosure_new(G_CALLBACK(gtkui_exit), NULL, NULL);
   gtk_accelerator_parse("<control>X", &keyval, &mods);
   gtk_accel_group_connect(accel_group, keyval, mods, 0, closure);
   gtk_window_add_accel_group(GTK_WINDOW(window), accel_group);
   gtk_window_add_accel_group(GTK_WINDOW(window), gtk_ui_manager_get_accel_group(menu_manager));

   

   if(EC_GBL_OPTIONS->reversed) {
      EC_GBL_OPTIONS->reversed = 0;
      action = gtk_ui_manager_get_action(menu_manager, "/MenuBar/TargetsMenu/ReverseMatching");
      gtk_toggle_action_set_active(GTK_TOGGLE_ACTION(action), TRUE);
   }

   if(EC_GBL_OPTIONS->resolve) {
      EC_GBL_OPTIONS->resolve = 0;
      action = gtk_ui_manager_get_action(menu_manager, "/MenuBar/ViewMenu/ResolveIpAddresses");
      gtk_toggle_action_set_active(GTK_TOGGLE_ACTION(action), TRUE);
   }

   if(EC_GBL_OPTIONS->compress) {
      EC_GBL_OPTIONS->compress = 0;
      action = gtk_ui_manager_get_action(menu_manager, "/MenuBar/LoggingMenu/LogCompressed");
      gtk_toggle_action_set_active(GTK_TOGGLE_ACTION(action), TRUE);
   }

   /* Some menus doesn't apply if started in offline or bridged sniffing mode */
   if (live == 0 || EC_GBL_SNIFF->type == SM_BRIDGED) {
      gtk_widget_set_visible(gtk_ui_manager_get_widget(menu_manager, "/MenuBar/HostsMenu"), FALSE);
      gtk_widget_set_visible(gtk_ui_manager_get_widget(menu_manager, "/MenuBar/MitmMenu"), FALSE);
   }

#ifdef HAVE_PLUGINS
   if (live == 0)
      gtk_widget_set_visible(gtk_ui_manager_get_widget(menu_manager, "/MenuBar/PluginsMenu"), FALSE);
#endif

   /* get the menu widget and add it to the window */
   main_menu = gtk_ui_manager_get_widget(menu_manager, "/MenuBar");
   gtk_box_pack_start(GTK_BOX(vbox), main_menu, FALSE, FALSE, 0);
   gtk_widget_show(main_menu);
   
}

void gtkui_create_tab_menu(void)
{
   GtkWidget *context;
   GtkUIManager *tab_menu_manager;
   GtkActionGroup *tabactions;
   GError *error = NULL;

   static gchar *tab_menu_structure = 
       "<ui>"
       "   <popup name='NoteBook'>"
       "      <menuitem name='DetachPage' action='DetachPageAction' />"
       "      <menuitem name='ClosePage' action='ClosePageAction' />"
       "      <separator />"
       "      <menuitem name='NextPage' action='NextPageAction' />"
       "      <menuitem name='PreviousPage' action='PreviousPageAction' />"
       "   </popup>"
       "</ui>";

   GtkActionEntry tab_menu_items[] = {
      {
         "DetachPageAction", GTK_STOCK_GO_UP,
         "Detach page", "<control>D",
         NULL, G_CALLBACK(gtkui_page_detach_current)
      },

      {
         "ClosePageAction", GTK_STOCK_CLOSE,
         "Close page", "<control>W",
         NULL, G_CALLBACK(gtkui_page_close_current)
      },

      {
         "NextPageAction", GTK_STOCK_GO_FORWARD,
         "Next page", "<control>Tab",
         NULL, G_CALLBACK(gtkui_page_right)
      },

      {
         "PreviousPageAction", GTK_STOCK_GO_BACK,
         "Previous page", "<control><shift>Tab",
         NULL, G_CALLBACK(gtkui_page_left)
      }
   };
   /* Create Action Group for tab menu */
   tabactions = gtk_action_group_new("TabActions");
   gtk_action_group_add_actions(tabactions, tab_menu_items, G_N_ELEMENTS(tab_menu_items), NULL);

   /* context menu for notebook */
   tab_menu_manager = gtk_ui_manager_new();
   gtk_ui_manager_insert_action_group(tab_menu_manager, tabactions, 0);
   gtk_ui_manager_add_ui_from_string(tab_menu_manager, tab_menu_structure, -1, &error);
   if (error) {
       g_message("building tab menu failed: %s", error->message);
       g_error_free(error);
       error = NULL;
   }

   /* Add Accelerators */
   gtk_window_add_accel_group(GTK_WINDOW(window), gtk_ui_manager_get_accel_group(tab_menu_manager));

   /* Bind popup menu to event */
   context = gtk_ui_manager_get_widget(tab_menu_manager, "/NoteBook");
   g_signal_connect(G_OBJECT(notebook), "button-press-event", G_CALLBACK(gtkui_context_menu), context);
}


/* EOF */

// vim:ts=3:expandtab

