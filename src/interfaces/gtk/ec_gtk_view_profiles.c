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
#include <ec_format.h>
#include <ec_profiles.h>
#include <ec_manuf.h>
#include <ec_services.h>
#include <ec_geoip.h>

/* proto */

static void gtkui_profiles_detach(GtkWidget *child);
static void gtkui_profiles_attach(void);
static void gtkui_kill_profiles(void);
static gboolean refresh_profiles(gpointer data);
static void gtkui_profile_detail(void);
static void gtkui_profile_detail_destroy(GtkWidget *widget, gpointer *data);
static void gtkui_profiles_local(void);
static void gtkui_profiles_remote(void);
static void gtkui_profiles_convert(void);
static void gtkui_profiles_dump(void *dummy);
static void dump_profiles(void);

static struct host_profile *gtkui_profile_selected(void);

/* globals */

static char *logfile = NULL;
static GtkWidget  *profiles_window = NULL;
static GtkWidget         *treeview = NULL;
static GtkTreeSelection *selection = NULL;
static GtkListStore     *ls_profiles = NULL;
static guint profiles_idle; /* for removing the idle call */
static guint detail_timer = 0;

/*******************************************/

/*
 * the auto-refreshing list of profiles 
 */
void gtkui_show_profiles(void)
{
   GtkWidget *scrolled, *vbox, *hbox, *button;
   GtkCellRenderer   *renderer;
   GtkTreeViewColumn *column;  

   DEBUG_MSG("gtk_show_profiles");

   /* if the object already exist, set the focus to it */
   if(profiles_window) {
      if(GTK_IS_WINDOW (profiles_window))
         gtk_window_present(GTK_WINDOW (profiles_window));
      else
         gtkui_page_present(profiles_window);
      return;
   }
   
   profiles_window = gtkui_page_new("Profiles", &gtkui_kill_profiles, &gtkui_profiles_detach);

   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
   gtk_container_add(GTK_CONTAINER (profiles_window), vbox);
   gtk_widget_show(vbox);

  /* list */
   scrolled = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scrolled), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);
   gtk_widget_show(scrolled);

   treeview = gtk_tree_view_new();
   gtk_container_add(GTK_CONTAINER (scrolled), treeview);
   gtk_widget_show(treeview);

   selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (treeview));
   gtk_tree_selection_set_mode (selection, GTK_SELECTION_SINGLE);
   g_signal_connect (G_OBJECT (treeview), "row_activated", G_CALLBACK (gtkui_profile_detail), NULL);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes (" ", renderer, "text", 0, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 0);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("IP Address", renderer, "text", 1, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 1);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Hostname", renderer, "text", 2, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 2);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

#ifdef HAVE_GEOIP
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Country", renderer, "text", 3, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 3);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);
#endif

   refresh_profiles(NULL);
   gtk_tree_view_set_model(GTK_TREE_VIEW (treeview), GTK_TREE_MODEL (ls_profiles));

   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 5, TRUE);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

   button = gtk_button_new_with_mnemonic("Purge _Local");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_profiles_local), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

   button = gtk_button_new_with_mnemonic("Purge _Remote");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_profiles_remote), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show_all(hbox);

   button = gtk_button_new_with_mnemonic("_Convert to Host List");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_profiles_convert), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

   button = gtk_button_new_with_mnemonic("_Dump to File");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_profiles_dump), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show_all(hbox);

   /* refresh the stats window every 1000 ms */
   /* GTK has a gtk_idle_add also but it calls too much and uses 100% cpu */
   profiles_idle = g_timeout_add(1000, refresh_profiles, NULL);

   gtk_widget_show(profiles_window);

}

static void gtkui_profiles_detach(GtkWidget *child)
{
   profiles_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (profiles_window), "Collected passive profiles");
   gtk_window_set_default_size(GTK_WINDOW (profiles_window), 400, 300);
   g_signal_connect (G_OBJECT (profiles_window), "delete_event", G_CALLBACK (gtkui_kill_profiles), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(profiles_window, gtkui_profiles_attach);

   gtk_container_add(GTK_CONTAINER (profiles_window), child);

   gtk_window_present(GTK_WINDOW (profiles_window));
}

static void gtkui_profiles_attach(void)
{
   gtkui_kill_profiles();
   gtkui_show_profiles();
}

static void gtkui_kill_profiles(void)
{
   DEBUG_MSG("gtk_kill_profiles");

   g_source_remove(profiles_idle);

   gtk_widget_destroy(profiles_window);
   profiles_window = NULL;
}

static gboolean refresh_profiles(gpointer data)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   gboolean gotiter = FALSE;
   struct host_profile *hcurr, *hitem;
   struct open_port *o;
   struct active_user *u;
   char tmp[MAX_ASCII_ADDR_LEN];
   char name[MAX_HOSTNAME_LEN];
   int found = 0;

   /* variable not used */
   (void) data;

   if(!ls_profiles) {
      ls_profiles = gtk_list_store_new (5, G_TYPE_STRING, G_TYPE_STRING, 
                                           G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);
   }

   /* get iter for first item in list widget */
   model = GTK_TREE_MODEL(ls_profiles);
   gotiter = gtk_tree_model_get_iter_first(model, &iter);

   TAILQ_FOREACH(hcurr, &EC_GBL_PROFILES, next) {
      /* see if the item is already in our list */
      gotiter = gtk_tree_model_get_iter_first(model, &iter);
      while(gotiter) {
         gtk_tree_model_get (model, &iter, 4, &hitem, -1);
         if(hcurr == hitem) {
            found = 0;
            /* search at least one account */
            LIST_FOREACH(o, &(hcurr->open_ports_head), next) {
               LIST_FOREACH(u, &(o->users_list_head), next) {
                  found = 1;
               }
            }

            gtk_list_store_set (ls_profiles, &iter, 0, (found)?"X":" ", -1);

            /* check if we have to update the hostname */
            if (strcmp(hcurr->hostname,"")) {
               gtk_list_store_set(ls_profiles, &iter, 2, hcurr->hostname, -1);
            } else {
               /* resolve the hostname (using the cache) */
               if (host_iptoa(&hcurr->L3_addr, name) == -E_NOMATCH) {
                  gtk_list_store_set(ls_profiles, &iter, 2, "resolving...", -1);
                  struct resolv_object *ro;
                  SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
                  ro->type = GTK_TYPE_LIST_STORE; 
                  ro->liststore = GTK_LIST_STORE(ls_profiles);
                  ro->treeiter = iter;
                  ro->column = 2;
                  ro->ip = &hcurr->L3_addr;
                  g_timeout_add(1000, gtkui_iptoa_deferred, ro);
               }
               else {
                  strncpy(hcurr->hostname, name, MAX_HOSTNAME_LEN);
                  gtk_list_store_set(ls_profiles, &iter, 2, hcurr->hostname, -1);
               }
            }

            break;
         }
         gotiter = gtk_tree_model_iter_next(model, &iter);
      }

      /* if it is, move on to next item */
      if(gotiter)
         continue;

      found = 0;
      /* search at least one account */
      LIST_FOREACH(o, &(hcurr->open_ports_head), next) {
         LIST_FOREACH(u, &(o->users_list_head), next) {
            found = 1;
         }
      }

      /* otherwise, add the new item */
      gtk_list_store_append (ls_profiles, &iter);

      gtk_list_store_set (ls_profiles, &iter, 
                          0, (found)?"X":" ",
                          1, ip_addr_ntoa(&hcurr->L3_addr, tmp), 
                          4, hcurr, -1);

#ifdef HAVE_GEOIP
      if (EC_GBL_CONF->geoip_support_enable)
         gtk_list_store_set(ls_profiles, &iter, 
               3, geoip_country_by_ip(&hcurr->L3_addr), -1);
#endif

      /* treat hostname resolution differently due to async processing */
      if (strcmp(hcurr->hostname,"")) {
         gtk_list_store_set(ls_profiles, &iter, 2, hcurr->hostname, -1);
      } else {
         /* resolve the hostname (using the cache) */
         if (host_iptoa(&hcurr->L3_addr, name) == -E_NOMATCH) {
            gtk_list_store_set(ls_profiles, &iter, 2, "resolving...", -1);
            struct resolv_object *ro;
            SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
            ro->type = GTK_TYPE_LIST_STORE; 
            ro->liststore = GTK_LIST_STORE(ls_profiles);
            ro->treeiter = iter;
            ro->column = 2;
            ro->ip = &hcurr->L3_addr;
            g_timeout_add(1000, gtkui_iptoa_deferred, ro);
         }
         else {
            strncpy(hcurr->hostname, name, MAX_HOSTNAME_LEN);
            gtk_list_store_set(ls_profiles, &iter, 2, hcurr->hostname, -1);
         }
      }
   }

   return TRUE;
}

/*
 * display details for a profile
 */
static void gtkui_profile_detail(void)
{
   GtkWidget *dwindow, *vbox, *hbox, *table, *label, *button;
   struct host_profile *h;
   struct open_port *o;
   struct active_user *u;
   char tmp[MAX_ASCII_ADDR_LEN];
   char os[OS_LEN+1];
   gchar *str, *markup;
   guint nrows = 2, ncols = 3, col = 0, row = 0;

   
   DEBUG_MSG("gtkui_profile_detail");

   h = gtkui_profile_selected();

   memset(os, 0, sizeof(os));

   dwindow = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW(dwindow), "Profile Details");
   gtk_window_set_modal(GTK_WINDOW(dwindow), TRUE);
   gtk_window_set_transient_for(GTK_WINDOW(dwindow), GTK_WINDOW(window));
   gtk_window_set_position(GTK_WINDOW(dwindow), GTK_WIN_POS_CENTER_ON_PARENT);
   gtk_container_set_border_width(GTK_CONTAINER(dwindow), 5);
   g_signal_connect(G_OBJECT(dwindow), "delete-event", 
         G_CALLBACK(gtkui_profile_detail_destroy), NULL);

   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 5, FALSE);
   gtk_container_add(GTK_CONTAINER(dwindow), vbox);

   table = gtk_table_new(nrows, ncols, FALSE);
   gtk_table_set_row_spacings(GTK_TABLE(table), 5);
   gtk_table_set_col_spacings(GTK_TABLE(table), 5);
   gtk_container_set_border_width(GTK_CONTAINER(table), 8);
   gtk_box_pack_start(GTK_BOX(vbox), table, FALSE, FALSE, 0);

   /* Host Information */
   label = gtk_label_new("Host Information:");
   markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>", 
         gtk_label_get_text(GTK_LABEL(label)));
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach(GTK_TABLE(table), label, col, col+3, row, row+1, GTK_FILL, GTK_FILL, 0, 0);
   g_free(markup);

   row++;
   label = gtk_label_new("IP address:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

   label = gtk_label_new(ip_addr_ntoa(&h->L3_addr, tmp));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);

   if (EC_GBL_OPTIONS->resolve) {
      row++;
      label = gtk_label_new("Hostname:");
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

      label = gtk_label_new(h->hostname);
      if (!strcmp(h->hostname,"")) {
         /* resolve the hostname (using the cache) */
         if (host_iptoa(&h->L3_addr, h->hostname) == -E_NOMATCH) {
            gtk_label_set_text(GTK_LABEL(label), "resolving...");
            struct resolv_object *ro;
            SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
            ro->type = GTK_TYPE_LABEL;
            ro->widget = GTK_WIDGET(label);
            ro->ip = &h->L3_addr;
            detail_timer = g_timeout_add(1000, gtkui_iptoa_deferred, ro);
         }
         else {
            gtk_label_set_text(GTK_LABEL(label), h->hostname);
         }
      }
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);
   }

#ifdef HAVE_GEOIP
   if (EC_GBL_CONF->geoip_support_enable) {
      row++;
      label = gtk_label_new("Location:");
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

      label = gtk_label_new(geoip_country_by_ip(&h->L3_addr));
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);
   }
#endif

   if (h->type & FP_HOST_LOCAL || h->type == FP_UNKNOWN) {
      row++;
      label = gtk_label_new("MAC address:");
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

      label = gtk_label_new(mac_addr_ntoa(h->L2_addr, tmp));
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);
      
      row++;
      label = gtk_label_new("Manufacturer:");
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

      label = gtk_label_new(manuf_search(h->L2_addr));
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);
   }

   /* Connectivity information */
   gtk_table_set_row_spacing(GTK_TABLE(table), row, 10);
   row++;
   label = gtk_label_new("Connectivity Information:");
   markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>", 
         gtk_label_get_text(GTK_LABEL(label)));
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach(GTK_TABLE(table), label, col, col+3, row, row+1, GTK_FILL, GTK_FILL, 0, 0);
   g_free(markup);

   row++;
   label = gtk_label_new("Distance:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

   label = gtk_label_new((str = g_strdup_printf("%d", h->distance)));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);
   g_free(str);

   row++;
   label = gtk_label_new("Type:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

   if (h->type & FP_GATEWAY)
      label = gtk_label_new("GATEWAY");
   else if (h->type & FP_HOST_LOCAL)
      label = gtk_label_new("LAN host");
   else if (h->type & FP_ROUTER)
      label = gtk_label_new("REMOTE ROUTER");
   else if (h->type & FP_HOST_NONLOCAL)
      label = gtk_label_new("REMOTE host");
   else if (h->type == FP_UNKNOWN)
      label = gtk_label_new("unknown");
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);

   /* OS and service information */
   gtk_table_set_row_spacing(GTK_TABLE(table), row, 10);
   row++;
   label = gtk_label_new("OS and Service Information:");
   markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>", 
         gtk_label_get_text(GTK_LABEL(label)));
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach(GTK_TABLE(table), label, col, col+3, row, row+1, GTK_FILL, GTK_FILL, 0, 0);
   g_free(markup);

   if (h->os) {
      row++;
      label = gtk_label_new("Observed OS:");
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

      label = gtk_label_new(h->os);
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);
   }

   row++;
   label = gtk_label_new("Fingerprint:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

   label = gtk_label_new(h->fingerprint);
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);

   row++;
   label = gtk_label_new("Operating System:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

   if (fingerprint_search(h->fingerprint, os) == E_SUCCESS) {
      label = gtk_label_new(os);
      str = g_strdup_printf("unknown fingerprint (please submit it)\nNeares one is: %s", os);
      label = gtk_label_new(str);
      g_free(str);
   }
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);

   LIST_FOREACH(o, &(h->open_ports_head), next) {

      row++;
      label = gtk_label_new("Fingerprint:");
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

      str = g_strdup_printf("%s %d", (o->L4_proto == NL_TYPE_TCP) ? "TCP" : "UDP", ntohs(o->L4_addr));
      label = gtk_label_new(str);
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+2, row, row+1);
      g_free(str);

      str = g_strdup_printf("%s [%s]", 
            service_search(o->L4_addr, o->L4_proto), 
            (o->banner) ? o->banner : "");
      label = gtk_label_new(str);
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
      gtk_table_attach_defaults(GTK_TABLE(table), label, col+2, col+3, row, row+1);
      g_free(str);

      LIST_FOREACH(u, &(o->users_list_head), next) {
         row++;
         if (u->failed)
            label = gtk_label_new("Account: *");
         else
            label = gtk_label_new("Account:");
         gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
         gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

         str = g_strdup_printf("%s / %s (%s)", u->user, u->pass, ip_addr_ntoa(&u->client, tmp));
         label = gtk_label_new(str);
         gtk_label_set_selectable(GTK_LABEL(label), TRUE);
         gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
         gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);
         g_free(str);

         if (u->info) {
            row++;
            label = gtk_label_new("Info:");
            gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
            gtk_table_attach(GTK_TABLE(table), label, col, col+1, row, row+1, GTK_FILL, GTK_FILL, 0, 0);

            label = gtk_label_new(u->info);
            gtk_label_set_selectable(GTK_LABEL(label), TRUE);
            gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
            gtk_table_attach_defaults(GTK_TABLE(table), label, col+1, col+3, row, row+1);
         }
      }
   }
   /* resize table to the actual size */
   gtk_table_resize(GTK_TABLE(table), row, ncols);


   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

   button = gtk_button_new_from_stock(GTK_STOCK_CLOSE);
   g_signal_connect_swapped(G_OBJECT(button), "clicked", 
         G_CALLBACK(gtkui_profile_detail_destroy), dwindow);
   gtk_box_pack_end(GTK_BOX(hbox), button, FALSE, FALSE, 0);
   gtk_widget_grab_focus(button);
   
   gtk_widget_show_all(dwindow);

}

static void gtkui_profile_detail_destroy(GtkWidget *widget, gpointer *data)
{
   (void)data;

   if (detail_timer)
      g_source_remove(detail_timer);

   gtk_widget_destroy(widget);
}

static void gtkui_profiles_local(void)
{
   profile_purge_local();
   gtk_list_store_clear(GTK_LIST_STORE (ls_profiles));
}

static void gtkui_profiles_remote(void)
{
   profile_purge_remote();
   gtk_list_store_clear(GTK_LIST_STORE (ls_profiles));
}

static void gtkui_profiles_convert(void)
{
   profile_convert_to_hostlist();
   gtkui_refresh_host_list(NULL);
   gtkui_message("The hosts list was populated with local profiles");
}

static void gtkui_profiles_dump(void *dummy)
{
   /* variable not used */
   (void) dummy;

   DEBUG_MSG("gtkui_profiles_dump");

   /* make sure to free if already set */
   SAFE_FREE(logfile);
   SAFE_CALLOC(logfile, 50, sizeof(char));

   gtkui_input("Log File :", logfile, 50, dump_profiles);

}

static void dump_profiles(void)
{
   /* dump the profiles */
   if (profile_dump_to_file(logfile) == E_SUCCESS)
      gtkui_message("Profiles dumped to file");
}

static struct host_profile *gtkui_profile_selected(void) {
   GtkTreeIter iter;
   GtkTreeModel *model;
   struct host_profile *h = NULL;

   model = GTK_TREE_MODEL (ls_profiles);

   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 4, &h, -1);
   } else
      return(NULL); /* nothing is selected */

   return(h);
}

/* EOF */

// vim:ts=3:expandtab

