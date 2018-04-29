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
#include <ec_strings.h>

/* proto */

static void set_targets(void);
static void gtkui_add_target1(void *);
static void gtkui_add_target2(void *);
static void add_target1(void);
static void add_target2(void);
static void gtkui_delete_targets(GtkWidget *widget, gpointer data);
static void gtkui_targets_destroy(void);
static void gtkui_targets_detach(GtkWidget *child);
static void gtkui_targets_attach(void);

/* globals */

static char thost[MAX_ASCII_ADDR_LEN];

GtkWidget    *targets_window = NULL;
GtkTreeSelection *selection1 = NULL;
GtkTreeSelection *selection2 = NULL;
GtkListStore     *liststore1 = NULL;
GtkListStore     *liststore2 = NULL;

/*******************************************/

void toggle_reverse(void)
{
   if (EC_GBL_OPTIONS->reversed) {
      EC_GBL_OPTIONS->reversed = 0;
   } else {
      EC_GBL_OPTIONS->reversed = 1;
   }
}

/*
 * wipe the targets struct setting both T1 and T2 to ANY/ANY/ANY
 */
void wipe_targets(void)
{
   DEBUG_MSG("wipe_targets");
   
   reset_display_filter(EC_GBL_TARGET1);
   reset_display_filter(EC_GBL_TARGET2);

   /* update the GTK liststores */
   gtkui_create_targets_array();

   /* display the message */
   gtkui_message("TARGETS were reset to ANY/ANY/ANY");
}

/*
 * display the protocol dialog
 */
void gtkui_select_protocol(void)
{
   GtkWidget *dialog, *content, *radio, *hbox, *frame;
   GSList *list = NULL;
   gint active = 1;
   enum {proto_udp, proto_tcp, proto_all};

   DEBUG_MSG("gtk_select_protocol");

   /* this will contain 'all', 'tcp' or 'udp' */
   if (!EC_GBL_OPTIONS->proto) {
      SAFE_CALLOC(EC_GBL_OPTIONS->proto, 4, sizeof(char));
      strncpy(EC_GBL_OPTIONS->proto, "all", 3);
   }

   /* create dialog for selecting the protocol */
   dialog = gtk_dialog_new_with_buttons("Set protocol", GTK_WINDOW(window),
                                        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
                                        GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        NULL);
   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

   frame = gtk_frame_new("Select the protocol");
   gtk_container_add(GTK_CONTAINER(content), frame);

   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 10, FALSE);
   gtk_container_add(GTK_CONTAINER(frame), hbox);

   radio = gtk_radio_button_new_with_mnemonic(NULL, "a_ll");
   gtk_box_pack_start(GTK_BOX(hbox), radio, TRUE, TRUE, 2);
   if (!strncasecmp(EC_GBL_OPTIONS->proto, "all", 4))
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio), TRUE);

   radio = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(radio), "_tcp");
   gtk_box_pack_start(GTK_BOX(hbox), radio, TRUE, TRUE, 2);
   if (!strncasecmp(EC_GBL_OPTIONS->proto, "tcp", 4))
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio), TRUE);

   radio = gtk_radio_button_new_with_mnemonic_from_widget(GTK_RADIO_BUTTON(radio), "_udp");
   gtk_box_pack_start(GTK_BOX(hbox), radio, TRUE, TRUE, 2);
   if (!strncasecmp(EC_GBL_OPTIONS->proto, "udp", 4))
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(radio), TRUE);


   gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK));
   gtk_widget_show_all(dialog);

   if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
      list = gtk_radio_button_get_group(GTK_RADIO_BUTTON(radio));
      for(active = 0; list != NULL; list = list->next) {
         if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(list->data))) {
            switch (active) {
               case proto_all:
                  strncpy(EC_GBL_OPTIONS->proto, "all", 4);
                  break;
               case proto_tcp:
                  strncpy(EC_GBL_OPTIONS->proto, "tcp", 4);
                  break;
               case proto_udp:
                  strncpy(EC_GBL_OPTIONS->proto, "udp", 4);
                  break;
            }
         }
         active++;
      } 
   }

   gtk_widget_destroy(dialog);

}

/*
 * display the TARGET(s) dialog
 */
void gtkui_select_targets(void)
{
   GtkWidget *dialog, *label, *table, *content;  
   GtkWidget *frame1, *frame2;
   GtkWidget *t1_mac, *t1_ip, *t1_port, *t2_mac, *t2_ip, *t2_port;
   gint ncols = 2, nrows = 3;
#ifdef WITH_IPV6
   GtkWidget *t1_ipv6, *t2_ipv6;
   nrows = 4;
#endif

#define TARGET_LEN ETH_ASCII_ADDR_LEN + 1 + \
                   IP_ASCII_ADDR_LEN + 1 + \
                   IP6_ASCII_ADDR_LEN + 1 + \
                   5 + 1

   DEBUG_MSG("gtk_select_targets");

   dialog = gtk_dialog_new_with_buttons("Enter Targets", GTK_WINDOW(window),
                                        GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT, 
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, 
                                        GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        NULL);
   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_set_border_width(GTK_CONTAINER(content), 20);

   frame1 = gtk_frame_new("Target 1");
   gtk_container_add(GTK_CONTAINER(content), frame1);

   frame2 = gtk_frame_new("Target 2");
   gtk_container_add(GTK_CONTAINER(content), frame2);

   table = gtk_table_new(nrows, ncols, FALSE);
   gtk_table_set_row_spacings(GTK_TABLE (table), 5);
   gtk_table_set_col_spacings(GTK_TABLE (table), 5);
   gtk_container_set_border_width(GTK_CONTAINER (table), 8);
   gtk_container_add(GTK_CONTAINER (frame1), table);

   label = gtk_label_new("MAC:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE (table), label, 0, 1, 0, 1, GTK_FILL, GTK_FILL, 0, 0);

   t1_mac = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(t1_mac), MAX_ASCII_ADDR_LEN);
   gtk_entry_set_width_chars(GTK_ENTRY(t1_mac), MAX_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE(table), t1_mac, 1, 2, 0, 1);

   label = gtk_label_new("IP address:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE(table), label, 0, 1, 1, 2, GTK_FILL, GTK_FILL, 0, 0);

   t1_ip = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(t1_ip), MAX_ASCII_ADDR_LEN);
   gtk_entry_set_width_chars(GTK_ENTRY(t1_ip), MAX_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE(table), t1_ip, 1, 2, 1, 2);

#ifdef WITH_IPV6
   label = gtk_label_new("IPv6 address:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE(table), label, 0, 1, 2, 3, GTK_FILL, GTK_FILL, 0, 0);

   t1_ipv6 = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(t1_ipv6), MAX_ASCII_ADDR_LEN);
   gtk_entry_set_width_chars(GTK_ENTRY(t1_ipv6), MAX_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE(table), t1_ipv6, 1, 2, 2, 3);
#endif

   label = gtk_label_new("Port:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE(table), label, 0, 1, nrows-1, nrows, GTK_FILL, GTK_FILL, 0, 0);

   t1_port = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(t1_port), MAX_ASCII_ADDR_LEN);
   gtk_entry_set_width_chars(GTK_ENTRY(t1_port), MAX_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE(table), t1_port, 1, 2, nrows-1, nrows);

   /* Fill previously set values */
   if (EC_GBL_OPTIONS->target1) {
      gchar **tokens, **p;
      tokens = g_strsplit(EC_GBL_OPTIONS->target1, "/", nrows);
      p = tokens;

      /* MAC */
      gtk_entry_set_text(GTK_ENTRY(t1_mac), *p++);
      /* IP address */
      gtk_entry_set_text(GTK_ENTRY(t1_ip), *p++);
#ifdef WITH_IPV6
      /* IPv6 address */
      gtk_entry_set_text(GTK_ENTRY(t1_ipv6), *p++);
#endif
      /* Port */
      gtk_entry_set_text(GTK_ENTRY(t1_port), *p);

      g_strfreev(tokens);
   }



   /* Target 2: */
   table = gtk_table_new(nrows, ncols, FALSE);
   gtk_table_set_row_spacings(GTK_TABLE (table), 5);
   gtk_table_set_col_spacings(GTK_TABLE (table), 5);
   gtk_container_set_border_width(GTK_CONTAINER (table), 8);
   gtk_container_add(GTK_CONTAINER (frame2), table);

   label = gtk_label_new("MAC:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE (table), label, 0, 1, 0, 1, GTK_FILL, GTK_FILL, 0, 0);

   t2_mac = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(t2_mac), MAX_ASCII_ADDR_LEN);
   gtk_entry_set_width_chars(GTK_ENTRY(t2_mac), MAX_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE(table), t2_mac, 1, 2, 0, 1);

   label = gtk_label_new("IP address:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE(table), label, 0, 1, 1, 2, GTK_FILL, GTK_FILL, 0, 0);

   t2_ip = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(t2_ip), MAX_ASCII_ADDR_LEN);
   gtk_entry_set_width_chars(GTK_ENTRY(t2_ip), MAX_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE(table), t2_ip, 1, 2, 1, 2);

#ifdef WITH_IPV6
   label = gtk_label_new("IPv6 address:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE(table), label, 0, 1, 2, 3, GTK_FILL, GTK_FILL, 0, 0);

   t2_ipv6 = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(t2_ipv6), MAX_ASCII_ADDR_LEN);
   gtk_entry_set_width_chars(GTK_ENTRY(t2_ipv6), MAX_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE(table), t2_ipv6, 1, 2, 2, 3);
#endif

   label = gtk_label_new("Port:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_table_attach(GTK_TABLE(table), label, 0, 1, nrows-1, nrows, GTK_FILL, GTK_FILL, 0, 0);

   t2_port = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(t2_port), MAX_ASCII_ADDR_LEN);
   gtk_entry_set_width_chars(GTK_ENTRY(t2_port), MAX_ASCII_ADDR_LEN);
   gtk_table_attach_defaults(GTK_TABLE(table), t2_port, 1, 2, nrows-1, nrows);

   /* Fill previously set values */
   if (EC_GBL_OPTIONS->target2) {
      gchar **tokens, **p;
      tokens = g_strsplit(EC_GBL_OPTIONS->target2, "/", nrows);
      p = tokens;

      /* MAC */
      gtk_entry_set_text(GTK_ENTRY(t2_mac), *p++);
      /* IP address */
      gtk_entry_set_text(GTK_ENTRY(t2_ip), *p++);
#ifdef WITH_IPV6
      /* IPv6 address */
      gtk_entry_set_text(GTK_ENTRY(t2_ipv6), *p++);
#endif
      /* Port */
      gtk_entry_set_text(GTK_ENTRY(t2_port), *p);

      g_strfreev(tokens);
   }

   gtk_widget_show_all(dialog);

   if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);

      SAFE_FREE(EC_GBL_OPTIONS->target1);
      SAFE_FREE(EC_GBL_OPTIONS->target2);

      SAFE_CALLOC(EC_GBL_OPTIONS->target1, TARGET_LEN, sizeof(char));
      SAFE_CALLOC(EC_GBL_OPTIONS->target2, TARGET_LEN, sizeof(char));

#ifdef WITH_IPV6
      snprintf(EC_GBL_OPTIONS->target1, TARGET_LEN, "%s/%s/%s/%s",
            gtk_entry_get_text(GTK_ENTRY(t1_mac)),
            gtk_entry_get_text(GTK_ENTRY(t1_ip)),
            gtk_entry_get_text(GTK_ENTRY(t1_ipv6)),
            gtk_entry_get_text(GTK_ENTRY(t1_port)));

      snprintf(EC_GBL_OPTIONS->target2, TARGET_LEN, "%s/%s/%s/%s",
            gtk_entry_get_text(GTK_ENTRY(t2_mac)),
            gtk_entry_get_text(GTK_ENTRY(t2_ip)),
            gtk_entry_get_text(GTK_ENTRY(t2_ipv6)),
            gtk_entry_get_text(GTK_ENTRY(t2_port)));
#else
      snprintf(EC_GBL_OPTIONS->target1, TARGET_LEN, "%s/%s/%s",
            gtk_entry_get_text(GTK_ENTRY(t1_mac)),
            gtk_entry_get_text(GTK_ENTRY(t1_ip)),
            gtk_entry_get_text(GTK_ENTRY(t1_port)));

      snprintf(EC_GBL_OPTIONS->target2, TARGET_LEN, "%s/%s/%s",
            gtk_entry_get_text(GTK_ENTRY(t2_mac)),
            gtk_entry_get_text(GTK_ENTRY(t2_ip)),
            gtk_entry_get_text(GTK_ENTRY(t2_port)));
#endif

      set_targets();
   }
   gtk_widget_destroy(dialog);
}

/*
 * set the targets 
 */
static void set_targets(void)
{
   /* delete the previous filters */
   reset_display_filter(EC_GBL_TARGET1);
   reset_display_filter(EC_GBL_TARGET2);

   /* free empty filters */
   if (!strcmp(EC_GBL_OPTIONS->target1, ""))
      SAFE_FREE(EC_GBL_OPTIONS->target1);
   
   /* free empty filters */
   if (!strcmp(EC_GBL_OPTIONS->target2, ""))
      SAFE_FREE(EC_GBL_OPTIONS->target2);
   
   /* compile the filters */
   compile_display_filter();

   /* if the 'current targets' window is displayed, refresh it */
   if (targets_window)
      gtkui_current_targets();
}

/*
 * display the list of current targets
 */
void gtkui_current_targets(void)
{
   GtkWidget *scrolled, *treeview, *vbox, *hbox, *button;
   GtkCellRenderer   *renderer;
   GtkTreeViewColumn *column;
   static gint delete_targets1 = 1;
   static gint delete_targets2 = 2;

   DEBUG_MSG("gtk_current_targets");

   /* prepare the liststores for the target lists */
   gtkui_create_targets_array();
  
   if(targets_window) {
      if(GTK_IS_WINDOW (targets_window))
         gtk_window_present(GTK_WINDOW (targets_window));
      else
         gtkui_page_present(targets_window);
      return;
   }

   targets_window = gtkui_page_new("Targets", &gtkui_targets_destroy, &gtkui_targets_detach);

   vbox= gtkui_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
   gtk_container_add(GTK_CONTAINER (targets_window), vbox);
   gtk_widget_show(vbox);

   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 5, TRUE);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 0);
   gtk_widget_show(hbox);

   /* list one */
   scrolled = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scrolled), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX(hbox), scrolled, TRUE, TRUE, 0);
   gtk_widget_show(scrolled);

   treeview = gtk_tree_view_new();
   gtk_tree_view_set_model(GTK_TREE_VIEW (treeview), GTK_TREE_MODEL (liststore1));
   gtk_container_add(GTK_CONTAINER (scrolled), treeview);
   gtk_widget_show(treeview);

   selection1 = gtk_tree_view_get_selection (GTK_TREE_VIEW (treeview));
   gtk_tree_selection_set_mode (selection1, GTK_SELECTION_MULTIPLE);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Target 1", renderer, "text", 0, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 0);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   /* list two */
   scrolled = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scrolled), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scrolled), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX(hbox), scrolled, TRUE, TRUE, 0);
   gtk_widget_show(scrolled);

   treeview = gtk_tree_view_new();
   gtk_tree_view_set_model(GTK_TREE_VIEW (treeview), GTK_TREE_MODEL (liststore2));
   gtk_container_add(GTK_CONTAINER (scrolled), treeview);
   gtk_widget_show(treeview);

   selection2 = gtk_tree_view_get_selection (GTK_TREE_VIEW (treeview));
   gtk_tree_selection_set_mode (selection2, GTK_SELECTION_MULTIPLE);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Target 2", renderer, "text", 0, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 0);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   /* buttons */
   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 5, TRUE);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

   button = gtk_button_new_with_mnemonic("Delete");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_delete_targets), &delete_targets1);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   button = gtk_button_new_with_mnemonic("Add");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_add_target1), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   button = gtk_button_new_with_mnemonic("Delete");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_delete_targets), &delete_targets2);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   button = gtk_button_new_with_mnemonic("Add");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_add_target2), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);

   gtk_widget_show_all(hbox);
   gtk_widget_show(targets_window);
}

static void gtkui_targets_detach(GtkWidget *child)
{
   targets_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (targets_window), "Current Targets");
   gtk_window_set_default_size(GTK_WINDOW (targets_window), 400, 300);
   g_signal_connect (G_OBJECT (targets_window), "delete_event", G_CALLBACK (gtkui_targets_destroy), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(targets_window, gtkui_targets_attach);

   gtk_container_add(GTK_CONTAINER (targets_window), child);

   gtk_window_present(GTK_WINDOW (targets_window));
}

static void gtkui_targets_attach(void)
{
   gtkui_targets_destroy();
   gtkui_current_targets();
}

static void gtkui_targets_destroy(void)
{
   gtk_widget_destroy(targets_window);
   targets_window = NULL;
}

/*
 * create the array for the widget.
 * erase any previously alloc'd array 
 */
void gtkui_create_targets_array(void)
{
   GtkTreeIter iter;
   struct ip_list *il;
   char tmp[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG("gtk_create_targets_array");

   if(liststore1)
      gtk_list_store_clear(GTK_LIST_STORE (liststore1));
   else
      liststore1 = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_POINTER);
   
   /* walk TARGET 1 */
   LIST_FOREACH(il, &EC_GBL_TARGET1->ips, next) {
      /* enlarge the array */
      gtk_list_store_append (liststore1, &iter);
      /* fill the element */
      gtk_list_store_set (liststore1, &iter, 0, ip_addr_ntoa(&il->ip, tmp), 1, il, -1);
   }

#ifdef WITH_IPV6
   /* walk TARGET 1 - IPv6 */
   LIST_FOREACH(il, &EC_GBL_TARGET1->ip6, next) {
      /* enlarge the array */
      gtk_list_store_append (liststore1, &iter);
      /* fill the element */
      gtk_list_store_set (liststore1, &iter, 0, ip_addr_ntoa(&il->ip, tmp), 1, il, -1);
   }
#endif

   if(liststore2)
      gtk_list_store_clear(GTK_LIST_STORE (liststore2));
   else
      liststore2 = gtk_list_store_new (2, G_TYPE_STRING, G_TYPE_POINTER);
   
   /* walk TARGET 2 */
   LIST_FOREACH(il, &EC_GBL_TARGET2->ips, next) {
      /* enlarge the array */
      gtk_list_store_append (liststore2, &iter);
      /* fill the element */
      gtk_list_store_set (liststore2, &iter, 0, ip_addr_ntoa(&il->ip, tmp), 1, il, -1);
   }
   
#ifdef WITH_IPV6
   /* walk TARGET 2 - IPv6 */
   LIST_FOREACH(il, &EC_GBL_TARGET2->ip6, next) {
      /* enlarge the array */
      gtk_list_store_append (liststore2, &iter);
      /* fill the element */
      gtk_list_store_set (liststore2, &iter, 0, ip_addr_ntoa(&il->ip, tmp), 1, il, -1);
   }
#endif
}

/*
 * display the "add host" dialog
 */
static void gtkui_add_target1(void *entry)
{
   /* variable not used */
   (void) entry;

   DEBUG_MSG("gtk_add_target1");

   gtkui_input("IP address :", thost, MAX_ASCII_ADDR_LEN, add_target1);
}

static void gtkui_add_target2(void *entry)
{
   /* variable not used */
   (void) entry;

   DEBUG_MSG("gtk_add_target2");

   gtkui_input("IP address :", thost, MAX_ASCII_ADDR_LEN, add_target2);
}

static void add_target1(void)
{
   struct ip_addr host;
   
   if (ip_addr_pton(thost, &host) != E_SUCCESS) {
      /* neither IPv4 nor IPv6 - inform user */
      gtkui_message("Invalid ip address");
      return;
   }
   
   add_ip_list(&host, EC_GBL_TARGET1);
   
   /* refresh the list */
   gtkui_create_targets_array();
}

static void add_target2(void)
{
   struct ip_addr host;
   
   if (ip_addr_pton(thost, &host) != E_SUCCESS) {
      /* neither IPv4 nor IPv6 - inform user */
      gtkui_message("Invalid ip address");
      return;
   }
   
   add_ip_list(&host, EC_GBL_TARGET2);
   
   /* refresh the list */
   gtkui_create_targets_array();
}

static void gtkui_delete_targets(GtkWidget *widget, gpointer data) {
   GList *list = NULL;
   GtkTreeIter iter;
   GtkTreeModel *model;
   struct ip_list *il = NULL;
   gint *type = data;

   /* variable not used */
   (void) widget;

   if (type == NULL)
       return;

   switch(*type) {
      case 1:
         DEBUG_MSG("gtkui_delete_target: list 1");
         model = GTK_TREE_MODEL (liststore1);

         if(gtk_tree_selection_count_selected_rows(selection1) > 0) {
            list = gtk_tree_selection_get_selected_rows (selection1, &model);
            for(list = g_list_last(list); list; list = g_list_previous(list)) {
               gtk_tree_model_get_iter(model, &iter, list->data);
               gtk_tree_model_get (model, &iter, 1, &il, -1);

               /* remove the host from the list */
               del_ip_list(&il->ip, EC_GBL_TARGET1);

               gtk_list_store_remove(GTK_LIST_STORE (liststore1), &iter);
            }
         }
         break;
      case 2:
         DEBUG_MSG("gtkui_delete_target: list 2");
         model = GTK_TREE_MODEL (liststore2);

         if(gtk_tree_selection_count_selected_rows(selection2) > 0) {
            list = gtk_tree_selection_get_selected_rows (selection2, &model);
            for(list = g_list_last(list); list; list = g_list_previous(list)) {
               gtk_tree_model_get_iter(model, &iter, list->data);
               gtk_tree_model_get (model, &iter, 1, &il, -1);

               /* remove the host from the list */
               del_ip_list(&il->ip, EC_GBL_TARGET2);

               gtk_list_store_remove(GTK_LIST_STORE (liststore2), &iter);
            }
         }
         break;
   }
   
   /* free the list of selections */
   if(list) {
      g_list_foreach (list,(GFunc) gtk_tree_path_free, NULL);
      g_list_free (list);
   }
}

/* EOF */

// vim:ts=3:expandtab

