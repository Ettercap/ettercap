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

    $Id: ec_gtk_view_connections.c,v 1.14 2004/03/04 13:16:24 daten Exp $
*/

#include <ec.h>
#include <ec_gtk.h>
#include <ec_conntrack.h>
#include <ec_manuf.h>
#include <ec_services.h>
#include <ec_strings.h>
#include <ec_format.h>
#include <ec_inject.h>

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* proto */

void gtkui_show_connections(void);
static void gtkui_connections_detach(GtkWidget *child);
static void gtkui_connections_attach(void);
static void gtkui_kill_connections(void);
static gboolean refresh_connections(gpointer data);
static void gtkui_connection_detail(void);
static void gtkui_connection_data(void);
static void gtkui_connection_data_split(void);
static void gtkui_connection_data_join(void);
static void gtkui_connection_data_detach(GtkWidget *child);
static void gtkui_connection_data_attach(void);
static void gtkui_destroy_conndata(void);
static void gtkui_data_print(int buffer, char *data, int color);
static void split_print(u_char *text, size_t len, struct ip_addr *L3_src);
static void split_print_po(struct packet_object *po);
static void join_print(u_char *text, size_t len, struct ip_addr *L3_src);
static void join_print_po(struct packet_object *po);
static void gtkui_connection_kill(void *conn);
static void gtkui_connection_kill_wrapper(void);
static void gtkui_connection_inject(void);
static void gtkui_inject_user(int side);
static void gtkui_connection_inject_file(void);
static void gtkui_inject_file(char *filename, int side);

extern void conntrack_lock(void);
extern void conntrack_unlock(void);

/*** globals ***/

/* connection list */
static GtkWidget *conns_window = NULL;
static GtkWidget     *treeview = NULL; 
static GtkListStore  *ls_conns = NULL;
static GtkTreeSelection   *selection = NULL;
static struct conn_object *curr_conn = NULL;
static guint connections_idle = 0;

/* split data view */
static GtkWidget   *data_window = NULL;
static GtkWidget     *textview1 = NULL;
static GtkWidget     *textview2 = NULL;
static GtkWidget     *textview3 = NULL;
static GtkTextBuffer *splitbuf1 = NULL;
static GtkTextBuffer *splitbuf2 = NULL;
static GtkTextBuffer *joinedbuf = NULL;
static GtkTextMark    *endmark1 = NULL;
static GtkTextMark    *endmark2 = NULL;
static GtkTextMark    *endmark3 = NULL;

static pthread_mutex_t display_mutex = PTHREAD_MUTEX_INITIALIZER;
#define DISPLAY_LOCK     do{ pthread_mutex_lock(&display_mutex); } while(0)
#define DISPLAY_UNLOCK   do{ pthread_mutex_unlock(&display_mutex); } while(0)

/* keep it global, so the memory region is always the same (reallocing it) */
static u_char *dispbuf;
static u_char *injectbuf;

/*******************************************/

/*
 * the auto-refreshing list of connections
 */
void gtkui_show_connections(void)
{
   GtkWidget *scrolled, *vbox, *items, *hbox, *button;
   GtkWidget *context_menu;
   GtkCellRenderer   *renderer;
   GtkTreeViewColumn *column;

   DEBUG_MSG("gtk_show_connections");

   /* if the object already exist, set the focus to it */
   if (conns_window) {
      if(GTK_IS_WINDOW (conns_window))
         gtk_window_present(GTK_WINDOW (conns_window));
      else
         gtkui_page_present(conns_window);
      return;
   }

   conns_window = gtkui_page_new("Connections", &gtkui_kill_connections, &gtkui_connections_detach);

   vbox = gtk_vbox_new(FALSE, 0);
   gtk_container_add(GTK_CONTAINER (conns_window), vbox);
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
   g_signal_connect (G_OBJECT (treeview), "row_activated", G_CALLBACK (gtkui_connection_data), NULL);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes (" ", renderer, "text", 0, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 0);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Host       ", renderer, "text", 1, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 1);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Port", renderer, "text", 2, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 2);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("-", renderer, "text", 3, NULL);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Host       ", renderer, "text", 4, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 4);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Port", renderer, "text", 5, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 5);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Proto", renderer, "text", 6, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 6);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("State", renderer, "text", 7, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 7);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Bytes", renderer, "text", 8, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 8);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   hbox = gtk_hbox_new(TRUE, 5);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
   gtk_widget_show(hbox);

   button = gtk_button_new_with_mnemonic("View _Details");
   g_signal_connect (G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_detail), NULL);
   
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   button = gtk_button_new_with_mnemonic("_Kill Connection");
   g_signal_connect (G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_kill), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

  /* context menu */
   context_menu = gtk_menu_new ();
   
   items = gtk_menu_item_new_with_label ("View Details");
   gtk_menu_shell_append (GTK_MENU_SHELL (context_menu), items);
   g_signal_connect (G_OBJECT (items), "activate", G_CALLBACK (gtkui_connection_detail), NULL);
   gtk_widget_show (items);

   items = gtk_menu_item_new_with_label ("Kill Connection");
   gtk_menu_shell_append (GTK_MENU_SHELL (context_menu), items);
   g_signal_connect (G_OBJECT (items), "activate", G_CALLBACK (gtkui_connection_kill), NULL);
   gtk_widget_show (items);

   g_signal_connect(G_OBJECT(treeview), "button-press-event", G_CALLBACK(gtkui_context_menu), context_menu);

   /* initialize the list */
   refresh_connections(NULL);

   gtk_tree_view_set_model(GTK_TREE_VIEW (treeview), GTK_TREE_MODEL (ls_conns));

   /* refresh the list every 500 ms */
   /* gtk_idle_add refreshes too fast, uses all cpu */
   connections_idle = gtk_timeout_add(500, refresh_connections, NULL);

   gtk_widget_show(conns_window);
}

void gtkui_connections_detach(GtkWidget *child)
{
   conns_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (conns_window), "Live connections");
   gtk_window_set_default_size(GTK_WINDOW (conns_window), 500, 250);
   g_signal_connect(G_OBJECT(conns_window), "delete_event", G_CALLBACK(gtkui_kill_connections), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(conns_window, gtkui_connections_attach);

   gtk_container_add(GTK_CONTAINER (conns_window), child);

   gtk_window_present(GTK_WINDOW (conns_window));
}

static void gtkui_connections_attach(void)
{
   gtkui_kill_connections();
   gtkui_show_connections();
}

static void gtkui_kill_connections(void)
{
   DEBUG_MSG("gtk_kill_connections");
   gtk_timeout_remove(connections_idle);

   gtk_widget_destroy(conns_window);
   conns_window = NULL;
}

static gboolean refresh_connections(gpointer data)
{
   struct conn_tail *c = NULL;
   struct conn_tail *cl = NULL;
   struct conn_tail *curr = NULL;
   char src[MAX_ASCII_ADDR_LEN];
   char dst[MAX_ASCII_ADDR_LEN];
   char *proto = "", *status = "", *flags = " ";
   GtkTreeIter iter, *next = NULL;
   GtkTreeModel *model = NULL;
   gboolean gotiter = FALSE;
   guint now = time(NULL), check = 0;

   if(ls_conns) {
      if (!GTK_WIDGET_VISIBLE(conns_window))
         return(FALSE);
   } else {
      ls_conns = gtk_list_store_new (11, 
                    G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, 
                    G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, 
                    G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, 
                    G_TYPE_POINTER, G_TYPE_UINT);
   }

   /* get first item in connection list */
   cl = conntrack_print(0, NULL, NULL, 0);
   if (cl == NULL)
      return(TRUE);

   /* get iter for first item in list widget */
   model = GTK_TREE_MODEL(ls_conns);

   for (c = cl; c != NULL; c = c->next.tqe_next) {

      /* initialize it */
      flags = " ";

      /* we'll set status on new and old items */
      switch (c->co->status) {
         case CONN_IDLE:    status = "idle   "; break;
         case CONN_OPENING: status = "opening"; break;
         case CONN_OPEN:    status = "open   "; break;
         case CONN_ACTIVE:  status = "active "; break;
         case CONN_CLOSING: status = "closing"; break;
         case CONN_CLOSED:  status = "closed "; break;
         case CONN_KILLED:  status = "killed "; break;
      }
      
      /* determine the flags */
      if (c->co->flags & CONN_MODIFIED)
         flags = "M";
      if (c->co->flags & CONN_INJECTED)
         flags = "I";
      if (c->co->DISSECTOR.user)
         flags = "X";
      
      /* see if the item is already in our list */
      gotiter = gtk_tree_model_get_iter_first(model, &iter);
      while (gotiter) {
         gtk_tree_model_get (model, &iter, 9, &curr, -1);
         if(c == curr) {
            gtk_list_store_set (ls_conns, &iter,
                                0, flags, 7, status, 8, c->co->xferred, 10, now, -1);
            break;
         }
         gotiter = gtk_tree_model_iter_next(model, &iter);
      }

      /* if it is, move on to next item */
      if (gotiter)
         continue;

      /* if we got here, we're making a new list item, set all values */
      switch (c->co->L4_proto) {
         case NL_TYPE_UDP: proto = "UDP"; break;
         case NL_TYPE_TCP: proto = "TCP"; break;
         default:          proto = "   "; break;
      }

      ip_addr_ntoa(&c->co->L3_addr1, src);
      ip_addr_ntoa(&c->co->L3_addr2, dst);

      gtk_list_store_append (ls_conns, &iter);
      gtk_list_store_set (ls_conns, &iter, 
                          0, flags, 1, src, 2, ntohs(c->co->L4_addr1),
                          3, "-",
                          4, dst, 5, ntohs(c->co->L4_addr2),
                          6, proto, 7, status, 8, c->co->xferred, 
                          9, c, 10, now, -1);
   }

   /* remove old connections */
   gotiter = gtk_tree_model_get_iter_first(model, &iter);
   while (gotiter) {
      gtk_tree_model_get (model, &iter, 10, &check, -1);

      if(check != now)
         next = gtk_tree_iter_copy(&iter);

      gotiter = gtk_tree_model_iter_next(model, &iter);

      if(next) {
         gtk_list_store_remove(GTK_LIST_STORE(ls_conns), next);
         gtk_tree_iter_free(next);
         next = NULL;
      }
   }

   return(TRUE);
}

/* 
 * details for a connection
 */
static void gtkui_connection_detail(void)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   GtkTextBuffer *textbuf;
   char line[200];
   struct conn_tail *c = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];
   char *proto = "";

   DEBUG_MSG("gtk_connection_detail");

   model = GTK_TREE_MODEL (ls_conns);

   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 9, &c, -1);
   } else
      return; /* nothing is selected */

   if(!c || !c->co)
      return;

   textbuf = gtkui_details_window("Connection Details");

   snprintf(line, 200, "Source MAC address: \t%s\n", mac_addr_ntoa(c->co->L2_addr1, tmp));
   gtkui_details_print(textbuf, line);

   snprintf(line, 200, "Destination MAC address: \t%s\n\n", mac_addr_ntoa(c->co->L2_addr2, tmp));
   gtkui_details_print(textbuf, line);


   snprintf(line, 200, "Source IP address: \t\t%s\n", ip_addr_ntoa(&(c->co->L3_addr1), tmp));
   gtkui_details_print(textbuf, line);

   snprintf(line, 200, "Destination IP address: \t%s\n\n", ip_addr_ntoa(&(c->co->L3_addr2), tmp));
   gtkui_details_print(textbuf, line);

      /* Protocol */
   switch (c->co->L4_proto) {
      case NL_TYPE_UDP:
         proto = "UDP";
         break;
      case NL_TYPE_TCP:
         proto = "TCP";
         break;
   }

   snprintf(line, 200, "Protocol: \t\t\t%s\n", proto);
   gtkui_details_print(textbuf, line);

   snprintf(line, 200, "Source port: \t\t%-5d  %s\n", ntohs(c->co->L4_addr1), service_search(c->co->L4_addr1, c->co->L4_proto));
   gtkui_details_print(textbuf, line);

   snprintf(line, 200, "Destination port: \t%-5d  %s\n\n", ntohs(c->co->L4_addr2), service_search(c->co->L4_addr2, c->co->L4_proto));
   gtkui_details_print(textbuf, line);

   snprintf(line, 200, "Transferred bytes: %d\n\n", c->co->xferred);
   gtkui_details_print(textbuf, line);

   /* Login Information */
   if (c->co->DISSECTOR.user) {
      snprintf(line, 200, "Account: \t%s / %s", c->co->DISSECTOR.user, c->co->DISSECTOR.pass);
      gtkui_details_print(textbuf, line);

      if (c->co->DISSECTOR.info) {
         snprintf(line, 200, "Additional Info: %s\n", c->co->DISSECTOR.info);
         gtkui_details_print(textbuf, line);
      }
   }
}

static void gtkui_connection_data(void)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   struct conn_tail *c = NULL;
   DEBUG_MSG("gtk_connection_data");

   model = GTK_TREE_MODEL (ls_conns);

   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 9, &c, -1);
   } else
      return; /* nothing is selected */

   if(c == NULL || c->co == NULL)
      return; /* just to be safe */
  
   /* 
    * remove any hook on the open connection.
    * this is done to prevent a switch of connection
    * with the panel opened
    */
   if (curr_conn) {
      conntrack_hook_conn_del(curr_conn, split_print_po);
      conntrack_hook_conn_del(curr_conn, join_print_po);
   }
   
   /* set the global variable to pass the parameter to other functions */
   curr_conn = c->co;
   
   /* default is split view */
   gtkui_connection_data_split();
}

/*
 * show the content of the connection
 */
static void gtkui_connection_data_split(void)
{
   GtkWidget *vbox, *scrolled, *label, *child;
   GtkWidget *hbox_big, *hbox_small, *button;
   GtkTextIter iter;
   char tmp[MAX_ASCII_ADDR_LEN];
   char title[MAX_ASCII_ADDR_LEN+6];

   DEBUG_MSG("gtk_connection_data_split");

   /* if we're switching views, make sure old hook is gone */
   if(curr_conn)
      conntrack_hook_conn_del(curr_conn, join_print_po);

   if(data_window) {
      child = gtk_bin_get_child(GTK_BIN (data_window));
      gtk_container_remove(GTK_CONTAINER (data_window), child);
   } else {
      data_window = gtkui_page_new("Connection data", &gtkui_destroy_conndata, &gtkui_connection_data_detach);
   }

   hbox_big = gtk_hbox_new(TRUE, 5);
   gtk_container_add(GTK_CONTAINER(data_window), hbox_big);
   gtk_widget_show(hbox_big);

  /*** left side ***/
   vbox = gtk_vbox_new(FALSE, 0);
   gtk_box_pack_start(GTK_BOX(hbox_big), vbox, TRUE, TRUE, 0);
   gtk_widget_show(vbox);

  /* title */
   snprintf(title, MAX_ASCII_ADDR_LEN+6, "%s:%d", 
            ip_addr_ntoa(&curr_conn->L3_addr1, tmp), ntohs(curr_conn->L4_addr1));
   label = gtk_label_new(title);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0.5);
   gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
   gtk_widget_show(label);

  /* data */
   scrolled = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scrolled), 
                                  GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scrolled), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);
   gtk_widget_show(scrolled);

   textview1 = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (textview1), GTK_WRAP_CHAR);
   gtk_text_view_set_editable(GTK_TEXT_VIEW (textview1), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview1), FALSE);
   gtk_text_view_set_right_margin(GTK_TEXT_VIEW (textview1), 5);
   gtk_text_view_set_right_margin(GTK_TEXT_VIEW (textview1), 5);
   gtk_container_add(GTK_CONTAINER (scrolled), textview1);
   gtk_widget_show(textview1);

   splitbuf1 = gtk_text_view_get_buffer(GTK_TEXT_VIEW (textview1));
   gtk_text_buffer_create_tag (splitbuf1, "blue_fg", "foreground", "blue", NULL);
   gtk_text_buffer_create_tag (splitbuf1, "monospace", "family", "monospace", NULL);
   gtk_text_buffer_get_end_iter(splitbuf1, &iter);
   endmark1 = gtk_text_buffer_create_mark(splitbuf1, "end", &iter, FALSE);

  /* first two buttons */
   hbox_small = gtk_hbox_new(TRUE, 5);
   gtk_box_pack_start(GTK_BOX(vbox), hbox_small, FALSE, FALSE, 0);
   gtk_widget_show(hbox_small);

   button = gtk_button_new_with_mnemonic("_Join Views");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_data_join), NULL);
   gtk_box_pack_start(GTK_BOX(hbox_small), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   button = gtk_button_new_with_mnemonic("_Inject Data");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_inject), NULL);
   gtk_box_pack_start(GTK_BOX(hbox_small), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

  /*** right side ***/
   vbox = gtk_vbox_new(FALSE, 0);
   gtk_box_pack_start(GTK_BOX(hbox_big), vbox, TRUE, TRUE, 0);
   gtk_widget_show(vbox);

  /* title */
   snprintf(title, MAX_ASCII_ADDR_LEN+6, "%s:%d", 
            ip_addr_ntoa(&curr_conn->L3_addr2, tmp), ntohs(curr_conn->L4_addr2));
   label = gtk_label_new(title);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0.5);
   gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
   gtk_widget_show(label);

  /* data */
   scrolled = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scrolled),
                                  GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scrolled), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);
   gtk_widget_show(scrolled);

   textview2 = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (textview2), GTK_WRAP_CHAR);
   gtk_text_view_set_editable(GTK_TEXT_VIEW (textview2), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview2), FALSE);
   gtk_text_view_set_right_margin(GTK_TEXT_VIEW (textview2), 5);
   gtk_text_view_set_right_margin(GTK_TEXT_VIEW (textview2), 5);
   gtk_container_add(GTK_CONTAINER (scrolled), textview2);
   gtk_widget_show(textview2);

   splitbuf2 = gtk_text_view_get_buffer(GTK_TEXT_VIEW (textview2));
   gtk_text_buffer_create_tag (splitbuf2, "blue_fg", "foreground", "blue", NULL);
   gtk_text_buffer_create_tag (splitbuf2, "monospace", "family", "monospace", NULL);
   gtk_text_buffer_get_end_iter(splitbuf2, &iter);
   endmark2 = gtk_text_buffer_create_mark(splitbuf2, "end", &iter, FALSE);

  /* second two buttons */
   hbox_small = gtk_hbox_new(TRUE, 5);
   gtk_box_pack_start(GTK_BOX(vbox), hbox_small, FALSE, FALSE, 0);
   gtk_widget_show(hbox_small);

   button = gtk_button_new_with_mnemonic("Inject _File"); 
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_inject_file), NULL);
   gtk_box_pack_start(GTK_BOX(hbox_small), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   button = gtk_button_new_with_mnemonic("_Kill Connection");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_kill_wrapper), NULL);
   gtk_box_pack_start(GTK_BOX(hbox_small), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   /* print the old data */
   connbuf_print(&curr_conn->data, split_print);

   /* add the hook on the connection to receive data only from it */
   conntrack_hook_conn_add(curr_conn, split_print_po);

   gtk_widget_show(data_window);

   if(GTK_IS_WINDOW (data_window))
      gtk_window_present(GTK_WINDOW (data_window));
   else
      gtkui_page_present(data_window);
}

static void gtkui_connection_data_detach(GtkWidget *child)
{
   data_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (data_window), "Connection data");
   gtk_window_set_default_size(GTK_WINDOW (data_window), 600, 400);
   gtk_container_set_border_width(GTK_CONTAINER (data_window), 5);
   g_signal_connect(G_OBJECT(data_window), "delete_event", G_CALLBACK(gtkui_destroy_conndata), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(data_window, gtkui_connection_data_attach);

   gtk_container_add(GTK_CONTAINER(data_window), child);

   gtk_window_present(GTK_WINDOW (data_window));
}

static void gtkui_connection_data_attach(void)
{
   gtkui_destroy_conndata();
   gtkui_connection_data_split();
}

static void gtkui_destroy_conndata(void)
{
   DEBUG_MSG("gtkui_destroy_conndata");

   gtk_widget_destroy(data_window);
   data_window = NULL;
}

static void gtkui_data_print(int buffer, char *data, int color) 
{
   GtkTextIter iter;
   GtkTextBuffer *textbuf = NULL;
   GtkWidget *textview = NULL;
   GtkTextMark *endmark = NULL;

   DISPLAY_LOCK;
   switch(buffer) {
      case 1:
         textbuf = splitbuf1;
         textview = textview1;
         endmark = endmark1;
         break;
      case 2:
         textbuf = splitbuf2;
         textview = textview2;
         endmark = endmark2;
         break;
      case 3:
         textbuf = joinedbuf;
         textview = textview3;
         endmark = endmark3;
         break;
      default:
         return;
   }
   
   gtk_text_buffer_get_end_iter(textbuf, &iter);
   if(color == 2)
      gtk_text_buffer_insert_with_tags_by_name(textbuf, &iter, data, 
         -1, "blue_fg", "monospace", NULL);
   else
      gtk_text_buffer_insert_with_tags_by_name(textbuf, &iter, data, 
         -1, "monospace", NULL);
   gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW (textview), 
      endmark, 0, FALSE, 0, 0);
   DISPLAY_UNLOCK;
}

static void split_print(u_char *text, size_t len, struct ip_addr *L3_src)
{
   int ret;

   /* use the global to reuse the same memory region */
   SAFE_REALLOC(dispbuf, hex_len(len) * sizeof(u_char) + 1);
   
   /* format the data */
   ret = GBL_FORMAT(text, len, dispbuf);
   dispbuf[ret] = 0;

   if (!ip_addr_cmp(L3_src, &curr_conn->L3_addr1))
      gtkui_data_print(1, dispbuf, 0);
   else
      gtkui_data_print(2, dispbuf, 0);
}

static void split_print_po(struct packet_object *po)
{
   int ret;
   
   /* if not open don't refresh it */
   if (!data_window)
      return;
   
   /* use the global to reuse the same memory region */
   SAFE_REALLOC(dispbuf, hex_len(po->DATA.disp_len) * sizeof(u_char) + 1);
      
   /* format the data */
   ret = GBL_FORMAT(po->DATA.disp_data, po->DATA.disp_len, dispbuf);
   dispbuf[ret] = 0;
        
   gdk_threads_enter();
   if (!ip_addr_cmp(&po->L3.src, &curr_conn->L3_addr1))
      gtkui_data_print(1, dispbuf, 0);
   else
      gtkui_data_print(2, dispbuf, 0);
   gdk_threads_leave();
}

/*
 * show the data in a joined window 
 */
static void gtkui_connection_data_join(void)
{
   GtkWidget *hbox, *vbox, *label, *scrolled, *button, *child;
   GtkTextIter iter;
   #define TITLE_LEN (MAX_ASCII_ADDR_LEN * 2) + 6
   char src[MAX_ASCII_ADDR_LEN];
   char dst[MAX_ASCII_ADDR_LEN];
   char title[TITLE_LEN];

   DEBUG_MSG("gtk_connection_data_join");

   /* if we're switching views, make sure old hook is gone */
   if(curr_conn)
      conntrack_hook_conn_del(curr_conn, split_print_po);

   if(data_window) {
      child = gtk_bin_get_child(GTK_BIN (data_window));
      gtk_container_remove(GTK_CONTAINER (data_window), child);
   } else {
      data_window = gtkui_page_new("Connection data", &gtkui_destroy_conndata, &gtkui_connection_data_detach);
   }
   
   vbox = gtk_vbox_new(FALSE, 0);
   gtk_container_add(GTK_CONTAINER(data_window), vbox);
   gtk_widget_show(vbox);
   
  /* title */
   snprintf(title, TITLE_LEN, "%s:%d - %s:%d", 
            ip_addr_ntoa(&curr_conn->L3_addr1, src), ntohs(curr_conn->L4_addr1),
            ip_addr_ntoa(&curr_conn->L3_addr2, dst), ntohs(curr_conn->L4_addr2));
   label = gtk_label_new(title);
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0.5);
   gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
   gtk_widget_show(label);
   
  /* data */
   scrolled = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scrolled),
                                  GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scrolled), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);
   gtk_widget_show(scrolled);     
   
   textview3 = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (textview3), GTK_WRAP_CHAR);
   gtk_text_view_set_editable(GTK_TEXT_VIEW (textview3), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview3), FALSE);
   gtk_text_view_set_right_margin(GTK_TEXT_VIEW (textview3), 5);
   gtk_text_view_set_right_margin(GTK_TEXT_VIEW (textview3), 5);
   gtk_container_add(GTK_CONTAINER (scrolled), textview3);
   gtk_widget_show(textview3);

   joinedbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW (textview3));
   gtk_text_buffer_create_tag (joinedbuf, "blue_fg", "foreground", "blue", NULL);
   gtk_text_buffer_create_tag (joinedbuf, "monospace", "family", "monospace", NULL);
   gtk_text_buffer_get_end_iter(joinedbuf, &iter);
   endmark3 = gtk_text_buffer_create_mark(joinedbuf, "end", &iter, FALSE);

   hbox = gtk_hbox_new(TRUE, 5);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
   gtk_widget_show(hbox);

   button = gtk_button_new_with_mnemonic("_Split View");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_data_split), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   button = gtk_button_new_with_mnemonic("_Kill Connection");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_kill_wrapper), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   /* print the old data */
   connbuf_print(&curr_conn->data, join_print);

   /* add the hook on the connection to receive data only from it */
   conntrack_hook_conn_add(curr_conn, join_print_po);

   gtk_widget_show(data_window);

   if(GTK_IS_WINDOW (data_window))
      gtk_window_present(GTK_WINDOW (data_window));
   else
      gtkui_page_present(data_window);
}

static void join_print(u_char *text, size_t len, struct ip_addr *L3_src)
{
   int ret;
   
   /* use the global to reuse the same memory region */
   SAFE_REALLOC(dispbuf, hex_len(len) * sizeof(u_char) + 1);
   
   /* format the data */
   ret = GBL_FORMAT(text, len, dispbuf);
   dispbuf[ret] = 0;
   
   if (!ip_addr_cmp(L3_src, &curr_conn->L3_addr1))
      gtkui_data_print(3, dispbuf, 1);
   else
      gtkui_data_print(3, dispbuf, 2);
}

static void join_print_po(struct packet_object *po)
{
   int ret;

   /* if not focused don't refresh it */
   if (!data_window)
      return;
   
   /* use the global to reuse the same memory region */
   SAFE_REALLOC(dispbuf, hex_len(po->DATA.disp_len) * sizeof(u_char) + 1);
      
   /* format the data */
   ret = GBL_FORMAT(po->DATA.disp_data, po->DATA.disp_len, dispbuf);
   dispbuf[ret] = 0;
        
   gdk_threads_enter();
   if (!ip_addr_cmp(&po->L3.src, &curr_conn->L3_addr1))
      gtkui_data_print(3, dispbuf, 1);
   else
      gtkui_data_print(3, dispbuf, 2);
   gdk_threads_leave();
}

/*
 * kill the selected connection connection
 */
static void gtkui_connection_kill(void *conn)
{
   struct conn_object *c = (struct conn_object *)conn;
   
   DEBUG_MSG("gtk_connection_kill");
   
   /* kill it */
   user_kill(curr_conn);

   /* set the status */
   c->status = CONN_KILLED;
   gtkui_message("The connection was killed !!");
}

/*
 * call the specialized funtion as this is a callback 
 * without the parameter
 */
static void gtkui_connection_kill_wrapper(void)
{
   gtkui_connection_kill(curr_conn);
}

/*
 * inject interactively with the user
 */
static void gtkui_connection_inject(void)
{
   GtkWidget *dialog, *text, *label, *vbox, *frame;
   GtkWidget *button1, *button2, *hbox;
   GtkTextBuffer *buf;
   GtkTextIter start, end;
   char tmp[MAX_ASCII_ADDR_LEN];
   gint response = 0;

   DEBUG_MSG("gtk_connection_inject");

   if(curr_conn == NULL)
      return;

   dialog = gtk_dialog_new_with_buttons("Character Injection", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL, GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
   gtk_window_set_default_size(GTK_WINDOW (dialog), 400, 200);
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
   vbox = GTK_DIALOG (dialog)->vbox;

   label = gtk_label_new ("Packet source:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);
   gtk_widget_show(label);

   hbox = gtk_hbox_new(FALSE, 5);
   gtk_box_pack_start (GTK_BOX (vbox), hbox, FALSE, FALSE, 0);
   gtk_widget_show(hbox);

   button1 = gtk_radio_button_new_with_label(NULL, ip_addr_ntoa(&curr_conn->L3_addr1, tmp));
   gtk_box_pack_start(GTK_BOX(hbox), button1, FALSE, FALSE, 0);
   gtk_widget_show(button1);

   button2 = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (button1),
               ip_addr_ntoa(&curr_conn->L3_addr2, tmp));
   gtk_box_pack_start(GTK_BOX(hbox), button2, FALSE, FALSE, 0);
   gtk_widget_show(button2);

   label = gtk_label_new ("Characters to be injected:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);
   gtk_widget_show(label);

   frame = gtk_frame_new(NULL);
   gtk_frame_set_shadow_type(GTK_FRAME (frame), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX (vbox), frame, TRUE, TRUE, 5);
   gtk_widget_show(frame);

   text = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (text), GTK_WRAP_CHAR);
   gtk_container_add(GTK_CONTAINER (frame), text);
   gtk_widget_show(text);
    
   response = gtk_dialog_run(GTK_DIALOG(dialog));
   if(response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);

      SAFE_REALLOC(injectbuf, 501 * sizeof(char));
      memset(injectbuf, 0, 501);

      buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW (text));

      /* initialize iters for get text */
      gtk_text_buffer_get_start_iter(buf, &start);
      gtk_text_buffer_get_start_iter(buf, &end);
      /* advance end iter to end of text, 500 char max */
      gtk_text_iter_forward_chars(&end, 500);
      
      strcpy(injectbuf, gtk_text_buffer_get_text(buf, &start, &end, FALSE));

      if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button1)))
         gtkui_inject_user(1);
      else if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button2)))
         gtkui_inject_user(2);
   }

   gtk_widget_destroy(dialog);
}

static void gtkui_inject_user(int side)
{
   size_t len;
    
   /* escape the sequnces in the buffer */
   len = strescape(injectbuf, injectbuf);

   /* check where to inject */
   if (side == 1 || side == 2) {
      user_inject(injectbuf, len, curr_conn, side);
   }
}

/*
 * inject form a file 
 */
static void gtkui_connection_inject_file(void)
{
/* START */
   GtkWidget *dialog, *label, *vbox, *hbox;
   GtkWidget *button1, *button2, *button, *entry;
   char tmp[MAX_ASCII_ADDR_LEN];
   char *filename = NULL;
   gint response = 0;
   
   DEBUG_MSG("gtk_connection_inject_file");

   if(curr_conn == NULL)
      return;

   dialog = gtk_dialog_new_with_buttons("Character Injection", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL, GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, NULL);
   gtk_window_set_default_size(GTK_WINDOW (dialog), 400, 150);
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
   vbox = GTK_DIALOG (dialog)->vbox;

   label = gtk_label_new ("Packet source:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);
   gtk_widget_show(label);

   hbox = gtk_hbox_new(FALSE, 5);
   gtk_box_pack_start (GTK_BOX (vbox), hbox, FALSE, FALSE, 0);
   gtk_widget_show(hbox);
      
   button1 = gtk_radio_button_new_with_label(NULL, ip_addr_ntoa(&curr_conn->L3_addr1, tmp));
   gtk_box_pack_start(GTK_BOX(hbox), button1, FALSE, FALSE, 0);
   gtk_widget_show(button1);
   
   button2 = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (button1),
               ip_addr_ntoa(&curr_conn->L3_addr2, tmp));
   gtk_box_pack_start(GTK_BOX(hbox), button2, FALSE, FALSE, 0);
   gtk_widget_show(button2);
   
   label = gtk_label_new ("File to inject:");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);
   gtk_widget_show(label);

   hbox = gtk_hbox_new(FALSE, 5);
   gtk_box_pack_start (GTK_BOX (vbox), hbox, FALSE, FALSE, 0);
   gtk_widget_show(hbox);

   entry = gtk_entry_new();
   gtk_box_pack_start(GTK_BOX (hbox), entry, TRUE, TRUE, 0);
   gtk_widget_show(entry);

   button = gtk_button_new_with_label("...");
   gtk_box_pack_start(GTK_BOX (hbox), button, FALSE, FALSE, 0);
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_filename_browse), entry);
   gtk_widget_show(button);

   response = gtk_dialog_run(GTK_DIALOG (dialog));
   if(response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      filename = gtk_entry_get_text(GTK_ENTRY (entry));
      if(filename && strlen(filename) > 0) {
         if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button1)))
            gtkui_inject_file(filename, 1);
         else if(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON (button2)))
            gtkui_inject_file(filename, 2);
      }
   }
   gtk_widget_destroy(dialog);
}

/*
 * map the file into memory and pass the buffer to the inject function
 */
static void gtkui_inject_file(char *filename, int side)
{
   int fd;
   void *buf;
   size_t size;
   
   DEBUG_MSG("inject_file %s", filename);
   
   /* open the file */
   if ((fd = open(filename, O_RDONLY)) == -1) {
      ui_error("Can't load the file");
      return;
   }
      
   /* calculate the size of the file */
   size = lseek(fd, 0, SEEK_END);
   
   /* map it to the memory */
   buf = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
   if (buf == MAP_FAILED) {
      ui_error("Can't mmap the file");
      return;
   }

   /* check where to inject */
   if (side == 1 || side == 2) {
      user_inject(buf, size, curr_conn, side);
   }

   close(fd);
   munmap(buf, size);
}

/* EOF */

// vim:ts=3:expandtab

