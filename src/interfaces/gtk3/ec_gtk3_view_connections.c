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
#include <ec_conntrack.h>
#include <ec_manuf.h>
#include <ec_services.h>
#include <ec_format.h>
#include <ec_inject.h>
#include <ec_proto.h>
#include <ec_geoip.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* double-linked list for fast updates to connection list */
struct row_pairs {
   void *conn;
   GtkTreeIter iter;

   struct row_pairs *next;
   struct row_pairs *prev;
};

/* filter objects */
struct conn_filter {
   /* model handle for filtered tree */
   GtkTreeModel *model;
   /* Host filter */
   const gchar *host;
   /* Protocol filter */
   gboolean tcp;
   gboolean udp;
   gboolean other;
   /* Connection state filter */
   gboolean active;
   gboolean idle;
   gboolean closing;
   gboolean closed;
   gboolean killed;
};

/* proto */

static void gtkui_connections_detach(GtkWidget *child);
static void gtkui_connections_attach(void);
static void gtkui_kill_connections(void);
static gboolean refresh_connections(gpointer data);
static struct row_pairs *gtkui_connections_add(struct conn_object *co, void *conn, struct row_pairs **list);
static void gtkui_connection_list_row(int top, struct row_pairs *pair);
static void gtkui_connection_detail(void);
static void gtkui_connection_detail_destroy(GtkWidget *widget, gpointer *data);
static void gtkui_connection_data(void);
static void gtkui_connection_data_split(void);
static void gtkui_connection_data_join(void);
static void gtkui_connection_data_detach(GtkWidget *child);
static void gtkui_connection_data_attach(void);
static void gtkui_destroy_conndata(void);
static gboolean gtkui_connections_scroll(gpointer data);
static void gtkui_data_print(int buffer, char *data, int color);
static void split_print(u_char *text, size_t len, struct ip_addr *L3_src);
static void split_print_po(struct packet_object *po);
static void join_print(u_char *text, size_t len, struct ip_addr *L3_src);
static void join_print_po(struct packet_object *po);
static void gtkui_connection_purge(void *conn);
static void gtkui_connection_kill(void *conn);
static void gtkui_connection_kill_curr_conn(void);
static void gtkui_connection_inject(void);
static void gtkui_inject_user(int side);
static void gtkui_connection_inject_file(void);
static void gtkui_inject_file(const char *filename, int side);
static void set_connfilter(GtkWidget *widget, gpointer *data);
static void set_connfilter_host(GtkWidget *widget, gpointer *data);
static gboolean connfilter(GtkTreeModel *model, GtkTreeIter *iter, gpointer *data);

extern void conntrack_lock(void);
extern void conntrack_unlock(void);

/*** globals ***/

/* connection list */
static struct row_pairs *connections = NULL;
static GtkWidget *conns_window = NULL;
static GtkWidget     *treeview = NULL; /* the visible part of the GTK list */
static GtkListStore  *ls_conns = NULL; /* the data part */
static GtkTreeSelection   *selection = NULL;
static struct conn_object *curr_conn = NULL;
static struct conn_filter filter;
static guint connections_idle = 0;

/* connection detail window */
static guint detail_timer1 = 0;
static guint detail_timer2 = 0;

/* split and joined data views */
static GtkWidget   *data_window = NULL;
static GtkWidget     *textview1 = NULL; /* visible part of data output */
static GtkWidget     *textview2 = NULL;
static GtkWidget     *textview3 = NULL;
static GtkTextBuffer *splitbuf1 = NULL; /* where data is stored */
static GtkTextBuffer *splitbuf2 = NULL;
static GtkTextBuffer *joinedbuf = NULL;
static GtkTextMark    *endmark1 = NULL; /* marks for auto-scrolling */
static GtkTextMark    *endmark2 = NULL;
static GtkTextMark    *endmark3 = NULL;

/* keep it global, so the memory region is always the same (reallocing it) */
static u_char *dispbuf;
static u_char *injectbuf;

/*******************************************/

/*
 * the auto-refreshing list of connections
 */
void gtkui_show_connections(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *scrolled, *vbox, *items, *hbox, *button, *tbox, *box;
   GtkWidget *context_menu, *frame, *entry, *chkb_tcp, *chkb_udp, *chkb_other;
   GtkWidget *chkb_active, *chkb_idle, *chkb_closing, *chkb_closed, *chkb_killed;
   GtkTreeModel *model;
   GtkToolItem *toolbutton;
   GtkCellRenderer   *renderer;
   GtkTreeViewColumn *column;

   (void) action;
   (void) value;
   (void) data;

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

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_container_add(GTK_CONTAINER (conns_window), vbox);
   gtk_widget_show(vbox);

   /* filter bar */
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
   gtk_widget_set_margin_top(hbox, 5);
   gtk_widget_set_margin_bottom(hbox, 5);
   gtk_widget_set_margin_start(hbox, 5);

   frame = gtk_frame_new("Host filter");
   tbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
   gtk_container_add(GTK_CONTAINER(frame), tbox);

   box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   entry = gtk_entry_new();
   g_signal_connect(G_OBJECT(entry), "activate", G_CALLBACK(set_connfilter_host), NULL);
   gtk_box_pack_start(GTK_BOX(box), entry, TRUE, FALSE, 5);
   gtk_box_pack_start(GTK_BOX(tbox), box, TRUE, FALSE, 5);

   toolbutton = gtk_tool_button_new(
         gtk_image_new_from_icon_name("system-search", GTK_ICON_SIZE_BUTTON), 
         "Search");
   g_signal_connect_swapped(G_OBJECT(toolbutton), "clicked", G_CALLBACK(set_connfilter_host), entry);
   gtk_box_pack_start(GTK_BOX(tbox), GTK_WIDGET(toolbutton), FALSE, FALSE, 5);
   filter.host = NULL;
   gtk_box_pack_start(GTK_BOX(hbox), frame, FALSE, FALSE, 0);

   frame = gtk_frame_new("Protocol filter");
   tbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
   gtk_container_add(GTK_CONTAINER(frame), tbox);

   chkb_tcp = gtk_check_button_new_with_label("TCP");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkb_tcp), TRUE);
   filter.tcp = TRUE;
   g_signal_connect(G_OBJECT(chkb_tcp), "toggled", G_CALLBACK(set_connfilter), &filter.tcp);
   gtk_box_pack_start(GTK_BOX(tbox), chkb_tcp, FALSE, FALSE, 5);

   chkb_udp = gtk_check_button_new_with_label("UDP");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkb_udp), TRUE);
   filter.udp = TRUE;
   g_signal_connect(G_OBJECT(chkb_udp), "toggled", G_CALLBACK(set_connfilter), &filter.udp);
   gtk_box_pack_start(GTK_BOX(tbox), chkb_udp, FALSE, FALSE, 5);

   chkb_other = gtk_check_button_new_with_label("Other");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkb_other), TRUE);
   filter.other = TRUE;
   g_signal_connect(G_OBJECT(chkb_other), "toggled", G_CALLBACK(set_connfilter), &filter.other);
   gtk_box_pack_start(GTK_BOX(tbox), chkb_other, FALSE, FALSE, 5);

   gtk_box_pack_start(GTK_BOX(hbox), frame, FALSE, FALSE, 0);

   frame = gtk_frame_new("Connection state filter");
   tbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
   gtk_container_add(GTK_CONTAINER(frame), tbox);

   chkb_active = gtk_check_button_new_with_label("Active");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkb_active), TRUE);
   filter.active = TRUE;
   g_signal_connect(G_OBJECT(chkb_active), "toggled", G_CALLBACK(set_connfilter), &filter.active);
   gtk_box_pack_start(GTK_BOX(tbox), chkb_active, FALSE, FALSE, 5);

   chkb_idle = gtk_check_button_new_with_label("Idle");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkb_idle), TRUE);
   filter.idle = TRUE;
   g_signal_connect(G_OBJECT(chkb_idle), "toggled", G_CALLBACK(set_connfilter), &filter.idle);
   gtk_box_pack_start(GTK_BOX(tbox), chkb_idle, FALSE, FALSE, 5);

   chkb_closing = gtk_check_button_new_with_label("Closing");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkb_closing), TRUE);
   filter.closing = TRUE;
   g_signal_connect(G_OBJECT(chkb_closing), "toggled", G_CALLBACK(set_connfilter), &filter.closing);
   gtk_box_pack_start(GTK_BOX(tbox), chkb_closing, FALSE, FALSE, 5);

   chkb_closed = gtk_check_button_new_with_label("Closed");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkb_closed), TRUE);
   filter.closed = TRUE;
   g_signal_connect(G_OBJECT(chkb_closed), "toggled", G_CALLBACK(set_connfilter), &filter.closed);
   gtk_box_pack_start(GTK_BOX(tbox), chkb_closed, FALSE, FALSE, 5);

   chkb_killed = gtk_check_button_new_with_label("Killed");
   gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(chkb_killed), TRUE);
   filter.killed = TRUE;
   g_signal_connect(G_OBJECT(chkb_killed), "toggled", G_CALLBACK(set_connfilter), &filter.killed);
   gtk_box_pack_start(GTK_BOX(tbox), chkb_killed, FALSE, FALSE, 5);

   gtk_box_pack_start(GTK_BOX(hbox), frame, FALSE, FALSE, 0);
   gtk_widget_show_all(hbox);


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
   column = gtk_tree_view_column_new_with_attributes ("TX Bytes", renderer, "text", 8, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 8);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("RX Bytes", renderer, "text", 9, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 9);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

#ifdef HAVE_GEOIP
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Countries", renderer, "text", 10, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 10);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);
#endif

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
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
   
   button = gtk_button_new_with_mnemonic("E_xpunge Connections");
   g_signal_connect (G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_purge), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   /* context menu */
   context_menu = gtk_menu_new();
   
   items = gtk_menu_item_new_with_label("View Details");
   gtk_menu_shell_append (GTK_MENU_SHELL (context_menu), items);
   g_signal_connect (G_OBJECT (items), "activate", G_CALLBACK (gtkui_connection_detail), NULL);
   gtk_widget_show (items);

   items = gtk_menu_item_new_with_label("Kill Connection");
   gtk_menu_shell_append (GTK_MENU_SHELL (context_menu), items);
   g_signal_connect (G_OBJECT (items), "activate", G_CALLBACK (gtkui_connection_kill), NULL);
   gtk_widget_show (items);

   g_signal_connect(G_OBJECT(treeview), "button-press-event", G_CALLBACK(gtkui_context_menu), context_menu);

   /* initialize the list */
   refresh_connections(NULL);

   /* init filter model handle */
   filter.model = gtk_tree_model_filter_new(GTK_TREE_MODEL(ls_conns), NULL);
   gtk_tree_model_filter_set_visible_func(GTK_TREE_MODEL_FILTER(filter.model), 
                                          (GtkTreeModelFilterVisibleFunc)connfilter, NULL, NULL);

   /* sorting model has to be explicitely created from the filtered model to support both */
   model = gtk_tree_model_sort_new_with_model(filter.model);

   /* link the Tree Model with the Tree View */
   gtk_tree_view_set_model(GTK_TREE_VIEW (treeview), model);

   /* refresh the list every 1000 ms */
   /* gtk_idle_add refreshes too fast, uses all cpu */
   connections_idle = g_timeout_add(1000, refresh_connections, NULL);

   gtk_widget_show(conns_window);
}

/* callback for detaching the tab */
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

/* callback for attaching the tab */
static void gtkui_connections_attach(void)
{
   gtkui_kill_connections();
   gtkui_show_connections(NULL, NULL, NULL);
}

/* connection list closed */
static void gtkui_kill_connections(void)
{
   DEBUG_MSG("gtk_kill_connections");
   g_source_remove(connections_idle);

   gtk_widget_destroy(conns_window);
   conns_window = NULL;
}

/* for keeping the connection list in sync with the conntrack list */
static gboolean refresh_connections(gpointer data)
{
   struct row_pairs *lastconn = NULL, *cache = NULL;
   GtkTreeModel *model = GTK_TREE_MODEL (ls_conns);
   void *list, *next, *listend;
   struct conn_object *conn;    /* stores connection details */
   GtkTreeIter iter;            /* points to a specific row */
   char flags[2], status[8];
   unsigned int tx = 0, rx = 0;
   struct row_pairs *row = NULL, *nextrow = NULL, top, bottom;

   /* variable not used */
   (void) data;

   /* init strings */
   memset(&flags, 0, sizeof(flags));
   memset(&status, 0, sizeof(status));

   /* make sure the list has been created and window is visible */
   if(ls_conns) {
      if (!gtk_widget_get_visible(conns_window))
         return(FALSE);
   } else {
      /* Columns:   Flags, Host, Port, "-",   Host, Port,
                    Proto, State, TX Bytes, RX Bytes, Countries, (hidden) pointer */
      ls_conns = gtk_list_store_new (12,
                    G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, 
                    G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, 
                    G_TYPE_STRING, G_TYPE_STRING, G_TYPE_UINT, 
                    G_TYPE_UINT,  G_TYPE_STRING, G_TYPE_POINTER);
      connections = NULL;
   }

   /* remove old connections */
   for(row = connections; row; row = nextrow) {
       nextrow = row->next;
       if(conntrack_get(0, row->conn, NULL) == NULL) {
          /* remove row from the GTK list */
          gtk_list_store_remove(GTK_LIST_STORE(ls_conns), &row->iter);

          /* remove pointers from the linked-list and free */
          if(row->next)
              row->next->prev = row->prev;

          if(row->prev)
              row->prev->next = row->next;
          else
              connections = row->next;
          SAFE_FREE(row);
       }
       if(row)
           lastconn = row;
   }

   /* make sure we have a place to start searching for new rows */
   if(!lastconn) {
      listend = conntrack_get(0, NULL, NULL);
      if(listend == NULL)
         return(TRUE);
   } else {
      listend = lastconn->conn;
   }

   /* add new connections */
   for(list = conntrack_get(+1, listend, NULL); list; list = next) {
      next = conntrack_get(+1, list, &conn);
      cache = gtkui_connections_add(conn, list, &connections);
      if(cache)
         lastconn = cache;
   }

   /* find the first and last visible rows */
   gtkui_connection_list_row(1, &top);
   gtkui_connection_list_row(0, &bottom);

   if(top.conn == NULL) 
      return(TRUE);

   iter = top.iter; /* copy iter by value */

   /* update visible part of list */
   do {
      /* get the conntrack pointer for this row */
      gtk_tree_model_get (model, &iter, 11, &list, -1);
      conntrack_get(0, list, &conn);

      /* extract changing values from conntrack_print string */
      conntrack_flagstr(conn, flags, sizeof(flags));
      conntrack_statusstr(conn, status, sizeof(status));
      tx = conn->tx;
      rx = conn->rx;

      gtk_list_store_set (ls_conns, &iter, 0, flags, 7, status, 8, tx, 9, rx, -1);

      /* when we reach the bottom of the visible part, stop updating */
      if(bottom.conn == list)
         break;
   } while(gtk_tree_model_iter_next(model, &iter));

   /* finnaly apply the filter */
   gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(filter.model));
  
   return(TRUE);
}

static struct row_pairs *gtkui_connections_add(struct conn_object *co, void *conn, struct row_pairs **list) {
   GtkTreeIter iter;
   char flags[2], src[MAX_ASCII_ADDR_LEN], dst[MAX_ASCII_ADDR_LEN];
   char proto[4], status[8], ccodes[8];
   unsigned int src_port = 0, dst_port = 0, tx = 0, rx = 0;
   struct row_pairs *row = NULL;

   /* even if list is empty, we need a pointer to the NULL pointer */
   /* so we can start a list */
   if(!list)
      return(NULL);

   /* init strings */
   memset(&flags, 0, sizeof(flags));
   memset(&proto, 0, sizeof(proto));
   memset(&src, 0, sizeof(src));
   memset(&dst, 0, sizeof(dst));
   memset(&status, 0, sizeof(status));
   memset(&ccodes, 0, sizeof(ccodes));

   /* copy data from conntrack_print string */
   conntrack_flagstr(co, flags, sizeof(flags));
   conntrack_statusstr(co, status, sizeof(status));
   conntrack_protostr(co, proto, sizeof(proto));
   conntrack_countrystr(co, ccodes, sizeof(ccodes));

   ip_addr_ntoa(&co->L3_addr1, src);
   ip_addr_ntoa(&co->L3_addr2, dst);

   src_port = ntohs(co->L4_addr1);
   dst_port = ntohs(co->L4_addr2);

   tx = co->tx;
   rx = co->rx;

   /* add it to GTK list */
   gtk_list_store_append (ls_conns, &iter);
   gtk_list_store_set (ls_conns, &iter,
                       0, flags, 1, src,     2, src_port,
                       3, "-",   4, dst,     5, dst_port,
                       6, proto, 7, status,  8, tx,
                       9, rx, 10, ccodes, 11, conn, -1);
   /* and add it to our linked list */
   if(!*list) {
      row = malloc(sizeof(struct row_pairs));
      if(row == NULL) {
         USER_MSG("Failed create new connection row\n");
         DEBUG_MSG("gktui_connections_add: failed to allocate memory for a new row");
      }
      row->prev = NULL;
   } else {
      for(row = *list; row && row->next; row = row->next);
      row->next = malloc(sizeof(struct row_pairs));
      if(row->next == NULL) {
         USER_MSG("Failed create new connection row\n");
         DEBUG_MSG("gktui_connections_add: failed to allocate memory for a new row");
      }
      row->next->prev = row;
      row = row->next;
   }

   row->conn = conn;
   row->iter = iter;
   row->next = NULL;

   /* in case this was the first list entry */
   if(!*list)
       *list = row;

   return(row);
}

/* 
 * get the top or bottom visible row in the connection list
 * returns TOP row if (int top) is > 0  and list is not empty
 * returns BOTTOM row if (int top) is 0 and visible area is full
 */
static void gtkui_connection_list_row(int top, struct row_pairs *pair) {
   GtkTreeIter iter;            /* points to a specific row */
   GtkTreePath *path = NULL;    /* for finding the first visible row */
   GtkTreeModel *model = NULL;  /* points to the list data */
   GdkRectangle rect;           /* holds coordinates of visible rows */
   int wx = 0, wy = 0;          /* for converting tree view coords to widget coords */
   void *row = NULL;

   if(!ls_conns || !pair)
      return;

   /* in case we don't get a row */
   pair->conn = NULL;

   model = GTK_TREE_MODEL (ls_conns);
   if(gtk_tree_model_get_iter_first(model, &iter)) {
      gtk_tree_view_get_visible_rect(GTK_TREE_VIEW(treeview), &rect);

      /* get the first visible row */
      gtk_tree_view_convert_bin_window_to_widget_coords(GTK_TREE_VIEW(treeview), 
            rect.x, (top)?rect.y:rect.height, &wx, &wy);
      path = gtk_tree_path_new();
      if(gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(treeview), wx+2, (top)?wy+2:wy-2, &path, NULL, NULL, NULL)) {
         gtk_tree_model_get_iter(model, &iter, path);
         gtk_tree_model_get (model, &iter, 11, &row, -1);
         pair->iter = iter;
         pair->conn = row;
      }
      if(path)
         gtk_tree_path_free(path);
   }

   return;
}

/* 
 * details for a connection
 */
static void gtkui_connection_detail(void)
{
   GtkWidget *dwindow, *vbox, *hbox, *grid, *label, *header, *content;
   GtkTreeIter iter;
   GtkTreeModel *model;
   struct conn_tail *c = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];
   char name[MAX_HOSTNAME_LEN];
   gchar *str, *markup;
   guint row = 0, col = 0;
#ifdef HAVE_GEOIP
   char src_country[MAX_GEOIP_STR_LEN];
   char dst_country[MAX_GEOIP_STR_LEN];
#endif

   DEBUG_MSG("gtk_connection_detail");

   model = GTK_TREE_MODEL (ls_conns);

   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 11, &c, -1);
   } else
      return; /* nothing is selected */

   if(!c || !c->co)
      return;

   header = gtk_header_bar_new();
   gtk_header_bar_set_title(GTK_HEADER_BAR(header), "Connection Details");
   gtk_header_bar_set_decoration_layout(GTK_HEADER_BAR(header), ":close");
   gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);

   dwindow = gtk_dialog_new();
   gtk_window_set_titlebar(GTK_WINDOW(dwindow), header);
   gtk_window_set_modal(GTK_WINDOW(dwindow), TRUE);
   gtk_window_set_transient_for(GTK_WINDOW(dwindow), GTK_WINDOW(window));
   gtk_window_set_position(GTK_WINDOW(dwindow), GTK_WIN_POS_CENTER_ON_PARENT);
   gtk_container_set_border_width(GTK_CONTAINER(dwindow), 5);
   g_signal_connect(G_OBJECT(dwindow), "delete-event", 
         G_CALLBACK(gtkui_connection_detail_destroy), NULL);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
   content = gtk_dialog_get_content_area(GTK_DIALOG(dwindow));
   gtk_container_add(GTK_CONTAINER(content), vbox);

   grid = gtk_grid_new();
   gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
   gtk_container_set_border_width(GTK_CONTAINER(grid), 8);
   gtk_box_pack_start(GTK_BOX(vbox), grid, FALSE, FALSE, 0);

   /* Layer 2 Information */
   label = gtk_label_new("Layer 2 Information:");
   markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>", 
         gtk_label_get_text(GTK_LABEL(label)));
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 3, 1);
   g_free(markup);

   row++;
   label = gtk_label_new("Source MAC address:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

   label = gtk_label_new(mac_addr_ntoa(c->co->L2_addr1, tmp));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);

   row++;
   label = gtk_label_new("Destination MAC address:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

   label = gtk_label_new(mac_addr_ntoa(c->co->L2_addr2, tmp));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);

   /* Layer 3 information */
   row++;
   label = gtk_label_new("Layer 3 Information:");
   markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>", 
         gtk_label_get_text(GTK_LABEL(label)));
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 3, 1);
   gtk_widget_set_margin_top(label, 10);
   g_free(markup);

   row++;
   label = gtk_label_new("Source IP address:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

   label = gtk_label_new(ip_addr_ntoa(&c->co->L3_addr1, tmp));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);

   if (EC_GBL_OPTIONS->resolve) {
      row++;
      label = gtk_label_new("Source hostname:");
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

      label = gtk_label_new("resolving...");
      if (host_iptoa(&c->co->L3_addr1, name) == -E_NOMATCH) {
         /* IP not yet resolved - keep trying asyncronously */
         struct resolv_object *ro;
         SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
         ro->type = GTK_TYPE_LABEL;
         ro->widget = label;
         ro->ip = &c->co->L3_addr1;
         detail_timer1 = g_timeout_add(1000, gtkui_iptoa_deferred, ro);
      }
      else {
         gtk_label_set_text(GTK_LABEL(label), name);
      }
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);
   }

#ifdef HAVE_GEOIP
   if (EC_GBL_CONF->geoip_support_enable) {
      row++;
      label = gtk_label_new("Source location:");
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

      label = gtk_label_new(geoip_get_by_ip(&c->co->L3_addr1, GEOIP_CNAME, src_country, MAX_GEOIP_STR_LEN));
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);
   }
#endif

   row++;
   label = gtk_label_new("Destination IP address:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

   label = gtk_label_new(ip_addr_ntoa(&c->co->L3_addr2, tmp));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);

   if (EC_GBL_OPTIONS->resolve) {
      row++;
      label = gtk_label_new("Destination hostname:");
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

      label = gtk_label_new("resolving...");
      if (host_iptoa(&c->co->L3_addr2, name) == -E_NOMATCH) {
         /* IP not yet resolved - keep trying asyncronously */
         struct resolv_object *ro;
         SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
         ro->type = GTK_TYPE_LABEL;
         ro->widget = label;
         ro->ip = &c->co->L3_addr2;
         detail_timer2 = g_timeout_add(1000, gtkui_iptoa_deferred, ro);
      }
      else {
         gtk_label_set_text(GTK_LABEL(label), name);
      }
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);
   }

#ifdef HAVE_GEOIP
   if (EC_GBL_CONF->geoip_support_enable) {
      row++;
      label = gtk_label_new("Destination location:");
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

      label = gtk_label_new(geoip_get_by_ip(&c->co->L3_addr2, GEOIP_CNAME, dst_country, MAX_GEOIP_STR_LEN));
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);
   }
#endif

   /* Layer 4 information */
   row++;
   label = gtk_label_new("Layer 4 Information:");
   markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>", 
         gtk_label_get_text(GTK_LABEL(label)));
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 3, 1);
   gtk_widget_set_margin_top(label, 10);
   g_free(markup);

   row++;
   label = gtk_label_new("Protocol:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

   switch(c->co->L4_proto) {
      case NL_TYPE_UDP:
         label = gtk_label_new("UDP");
         break;
      case NL_TYPE_TCP:
         label = gtk_label_new("TCP");
         break;
      default:
         label = gtk_label_new("");
         break;
   }
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);

   row++;
   label = gtk_label_new("Source port:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

   label = gtk_label_new((str = g_strdup_printf("%d", ntohs(c->co->L4_addr1))));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 1, 1);
   g_free(str);

   label = gtk_label_new(service_search(c->co->L4_addr1, c->co->L4_proto));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+2, row, 1, 1);

   row++;
   label = gtk_label_new("Destination port:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

   label = gtk_label_new((str = g_strdup_printf("%d", ntohs(c->co->L4_addr2))));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 1, 1);
   g_free(str);

   label = gtk_label_new(service_search(c->co->L4_addr2, c->co->L4_proto));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+2, row, 1, 1);

   row++;
   label = gtk_label_new("Transferred bytes:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

   label = gtk_label_new((str = g_strdup_printf("%d", c->co->xferred)));
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);
   g_free(str);

   /* Additional information */
   if (c->co->DISSECTOR.user) {
      row++;
      label = gtk_label_new("Additional Information:");
      markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>", 
            gtk_label_get_text(GTK_LABEL(label)));
      gtk_label_set_markup(GTK_LABEL(label), markup);
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col, row, 3, 1);
      gtk_widget_set_margin_top(label, 10);
      g_free(markup);

      row++;
      label = gtk_label_new("Account:");
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

      label = gtk_label_new(c->co->DISSECTOR.user);
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 1, 1);

      label = gtk_label_new(c->co->DISSECTOR.pass);
      gtk_label_set_selectable(GTK_LABEL(label), TRUE);
      gtk_widget_set_halign(label, GTK_ALIGN_START);
      gtk_grid_attach(GTK_GRID(grid), label, col+2, row, 1, 1);

      if (c->co->DISSECTOR.info) {
         row++;
         label = gtk_label_new("Additional info:");
         gtk_widget_set_halign(label, GTK_ALIGN_START);
         gtk_grid_attach(GTK_GRID(grid), label, col, row, 1, 1);

         label = gtk_label_new(c->co->DISSECTOR.info);
         gtk_label_set_selectable(GTK_LABEL(label), TRUE);
         gtk_widget_set_halign(label, GTK_ALIGN_START);
         gtk_grid_attach(GTK_GRID(grid), label, col+1, row, 2, 1);
      }
   }

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

   gtk_widget_show_all(dwindow);


}

static void gtkui_connection_detail_destroy(GtkWidget *widget, gpointer *data)
{
   /* unused variable */
   (void) data;

   /* destroy timer if still running */
   if (detail_timer1)
      g_source_remove(detail_timer1);
   if (detail_timer2)
      g_source_remove(detail_timer2);

   /* destroy widget */
   gtk_widget_destroy(widget);
}

static void gtkui_connection_data(void)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   struct conn_tail *c = NULL;
   DEBUG_MSG("gtk_connection_data");

   model = GTK_TREE_MODEL (ls_conns);

   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 11, &c, -1);
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
      /* remove the viewing flag */
      curr_conn->flags &= ~CONN_VIEWING;
   }
   
   /* set the global variable to pass the parameter to other functions */
   curr_conn = c->co;
   curr_conn->flags |= CONN_VIEWING;
   
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
   static gint scroll_split = 1;

   DEBUG_MSG("gtk_connection_data_split");

   /* if we're switching views, make sure old hook is gone */
   conntrack_hook_conn_del(curr_conn, join_print_po);

   if(data_window) {
      child = gtk_bin_get_child(GTK_BIN (data_window));
      gtk_container_remove(GTK_CONTAINER (data_window), child);
      textview3 = NULL;
      joinedbuf = NULL;
      endmark3 = NULL;     
   } else {
      data_window = gtkui_page_new("Connection data", &gtkui_destroy_conndata, &gtkui_connection_data_detach);
   }

   /* don't timeout this connection */
   curr_conn->flags |= CONN_VIEWING;

   hbox_big = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_container_add(GTK_CONTAINER(data_window), hbox_big);
   gtk_widget_show(hbox_big);

  /*** left side ***/
   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_box_pack_start(GTK_BOX(hbox_big), vbox, TRUE, TRUE, 0);
   gtk_widget_show(vbox);

  /* title */
   snprintf(title, MAX_ASCII_ADDR_LEN+6, "%s:%d", 
            ip_addr_ntoa(&curr_conn->L3_addr1, tmp), ntohs(curr_conn->L4_addr1));
   label = gtk_label_new(title);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
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
   hbox_small = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
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
   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_box_pack_start(GTK_BOX(hbox_big), vbox, TRUE, TRUE, 0);
   gtk_widget_show(vbox);

  /* title */
   snprintf(title, MAX_ASCII_ADDR_LEN+6, "%s:%d", 
            ip_addr_ntoa(&curr_conn->L3_addr2, tmp), ntohs(curr_conn->L4_addr2));
   label = gtk_label_new(title);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
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
   hbox_small = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_box_pack_start(GTK_BOX(vbox), hbox_small, FALSE, FALSE, 0);
   gtk_widget_show(hbox_small);

   button = gtk_button_new_with_mnemonic("Inject _File"); 
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_inject_file), NULL);
   gtk_box_pack_start(GTK_BOX(hbox_small), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   button = gtk_button_new_with_mnemonic("_Kill Connection");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_kill_curr_conn), NULL);
   gtk_box_pack_start(GTK_BOX(hbox_small), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   gtk_widget_show(data_window);

   if(GTK_IS_WINDOW (data_window))
      gtk_window_present(GTK_WINDOW (data_window));
   else
      gtkui_page_present(data_window);

   /* after widgets are drawn, scroll to bottom */
   g_timeout_add(500, gtkui_connections_scroll, &scroll_split);

   /* print the old data */
   connbuf_print(&curr_conn->data, split_print);

   /* add the hook on the connection to receive data only from it */
   conntrack_hook_conn_add(curr_conn, split_print_po);
}

/* detach connection data tab */
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

/* attach connection data tab */
static void gtkui_connection_data_attach(void)
{
   if (curr_conn) {
      conntrack_hook_conn_del(curr_conn, split_print_po);
      conntrack_hook_conn_del(curr_conn, join_print_po);
   }
   
   gtk_widget_destroy(data_window);
   textview1 = NULL;
   textview2 = NULL;
   textview3 = NULL;
   data_window = NULL;

   gtkui_connection_data_split();
}

/* close connection data tab */
static void gtkui_destroy_conndata(void)
{
   DEBUG_MSG("gtkui_destroy_conndata");

   if (curr_conn) {
      conntrack_hook_conn_del(curr_conn, split_print_po);
      conntrack_hook_conn_del(curr_conn, join_print_po);
      curr_conn->flags &= ~CONN_VIEWING;
      curr_conn = NULL;
   }

   gtk_widget_destroy(data_window);
   textview1 = NULL;
   textview2 = NULL;
   textview3 = NULL;
   data_window = NULL;
}

/* print connection data to one of the split or joined views */
/* int buffer - 1 for left split view, 2 for right split view, 3 for joined view */
/* char *data - string to print */
/* int color  - 2 for blue text (used in joined view) */
static void gtkui_data_print(int buffer, char *data, int color) 
{
   GtkTextIter iter;
   GtkTextBuffer *textbuf = NULL;
   GtkWidget *textview = NULL;
   GtkTextMark *endmark = NULL;
   char *unicode = NULL;

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

   
   /* make sure data is valid UTF8 */
   unicode = gtkui_utf8_validate(data);

   /* if interface has been destroyed or unicode conversion failed */
   if(!data_window || !textbuf || !textview || !endmark || !unicode)
      return;

   gtk_text_buffer_get_end_iter(textbuf, &iter);
   if(color == 2)
      gtk_text_buffer_insert_with_tags_by_name(textbuf, &iter, unicode, 
         -1, "blue_fg", "monospace", NULL);
   else
      gtk_text_buffer_insert_with_tags_by_name(textbuf, &iter, unicode, 
         -1, "monospace", NULL);
   gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW (textview), 
      endmark, 0, FALSE, 0, 0); 
}

static void split_print(u_char *text, size_t len, struct ip_addr *L3_src)
{
   int ret;
   
   /* check the regex filter */
   if (EC_GBL_OPTIONS->regex && 
       regexec(EC_GBL_OPTIONS->regex, text, 0, NULL, 0) != 0) {
      return;
   }

   /* use the global to reuse the same memory region */
   SAFE_REALLOC(dispbuf, hex_len(len) * sizeof(u_char) + 1);
   
   /* format the data */
   ret = EC_GBL_FORMAT(text, len, dispbuf);
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
   
   /* check the regex filter */
   if (EC_GBL_OPTIONS->regex && 
       regexec(EC_GBL_OPTIONS->regex, po->DATA.disp_data, 0, NULL, 0) != 0) {
      return;
   }
   
   /* use the global to reuse the same memory region */
   SAFE_REALLOC(dispbuf, hex_len(po->DATA.disp_len) * sizeof(u_char) + 1);
      
   /* format the data */
   ret = EC_GBL_FORMAT(po->DATA.disp_data, po->DATA.disp_len, dispbuf);
   dispbuf[ret] = 0;
        
   if (!ip_addr_cmp(&po->L3.src, &curr_conn->L3_addr1))
      gtkui_data_print(1, dispbuf, 0);
   else
      gtkui_data_print(2, dispbuf, 0);
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
   static gint scroll_join = 2;

   DEBUG_MSG("gtk_connection_data_join");

   /* if we're switching views, make sure old hook is gone */
   conntrack_hook_conn_del(curr_conn, split_print_po);

   if(data_window) {
      child = gtk_bin_get_child(GTK_BIN (data_window));
      gtk_container_remove(GTK_CONTAINER (data_window), child);
      textview1 = NULL;
      textview2 = NULL;
      splitbuf1 = NULL;
      splitbuf2 = NULL;
      endmark1 = NULL;
      endmark2 = NULL;
   } else {
      data_window = gtkui_page_new("Connection data", &gtkui_destroy_conndata, &gtkui_connection_data_detach);
   }

   /* don't timeout this connection */
   curr_conn->flags |= CONN_VIEWING;
   
   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_container_add(GTK_CONTAINER(data_window), vbox);
   gtk_widget_show(vbox);
   
  /* title */
   snprintf(title, TITLE_LEN, "%s:%d - %s:%d", 
            ip_addr_ntoa(&curr_conn->L3_addr1, src), ntohs(curr_conn->L4_addr1),
            ip_addr_ntoa(&curr_conn->L3_addr2, dst), ntohs(curr_conn->L4_addr2));
   label = gtk_label_new(title);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
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

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
   gtk_widget_show(hbox);

   button = gtk_button_new_with_mnemonic("_Split View");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_data_split), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   button = gtk_button_new_with_mnemonic("_Kill Connection");
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_connection_kill_curr_conn), NULL);
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   gtk_widget_show(button);

   gtk_widget_show(data_window);

   if(GTK_IS_WINDOW (data_window))
      gtk_window_present(GTK_WINDOW (data_window));
   else
      gtkui_page_present(data_window);

   /* after widgets are drawn, scroll to bottom */
   g_timeout_add(500, gtkui_connections_scroll, &scroll_join);

   /* print the old data */
   connbuf_print(&curr_conn->data, join_print);

   /* add the hook on the connection to receive data only from it */
   conntrack_hook_conn_add(curr_conn, join_print_po);
}

static gboolean gtkui_connections_scroll(gpointer data)
{
   gint *type = data;

   if (type == NULL)
       return FALSE;

   if(*type == 1 && textview1 && endmark1 && textview2 && endmark2) {
      /* scroll split data views to bottom */
      gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW (textview1), endmark1, 0, FALSE, 0, 0);
      gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW (textview2), endmark2, 0, FALSE, 0, 0); 
   } else if(textview3 && endmark3) {
      /* scroll joined data view to bottom */
      gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW (textview3), endmark3, 0, FALSE, 0, 0);
   }

   /* only execute once, don't repeat */
   return(FALSE);
}

static void join_print(u_char *text, size_t len, struct ip_addr *L3_src)
{
   int ret;
   
   /* check the regex filter */
   if (EC_GBL_OPTIONS->regex && 
       regexec(EC_GBL_OPTIONS->regex, text, 0, NULL, 0) != 0) {
      return;
   }
   
   /* use the global to reuse the same memory region */
   SAFE_REALLOC(dispbuf, hex_len(len) * sizeof(u_char) + 1);
   
   /* format the data */
   ret = EC_GBL_FORMAT(text, len, dispbuf);
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
   
   /* check the regex filter */
   if (EC_GBL_OPTIONS->regex && 
       regexec(EC_GBL_OPTIONS->regex, po->DATA.disp_data, 0, NULL, 0) != 0) {
      return;
   }
   
   /* use the global to reuse the same memory region */
   SAFE_REALLOC(dispbuf, hex_len(po->DATA.disp_len) * sizeof(u_char) + 1);
      
   /* format the data */
   ret = EC_GBL_FORMAT(po->DATA.disp_data, po->DATA.disp_len, dispbuf);
   dispbuf[ret] = 0;
        
   if (!ip_addr_cmp(&po->L3.src, &curr_conn->L3_addr1))
      gtkui_data_print(3, dispbuf, 1);
   else
      gtkui_data_print(3, dispbuf, 2);
}

/*
 * erase the connection list
 */
static void gtkui_connection_purge(void *conn)
{
   struct row_pairs *row, *nextrow, *list = connections;

   /* variable not used */
   (void) conn;

   DEBUG_MSG("gtkui_connection_purge");

   connections = NULL;
   for(row = list; row; row = nextrow) {
       nextrow = row->next;
       SAFE_FREE(row);
   }

   conntrack_purge();
   gtk_list_store_clear(GTK_LIST_STORE (ls_conns));
}

/*
 * kill the selected connection connection
 */
static void gtkui_connection_kill(void *conn)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   struct conn_tail *c = NULL;

   /* variable not used */
   (void) conn;

   DEBUG_MSG("gtkui_connection_kill");

   model = GTK_TREE_MODEL (ls_conns);

   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 11, &c, -1);
   } else
      return; /* nothing is selected */

   if (!c || !c->co)
      return;
   
   /* kill it */
   switch (user_kill(c->co)) {
      case E_SUCCESS:
         /* set the status */
         c->co->status = CONN_KILLED;
         gtkui_message("The connection was killed !!");
         break;
      case -E_FATAL:
         gtkui_message("Cannot kill UDP connections !!");
         break;
   }
}

/*
 * call the specialized funtion as this is a callback 
 * without the parameter
 */
static void gtkui_connection_kill_curr_conn(void)
{
   DEBUG_MSG("gtkui_connection_kill_curr_conn");
   
   /* kill it */
   switch (user_kill(curr_conn)) {
      case E_SUCCESS:
         /* set the status */
         curr_conn->status = CONN_KILLED;
         gtkui_message("The connection was killed !!");
         break;
      case -E_FATAL:
         gtkui_message("Cannot kill UDP connections !!");
         break;
   }
}

/*
 * inject interactively with the user
 */
static void gtkui_connection_inject(void)
{
   GtkWidget *dialog, *text, *label, *vbox, *frame, *content_area;
   GtkWidget *button1, *button2, *hbox;
   GtkTextBuffer *buf;
   GtkTextIter start, end;
   char tmp[MAX_ASCII_ADDR_LEN];
   gint response = 0;

   DEBUG_MSG("gtk_connection_inject");

   if(curr_conn == NULL)
      return;

   dialog = gtk_dialog_new_with_buttons("Character Injection", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR, 
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
#if !GTK_CHECK_VERSION(2, 22, 0)
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_box_pack_start(GTK_BOX(content_area), vbox, FALSE, FALSE, 0);

   label = gtk_label_new ("Packet destination:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

   button1 = gtk_radio_button_new_with_label(NULL, ip_addr_ntoa(&curr_conn->L3_addr2, tmp));
   gtk_box_pack_start(GTK_BOX(hbox), button1, FALSE, FALSE, 0);

   button2 = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (button1),
               ip_addr_ntoa(&curr_conn->L3_addr1, tmp));
   gtk_box_pack_start(GTK_BOX(hbox), button2, FALSE, FALSE, 0);

   label = gtk_label_new ("Characters to be injected:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);

   frame = gtk_frame_new(NULL);
   gtk_frame_set_shadow_type(GTK_FRAME (frame), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX (vbox), frame, TRUE, TRUE, 5);

   text = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (text), GTK_WRAP_CHAR);
   gtk_container_add(GTK_CONTAINER (frame), text);

   gtk_widget_show_all(dialog);
    
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
      
      strncpy(injectbuf, gtk_text_buffer_get_text(buf, &start, &end, FALSE), 501);

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
   len = strescape(injectbuf, injectbuf, strlen(injectbuf)+1);

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
   GtkWidget *dialog, *label, *vbox, *hbox, *content_area;
   GtkWidget *button1, *button2, *button, *entry;
   char tmp[MAX_ASCII_ADDR_LEN];
   const char *filename = NULL;
   gint response = 0;
   
   DEBUG_MSG("gtk_connection_inject_file");

   if(curr_conn == NULL)
      return;

   dialog = gtk_dialog_new_with_buttons("Character Injection", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR, 
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   gtk_window_set_default_size(GTK_WINDOW (dialog), 400, 150);
#if !GTK_CHECK_VERSION(2, 22, 0)
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   
   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_box_pack_start(GTK_BOX(content_area), vbox, FALSE, FALSE, 0);

   label = gtk_label_new ("Packet destination:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_box_pack_start (GTK_BOX (vbox), hbox, FALSE, FALSE, 0);
      
   button1 = gtk_radio_button_new_with_label(NULL, ip_addr_ntoa(&curr_conn->L3_addr2, tmp));
   gtk_box_pack_start(GTK_BOX(hbox), button1, FALSE, FALSE, 0);
   gtk_widget_show(button1);
   
   button2 = gtk_radio_button_new_with_label_from_widget(GTK_RADIO_BUTTON (button1),
               ip_addr_ntoa(&curr_conn->L3_addr1, tmp));
   gtk_box_pack_start(GTK_BOX(hbox), button2, FALSE, FALSE, 0);
   
   label = gtk_label_new ("File to inject:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_pack_start (GTK_BOX (vbox), label, FALSE, FALSE, 0);

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_box_pack_start (GTK_BOX (vbox), hbox, FALSE, FALSE, 0);

   entry = gtk_entry_new();
   gtk_box_pack_start(GTK_BOX (hbox), entry, TRUE, TRUE, 0);

   button = gtk_button_new_with_label("...");
   gtk_box_pack_start(GTK_BOX (hbox), button, FALSE, FALSE, 0);
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_filename_browse), entry);

   gtk_widget_show_all(dialog);

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
static void gtkui_inject_file(const char *filename, int side)
{
   int fd;
   void *buf;
   size_t size, ret;
   
   DEBUG_MSG("inject_file %s", filename);
   
   /* open the file */
   if ((fd = open(filename, O_RDONLY | O_BINARY)) == -1) {
      ui_error("Can't load the file");
      return;
   }
      
   /* calculate the size of the file */
   size = lseek(fd, 0, SEEK_END);
   
   /* load the file in memory */
   SAFE_CALLOC(buf, size, sizeof(char));
            
   /* rewind the pointer */
   lseek(fd, 0, SEEK_SET);
               
   ret = read(fd, buf, size);

   close(fd);

   if (ret != size) {
      ui_error("Cannot read the file into memory");
      return;
   }
      
   /* check where to inject */
   if (side == 1 || side == 2) {
      user_inject(buf, size, curr_conn, side);
   }

   SAFE_FREE(buf);
}

static void set_connfilter(GtkWidget *widget, gpointer *data)
{
   gboolean *value;

   DEBUG_MSG("set_connfilter");

   value = (gboolean*)data;
   *value = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(widget));
   /* reapply the filter */
   gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(filter.model));
}

static void set_connfilter_host(GtkWidget *widget, gpointer *data)
{
   /* unused variable */
   (void) data;
   DEBUG_MSG("set_connfilter_host");

   filter.host = gtk_entry_get_text(GTK_ENTRY(widget));

   /* reapply the filter */
   gtk_tree_model_filter_refilter(GTK_TREE_MODEL_FILTER(filter.model));
}

static gboolean connfilter(GtkTreeModel *model, GtkTreeIter *iter, gpointer *data)
{
   gchar *src_host, *dst_host;
   gboolean ret = TRUE;
   struct conn_tail *conn = NULL;

   /* unused variable */
   (void) data;

   /* fetch row values */
   gtk_tree_model_get(model, iter, 1, &src_host, 4, &dst_host, 11, &conn, -1);

   /* evaluate filter criteria */
   /* host filter set - filter hosts that do not match */
   if (filter.host && strlen(filter.host)) { 
      if (src_host && !strcasestr(src_host, filter.host) && 
          dst_host && !strcasestr(dst_host, filter.host)) {
         ret = FALSE;
         g_free(src_host);
         g_free(dst_host);
      }
   }

   if (conn && conn->co) {
      /* protocol filter */
      switch (conn->co->L4_proto) {
         case NL_TYPE_UDP:
            if (!filter.udp)
               ret = FALSE;
            break;
         case NL_TYPE_TCP:
            if (!filter.tcp)
               ret = FALSE;
            break;
         default:
            if (!filter.other)
               ret = FALSE;
      }

      /* connection state filter */
      switch (conn->co->status) {
         case CONN_IDLE:
            if (!filter.idle)
               ret = FALSE;
            break;
         case CONN_ACTIVE:
            if (!filter.active)
               ret = FALSE;
            break;
         case CONN_CLOSING:
            if (!filter.closing)
               ret = FALSE;
            break;
         case CONN_CLOSED:
            if (!filter.closed)
               ret = FALSE;
            break;
         case CONN_KILLED:
            if (!filter.killed)
               ret = FALSE;
            break;
         default:
            break;
      }
   }
   else {
      ret = FALSE;
   }

   return ret;
}

/* EOF */

// vim:ts=3:expandtab

