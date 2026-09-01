/*
    ettercap -- GTK4 GUI -- the live connection list, data views and injection

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

/*
 * The biggest of the list views, and the one where GtkColumnView pays off
 * most clearly. The GTK3 version maintained, alongside its GtkListStore, a
 * hand-rolled doubly linked list (struct row_pairs) mapping each conntrack
 * connection to its GtkTreeIter, plus a "only update the rows currently
 * visible" optimisation built on pixel coordinates
 * (gtk_tree_view_get_visible_rect, convert_bin_window_to_widget_coords,
 * get_path_at_pos) just to keep the once-a-second refresh cheap.
 *
 * None of that survives. Rows are EcConnItem GObjects keyed by their
 * conntrack pointer; the refresh reconciles the store against conntrack by
 * that key, updating the handful of changing fields in place. Filtering is a
 * GtkFilterListModel with a GtkCustomFilter instead of GtkTreeModelFilter's
 * visible-func, and the filter re-runs by asking the filter to re-evaluate
 * rather than by poking the model.
 */

#include <ec.h>
#include <ec_gtk4.h>
#include <ec_conntrack.h>
#include <ec_format.h>
#include <ec_manuf.h>
#include <ec_services.h>
#include <ec_geoip.h>
#include <ec_inject.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* filter state */
struct conn_filter {
   char host[64];
   gboolean tcp, udp, other;
   gboolean active, idle, closing, closed, killed;
};

/* proto */
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
static gboolean gtkui_connections_scroll(gpointer data);
static void gtkui_data_print(int buffer, char *data, int color);
static void split_print(u_char *text, size_t len, struct ip_addr *L3_src);
static void split_print_po(struct packet_object *po);
static void join_print(u_char *text, size_t len, struct ip_addr *L3_src);
static void join_print_po(struct packet_object *po);
static void gtkui_connection_purge(void);
static void gtkui_connection_kill(void);
static void gtkui_connection_kill_curr_conn(void);
static void gtkui_connection_inject(void);
static void gtkui_inject_user(int side);
static void gtkui_connection_inject_file(void);
static void gtkui_inject_file(const char *filename, int side);

extern void conntrack_lock(void);
extern void conntrack_unlock(void);

/*** globals ***/

static GtkWidget  *conns_window = NULL;
static GtkWidget  *conns_view = NULL;
static GListStore *ls_conns = NULL;         /* of EcConnItem */
static GtkSingleSelection *conns_selection = NULL;
static GtkFilterListModel *conns_filtermodel = NULL;
static GtkCustomFilter *conns_filter = NULL;
static struct conn_object *curr_conn = NULL;
static struct conn_filter filter;
static guint connections_idle = 0;

/* split and joined data views */
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

/* reused (realloc'd) scratch buffers */
static u_char *dispbuf;
static u_char *injectbuf;

/*******************************************/
/* EcConnItem                                                              */
/*******************************************/

#define EC_TYPE_CONN_ITEM (ec_conn_item_get_type())
G_DECLARE_FINAL_TYPE(EcConnItem, ec_conn_item, EC, CONN_ITEM, GObject)

struct _EcConnItem {
   GObject parent_instance;
   char *flags;
   char *src;
   guint src_port;
   char *dst;
   guint dst_port;
   char *proto;
   char *status;
   guint tx;
   guint rx;
   char *ccodes;
   void *conn;               /* the conntrack list node; not owned */
};

G_DEFINE_FINAL_TYPE(EcConnItem, ec_conn_item, G_TYPE_OBJECT)

enum {
   CPROP_0, CPROP_FLAGS, CPROP_SRC, CPROP_SRC_PORT, CPROP_DST, CPROP_DST_PORT,
   CPROP_PROTO, CPROP_STATUS, CPROP_TX, CPROP_RX, CPROP_CCODES, N_CPROPS
};
static GParamSpec *conn_props[N_CPROPS];

static void ec_conn_item_finalize(GObject *object)
{
   EcConnItem *self = EC_CONN_ITEM(object);

   g_free(self->flags);
   g_free(self->src);
   g_free(self->dst);
   g_free(self->proto);
   g_free(self->status);
   g_free(self->ccodes);

   G_OBJECT_CLASS(ec_conn_item_parent_class)->finalize(object);
}

static void ec_conn_item_get_property(GObject *object, guint id, GValue *value,
      GParamSpec *pspec)
{
   EcConnItem *self = EC_CONN_ITEM(object);

   switch (id) {
      case CPROP_FLAGS:    g_value_set_string(value, self->flags); break;
      case CPROP_SRC:      g_value_set_string(value, self->src); break;
      case CPROP_SRC_PORT: g_value_set_uint(value, self->src_port); break;
      case CPROP_DST:      g_value_set_string(value, self->dst); break;
      case CPROP_DST_PORT: g_value_set_uint(value, self->dst_port); break;
      case CPROP_PROTO:    g_value_set_string(value, self->proto); break;
      case CPROP_STATUS:   g_value_set_string(value, self->status); break;
      case CPROP_TX:       g_value_set_uint(value, self->tx); break;
      case CPROP_RX:       g_value_set_uint(value, self->rx); break;
      case CPROP_CCODES:   g_value_set_string(value, self->ccodes); break;
      default: G_OBJECT_WARN_INVALID_PROPERTY_ID(object, id, pspec);
   }
}

static void ec_conn_item_class_init(EcConnItemClass *klass)
{
   GObjectClass *object_class = G_OBJECT_CLASS(klass);

   object_class->finalize = ec_conn_item_finalize;
   object_class->get_property = ec_conn_item_get_property;

   conn_props[CPROP_FLAGS] = g_param_spec_string("flags", NULL, NULL, NULL,
         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_SRC] = g_param_spec_string("src", NULL, NULL, NULL,
         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_SRC_PORT] = g_param_spec_uint("src-port", NULL, NULL,
         0, G_MAXUINT, 0, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_DST] = g_param_spec_string("dst", NULL, NULL, NULL,
         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_DST_PORT] = g_param_spec_uint("dst-port", NULL, NULL,
         0, G_MAXUINT, 0, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_PROTO] = g_param_spec_string("proto", NULL, NULL, NULL,
         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_STATUS] = g_param_spec_string("status", NULL, NULL, NULL,
         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_TX] = g_param_spec_uint("tx", NULL, NULL,
         0, G_MAXUINT, 0, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_RX] = g_param_spec_uint("rx", NULL, NULL,
         0, G_MAXUINT, 0, G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
   conn_props[CPROP_CCODES] = g_param_spec_string("ccodes", NULL, NULL, NULL,
         G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

   g_object_class_install_properties(object_class, N_CPROPS, conn_props);
}

static void ec_conn_item_init(EcConnItem *self)
{
   (void) self;
}

/*
 * The connection object underlying an item. The item's `conn` is the
 * conntrack list node; conntrack_get(0, ...) resolves it to its conn_object.
 */
static struct conn_object *item_conn_object(EcConnItem *item)
{
   struct conn_object *co = NULL;

   if (item == NULL || item->conn == NULL)
      return NULL;

   conntrack_get(0, item->conn, &co);
   return co;
}

/*******************************************/
/* column view                                                             */
/*******************************************/

/* text columns bind a string property; the two port/byte columns are uint */
static void on_conn_setup(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_label_new(NULL);

   (void) factory;
   (void) data;

   gtk_label_set_xalign(GTK_LABEL(label), 0.0);
   gtk_list_item_set_child(item, label);
}

static void on_conn_bind_text(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   const char *property = data;
   GtkWidget *label = gtk_list_item_get_child(item);
   GObject *obj = gtk_list_item_get_item(item);
   GBinding *binding;

   (void) factory;

   if (obj == NULL || label == NULL)
      return;

   binding = g_object_bind_property(obj, property, label, "label",
         G_BINDING_SYNC_CREATE);
   g_object_set_data(G_OBJECT(item), "binding", binding);
}

/* a uint property has to go through a transform to become label text */
static gboolean uint_to_label(GBinding *binding, const GValue *from,
      GValue *to, gpointer user_data)
{
   (void) binding;
   (void) user_data;

   g_value_take_string(to, g_strdup_printf("%u", g_value_get_uint(from)));
   return TRUE;
}

static void on_conn_bind_uint(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   const char *property = data;
   GtkWidget *label = gtk_list_item_get_child(item);
   GObject *obj = gtk_list_item_get_item(item);
   GBinding *binding;

   (void) factory;

   if (obj == NULL || label == NULL)
      return;

   binding = g_object_bind_property_full(obj, property, label, "label",
         G_BINDING_SYNC_CREATE, uint_to_label, NULL, NULL, NULL);
   g_object_set_data(G_OBJECT(item), "binding", binding);
}

static void on_conn_unbind(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GBinding *binding = g_object_get_data(G_OBJECT(item), "binding");

   (void) factory;
   (void) data;

   if (binding != NULL) {
      g_binding_unbind(binding);
      g_object_set_data(G_OBJECT(item), "binding", NULL);
   }
}

static void add_conn_column(GtkColumnView *view, const char *title,
      const char *property, gboolean is_uint, gboolean expand)
{
   GtkListItemFactory *factory;
   GtkColumnViewColumn *column;
   GtkExpression *expression;
   GtkSorter *sorter;

   factory = gtk_signal_list_item_factory_new();
   g_signal_connect(factory, "setup", G_CALLBACK(on_conn_setup), NULL);
   g_signal_connect(factory, "bind",
         G_CALLBACK(is_uint ? on_conn_bind_uint : on_conn_bind_text),
         (gpointer)property);
   g_signal_connect(factory, "unbind", G_CALLBACK(on_conn_unbind), NULL);

   column = gtk_column_view_column_new(title, factory);
   gtk_column_view_column_set_resizable(column, TRUE);
   gtk_column_view_column_set_expand(column, expand);

   expression = gtk_property_expression_new(EC_TYPE_CONN_ITEM, NULL, property);
   if (is_uint)
      sorter = GTK_SORTER(gtk_numeric_sorter_new(expression));
   else
      sorter = GTK_SORTER(gtk_string_sorter_new(expression));
   gtk_column_view_column_set_sorter(column, sorter);
   g_object_unref(sorter);

   gtk_column_view_append_column(view, column);
   g_object_unref(column);
}

/*******************************************/
/* filtering                                                               */
/*******************************************/

static gboolean conn_filter_match(gpointer item, gpointer user_data)
{
   EcConnItem *ci = item;
   struct conn_object *co;

   (void) user_data;

   /* host filter: match either endpoint */
   if (filter.host[0] != '\0') {
      gboolean src_match = ci->src && strcasestr(ci->src, filter.host);
      gboolean dst_match = ci->dst && strcasestr(ci->dst, filter.host);
      if (!src_match && !dst_match)
         return FALSE;
   }

   co = item_conn_object(ci);
   if (co == NULL)
      return FALSE;

   switch (co->L4_proto) {
      case NL_TYPE_UDP: if (!filter.udp)   return FALSE; break;
      case NL_TYPE_TCP: if (!filter.tcp)   return FALSE; break;
      default:          if (!filter.other) return FALSE; break;
   }

   switch (co->status) {
      case CONN_IDLE:    if (!filter.idle)    return FALSE; break;
      case CONN_ACTIVE:  if (!filter.active)  return FALSE; break;
      case CONN_CLOSING: if (!filter.closing) return FALSE; break;
      case CONN_CLOSED:  if (!filter.closed)  return FALSE; break;
      case CONN_KILLED:  if (!filter.killed)  return FALSE; break;
      default: break;
   }

   return TRUE;
}

static void refilter(void)
{
   if (conns_filter != NULL)
      gtk_filter_changed(GTK_FILTER(conns_filter), GTK_FILTER_CHANGE_DIFFERENT);
}

static void on_proto_toggled(GtkCheckButton *button, gpointer data)
{
   gboolean *value = data;

   *value = gtk_check_button_get_active(button);
   refilter();
}

static void on_host_filter(GtkWidget *entry, gpointer data)
{
   const char *text;

   (void) data;

   /*
    * The GTK3 code stored the entry's internal string pointer in
    * filter.host and relied on it living as long as the entry. Copy it: the
    * filter can outlive the text the editable holds, and re-reads it on
    * every row.
    */
   text = gtk_editable_get_text(GTK_EDITABLE(entry));
   strncpy(filter.host, text, sizeof(filter.host) - 1);
   filter.host[sizeof(filter.host) - 1] = '\0';

   refilter();
}

/*******************************************/

static GtkWidget *filter_check(const char *label, gboolean *flag,
      gboolean initial)
{
   GtkWidget *check = gtk_check_button_new_with_label(label);

   gtk_check_button_set_active(GTK_CHECK_BUTTON(check), initial);
   *flag = initial;
   g_signal_connect(check, "toggled", G_CALLBACK(on_proto_toggled), flag);

   return check;
}

/*
 * the auto-refreshing list of connections
 */
void gtkui_show_connections(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   GtkWidget *scrolled, *vbox, *hbox, *button, *frame, *entry, *tbox;
   GtkWidget *popover;
   GtkGesture *gesture;
   GtkSortListModel *sortmodel;
   GSimpleActionGroup *actions;
   GMenu *menu;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_show_connections");

   if (conns_window) {
      if (GTK_IS_WINDOW(conns_window))
         gtk_window_present(GTK_WINDOW(conns_window));
      else
         gtkui_page_present(conns_window);
      return;
   }

   conns_window = gtkui_page_new("Connections", &gtkui_kill_connections,
         &gtkui_connections_detach);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_vexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(conns_window), vbox);

   /* filter bar */
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
   gtk_widget_set_margin_top(hbox, 5);
   gtk_widget_set_margin_bottom(hbox, 5);
   gtk_widget_set_margin_start(hbox, 5);
   gtk_box_append(GTK_BOX(vbox), hbox);

   /* host filter */
   frame = gtk_frame_new("Host filter");
   tbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_widget_set_margin_start(tbox, 5);
   gtk_widget_set_margin_end(tbox, 5);
   gtk_frame_set_child(GTK_FRAME(frame), tbox);

   entry = gtk_entry_new();
   g_signal_connect(entry, "activate", G_CALLBACK(on_host_filter), NULL);
   gtk_box_append(GTK_BOX(tbox), entry);

   button = gtk_button_new_from_icon_name("system-search-symbolic");
   g_signal_connect_swapped(button, "clicked",
         G_CALLBACK(on_host_filter), entry);
   gtk_box_append(GTK_BOX(tbox), button);
   filter.host[0] = '\0';
   gtk_box_append(GTK_BOX(hbox), frame);

   /* protocol filter */
   frame = gtk_frame_new("Protocol filter");
   tbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_frame_set_child(GTK_FRAME(frame), tbox);
   gtk_box_append(GTK_BOX(tbox), filter_check("TCP", &filter.tcp, TRUE));
   gtk_box_append(GTK_BOX(tbox), filter_check("UDP", &filter.udp, TRUE));
   gtk_box_append(GTK_BOX(tbox), filter_check("Other", &filter.other, TRUE));
   gtk_box_append(GTK_BOX(hbox), frame);

   /* connection state filter */
   frame = gtk_frame_new("Connection state filter");
   tbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_frame_set_child(GTK_FRAME(frame), tbox);
   gtk_box_append(GTK_BOX(tbox), filter_check("Active", &filter.active, TRUE));
   gtk_box_append(GTK_BOX(tbox), filter_check("Idle", &filter.idle, TRUE));
   gtk_box_append(GTK_BOX(tbox),
         filter_check("Closing", &filter.closing, TRUE));
   gtk_box_append(GTK_BOX(tbox), filter_check("Closed", &filter.closed, TRUE));
   gtk_box_append(GTK_BOX(tbox), filter_check("Killed", &filter.killed, TRUE));
   gtk_box_append(GTK_BOX(hbox), frame);

   /* the list */
   refresh_connections(NULL);

   conns_view = gtk_column_view_new(NULL);
   gtk_column_view_set_show_row_separators(GTK_COLUMN_VIEW(conns_view), TRUE);

   /* store -> filter -> sort -> selection */
   conns_filter = gtk_custom_filter_new(conn_filter_match, NULL, NULL);
   conns_filtermodel = gtk_filter_list_model_new(
         G_LIST_MODEL(g_object_ref(ls_conns)), GTK_FILTER(conns_filter));

   sortmodel = gtk_sort_list_model_new(
         G_LIST_MODEL(conns_filtermodel),
         g_object_ref(gtk_column_view_get_sorter(GTK_COLUMN_VIEW(conns_view))));

   conns_selection = gtk_single_selection_new(G_LIST_MODEL(sortmodel));
   gtk_column_view_set_model(GTK_COLUMN_VIEW(conns_view),
         GTK_SELECTION_MODEL(conns_selection));

   add_conn_column(GTK_COLUMN_VIEW(conns_view), " ", "flags", FALSE, FALSE);
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "Host", "src", FALSE, TRUE);
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "Port", "src-port", TRUE, FALSE);
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "Host", "dst", FALSE, TRUE);
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "Port", "dst-port", TRUE, FALSE);
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "Proto", "proto", FALSE, FALSE);
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "State", "status", FALSE, FALSE);
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "TX Bytes", "tx", TRUE, FALSE);
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "RX Bytes", "rx", TRUE, FALSE);
#ifdef HAVE_GEOIP
   add_conn_column(GTK_COLUMN_VIEW(conns_view), "Countries", "ccodes",
         FALSE, FALSE);
#endif

   g_signal_connect(conns_view, "activate",
         G_CALLBACK(gtkui_connection_data), NULL);

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), conns_view);
   gtk_widget_set_vexpand(scrolled, TRUE);
   gtk_box_append(GTK_BOX(vbox), scrolled);

   /* buttons */
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_widget_set_margin_top(hbox, 6);
   gtk_widget_set_margin_bottom(hbox, 6);
   gtk_widget_set_margin_start(hbox, 6);
   gtk_widget_set_margin_end(hbox, 6);
   gtk_box_append(GTK_BOX(vbox), hbox);

   button = gtk_button_new_with_mnemonic("View _Details");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_detail), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("_Kill Connection");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_kill), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("E_xpunge Connections");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_purge), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   /* context menu */
   actions = g_simple_action_group_new();
   {
      GSimpleAction *a;

      a = g_simple_action_new("detail", NULL);
      g_signal_connect_swapped(a, "activate",
            G_CALLBACK(gtkui_connection_detail), NULL);
      g_action_map_add_action(G_ACTION_MAP(actions), G_ACTION(a));
      g_object_unref(a);

      a = g_simple_action_new("kill", NULL);
      g_signal_connect_swapped(a, "activate",
            G_CALLBACK(gtkui_connection_kill), NULL);
      g_action_map_add_action(G_ACTION_MAP(actions), G_ACTION(a));
      g_object_unref(a);
   }
   gtk_widget_insert_action_group(conns_view, "conn",
         G_ACTION_GROUP(actions));

   menu = g_menu_new();
   g_menu_append(menu, "View Details", "conn.detail");
   g_menu_append(menu, "Kill Connection", "conn.kill");
   popover = gtk_popover_menu_new_from_model(G_MENU_MODEL(menu));
   gtk_widget_set_parent(popover, conns_view);
   gtk_popover_set_has_arrow(GTK_POPOVER(popover), FALSE);
   gtk_widget_set_halign(popover, GTK_ALIGN_START);

   gesture = gtk_gesture_click_new();
   gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(gesture),
         GDK_BUTTON_SECONDARY);
   g_signal_connect_swapped(gesture, "pressed",
         G_CALLBACK(gtk_popover_popup), popover);
   gtk_widget_add_controller(conns_view, GTK_EVENT_CONTROLLER(gesture));

   g_object_unref(actions);
   g_object_unref(menu);

   /* refresh the list every 1000 ms */
   connections_idle = g_timeout_add(1000, refresh_connections, NULL);

   gtkui_page_present(conns_window);
}

static void gtkui_connections_detach(GtkWidget *child)
{
   conns_window = gtk_window_new();
   gtk_window_set_title(GTK_WINDOW(conns_window), "Live connections");
   gtk_window_set_default_size(GTK_WINDOW(conns_window), 500, 250);
   g_signal_connect(conns_window, "close-request",
         G_CALLBACK(gtkui_kill_connections), NULL);

   gtkui_page_attach_shortcut(conns_window, gtkui_connections_attach);

   gtk_window_set_child(GTK_WINDOW(conns_window), child);

   gtk_window_present(GTK_WINDOW(conns_window));
}

static void gtkui_connections_attach(void)
{
   gtkui_kill_connections();
   gtkui_show_connections(NULL, NULL, NULL);
}

static void gtkui_kill_connections(void)
{
   DEBUG_MSG("gtk_kill_connections");

   if (connections_idle != 0) {
      g_source_remove(connections_idle);
      connections_idle = 0;
   }

   if (conns_window == NULL)
      return;

   if (GTK_IS_WINDOW(conns_window))
      gtk_window_destroy(GTK_WINDOW(conns_window));
   else
      gtkui_page_close(conns_window, NULL);

   conns_window = NULL;
   conns_view = NULL;
   conns_selection = NULL;
   conns_filter = NULL;
   conns_filtermodel = NULL;
}

/*
 * Find the row already tracking a given conntrack node, or NULL.
 */
static EcConnItem *find_conn_item(void *conn)
{
   guint i, n;

   if (ls_conns == NULL)
      return NULL;

   n = g_list_model_get_n_items(G_LIST_MODEL(ls_conns));
   for (i = 0; i < n; i++) {
      EcConnItem *item = g_list_model_get_item(G_LIST_MODEL(ls_conns), i);
      gboolean match = (item->conn == conn);
      g_object_unref(item);
      if (match)
         return g_list_model_get_item(G_LIST_MODEL(ls_conns), i);
   }

   return NULL;
}

static void conn_item_fill(EcConnItem *item, struct conn_object *co, void *conn)
{
   char flags[2], src[MAX_ASCII_ADDR_LEN], dst[MAX_ASCII_ADDR_LEN];
   char proto[4], status[8], ccodes[8];

   memset(flags, 0, sizeof(flags));
   memset(proto, 0, sizeof(proto));
   memset(status, 0, sizeof(status));
   memset(ccodes, 0, sizeof(ccodes));

   conntrack_flagstr(co, flags, sizeof(flags));
   conntrack_statusstr(co, status, sizeof(status));
   conntrack_protostr(co, proto, sizeof(proto));
   conntrack_countrystr(co, ccodes, sizeof(ccodes));

   item->conn = conn;
   item->flags = g_strdup(flags);
   item->src = g_strdup(ip_addr_ntoa(&co->L3_addr1, src));
   item->src_port = ntohs(co->L4_addr1);
   item->dst = g_strdup(ip_addr_ntoa(&co->L3_addr2, dst));
   item->dst_port = ntohs(co->L4_addr2);
   item->proto = g_strdup(proto);
   item->status = g_strdup(status);
   item->tx = co->tx;
   item->rx = co->rx;
   item->ccodes = g_strdup(ccodes);
}

/*
 * Update only the fields that change over a connection's life. Notifying
 * the property is what repaints a bound cell; the static fields (addresses,
 * ports, protocol) never change, so they are not touched.
 */
static void conn_item_update(EcConnItem *item, struct conn_object *co)
{
   char flags[2], status[8];

   memset(flags, 0, sizeof(flags));
   memset(status, 0, sizeof(status));
   conntrack_flagstr(co, flags, sizeof(flags));
   conntrack_statusstr(co, status, sizeof(status));

   if (g_strcmp0(item->flags, flags) != 0) {
      g_free(item->flags);
      item->flags = g_strdup(flags);
      g_object_notify_by_pspec(G_OBJECT(item), conn_props[CPROP_FLAGS]);
   }
   if (g_strcmp0(item->status, status) != 0) {
      g_free(item->status);
      item->status = g_strdup(status);
      g_object_notify_by_pspec(G_OBJECT(item), conn_props[CPROP_STATUS]);
   }
   if (item->tx != co->tx) {
      item->tx = co->tx;
      g_object_notify_by_pspec(G_OBJECT(item), conn_props[CPROP_TX]);
   }
   if (item->rx != co->rx) {
      item->rx = co->rx;
      g_object_notify_by_pspec(G_OBJECT(item), conn_props[CPROP_RX]);
   }
}

/*
 * Reconcile the store with the conntrack list.
 *
 * The GTK3 version tracked new-vs-existing rows with its own linked list and
 * updated only the on-screen rows. This walks conntrack once, updating a row
 * in place or appending one, and drops rows whose connection is gone -- and
 * because the changing fields notify only when they actually change, an
 * off-screen row costs a couple of string compares, not a repaint.
 */
static gboolean refresh_connections(gpointer data)
{
   void *list, *next;
   struct conn_object *conn;
   guint i, n;

   (void) data;

   if (ls_conns == NULL)
      ls_conns = g_list_store_new(EC_TYPE_CONN_ITEM);

   if (conns_window != NULL && !gtk_widget_get_visible(conns_window))
      return FALSE;

   /* drop rows whose connection has left the conntrack list */
   n = g_list_model_get_n_items(G_LIST_MODEL(ls_conns));
   for (i = n; i > 0; i--) {
      EcConnItem *item = g_list_model_get_item(G_LIST_MODEL(ls_conns), i - 1);
      if (conntrack_get(0, item->conn, NULL) == NULL)
         g_list_store_remove(ls_conns, i - 1);
      g_object_unref(item);
   }

   /* walk conntrack; update existing rows, append new ones */
   for (list = conntrack_get(+1, NULL, NULL); list; list = next) {
      EcConnItem *item;

      next = conntrack_get(+1, list, &conn);

      item = find_conn_item(list);
      if (item != NULL) {
         conn_item_update(item, conn);
         g_object_unref(item);
      } else {
         item = g_object_new(EC_TYPE_CONN_ITEM, NULL);
         conn_item_fill(item, conn, list);
         g_list_store_append(ls_conns, item);
         g_object_unref(item);
      }
   }

   /* re-evaluate the filter, since statuses may have changed */
   refilter();

   return TRUE;
}

/*******************************************/
/* detail dialog                                                           */
/*******************************************/

static struct conn_object *selected_conn(void)
{
   EcConnItem *item;

   if (conns_selection == NULL)
      return NULL;

   item = gtk_single_selection_get_selected_item(conns_selection);
   return item_conn_object(item);
}

struct detail_grid {
   GtkWidget *grid;
   int row;
};

static void detail_heading(struct detail_grid *g, const char *text)
{
   GtkWidget *label = gtk_label_new(NULL);
   char *markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>",
         text);

   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_widget_set_margin_top(label, 10);
   gtk_grid_attach(GTK_GRID(g->grid), label, 0, g->row++, 3, 1);
   g_free(markup);
}

static GtkWidget *detail_field(struct detail_grid *g, const char *caption,
      const char *value)
{
   GtkWidget *label;

   label = gtk_label_new(caption);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(g->grid), label, 0, g->row, 1, 1);

   label = gtk_label_new(value);
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(g->grid), label, 1, g->row, 2, 1);

   g->row++;
   return label;
}

static void detail_hostname(struct detail_grid *g, const char *caption,
      struct ip_addr *ip)
{
   GtkWidget *label;
   char name[MAX_HOSTNAME_LEN];

   label = detail_field(g, caption, "resolving...");

   if (host_iptoa(ip, name) == -E_NOMATCH) {
      struct resolv_object *ro;

      SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
      ro->item = g_object_ref(G_OBJECT(label));
      ro->property = "label";
      ro->ip = ip;
      g_timeout_add(1000, gtkui_iptoa_deferred, ro);
   } else {
      gtk_label_set_text(GTK_LABEL(label), name);
   }
}

static void gtkui_connection_detail(void)
{
   AdwDialog *dialog;
   GtkWidget *toolbar, *header, *scrolled;
   struct detail_grid g;
   struct conn_object *co;
   char tmp[MAX_ASCII_ADDR_LEN];
   char *str;
#ifdef HAVE_GEOIP
   char country[MAX_GEOIP_STR_LEN];
#endif

   DEBUG_MSG("gtk_connection_detail");

   co = selected_conn();
   if (co == NULL)
      return;

   g.grid = gtk_grid_new();
   g.row = 0;
   gtk_grid_set_row_spacing(GTK_GRID(g.grid), 5);
   gtk_grid_set_column_spacing(GTK_GRID(g.grid), 5);
   gtk_widget_set_margin_top(g.grid, 8);
   gtk_widget_set_margin_bottom(g.grid, 8);
   gtk_widget_set_margin_start(g.grid, 8);
   gtk_widget_set_margin_end(g.grid, 8);

   /* Layer 2 */
   detail_heading(&g, "Layer 2 Information:");
   detail_field(&g, "Source MAC address:", mac_addr_ntoa(co->L2_addr1, tmp));
   detail_field(&g, "Destination MAC address:",
         mac_addr_ntoa(co->L2_addr2, tmp));

   /* Layer 3 */
   detail_heading(&g, "Layer 3 Information:");
   detail_field(&g, "Source IP address:", ip_addr_ntoa(&co->L3_addr1, tmp));
   if (EC_GBL_OPTIONS->resolve)
      detail_hostname(&g, "Source hostname:", &co->L3_addr1);
#ifdef HAVE_GEOIP
   if (EC_GBL_CONF->geoip_support_enable)
      detail_field(&g, "Source location:",
            geoip_get_by_ip(&co->L3_addr1, GEOIP_CNAME, country,
               MAX_GEOIP_STR_LEN));
#endif

   detail_field(&g, "Destination IP address:",
         ip_addr_ntoa(&co->L3_addr2, tmp));
   if (EC_GBL_OPTIONS->resolve)
      detail_hostname(&g, "Destination hostname:", &co->L3_addr2);
#ifdef HAVE_GEOIP
   if (EC_GBL_CONF->geoip_support_enable)
      detail_field(&g, "Destination location:",
            geoip_get_by_ip(&co->L3_addr2, GEOIP_CNAME, country,
               MAX_GEOIP_STR_LEN));
#endif

   /* Layer 4 */
   detail_heading(&g, "Layer 4 Information:");
   detail_field(&g, "Protocol:",
         co->L4_proto == NL_TYPE_UDP ? "UDP" :
         co->L4_proto == NL_TYPE_TCP ? "TCP" : "");

   str = g_strdup_printf("%d", ntohs(co->L4_addr1));
   detail_field(&g, "Source port:", str);
   g_free(str);

   str = g_strdup_printf("%d", ntohs(co->L4_addr2));
   detail_field(&g, "Destination port:", str);
   g_free(str);

   str = g_strdup_printf("%d", co->xferred);
   detail_field(&g, "Transferred bytes:", str);
   g_free(str);

   /* dissector-supplied credentials, if any */
   if (co->DISSECTOR.user) {
      detail_heading(&g, "Additional Information:");
      detail_field(&g, "Account:", co->DISSECTOR.user);
      detail_field(&g, "Password:", co->DISSECTOR.pass);
      if (co->DISSECTOR.info)
         detail_field(&g, "Additional info:", co->DISSECTOR.info);
   }

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), g.grid);
   gtk_widget_set_vexpand(scrolled, TRUE);

   header = adw_header_bar_new();
   adw_header_bar_set_title_widget(ADW_HEADER_BAR(header),
         adw_window_title_new("Connection Details", NULL));

   toolbar = adw_toolbar_view_new();
   adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
   adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), scrolled);

   dialog = adw_dialog_new();
   adw_dialog_set_title(dialog, "Connection Details");
   adw_dialog_set_content_width(dialog, 500);
   adw_dialog_set_content_height(dialog, 500);
   adw_dialog_set_child(dialog, toolbar);

   adw_dialog_present(dialog, window);
}

/*******************************************/
/* data views (split / joined)                                             */
/*******************************************/

static void gtkui_connection_data(void)
{
   struct conn_object *co;

   DEBUG_MSG("gtk_connection_data");

   co = selected_conn();
   if (co == NULL)
      return;

   /*
    * remove any hook on the currently open connection, to prevent a switch
    * of connection with the panel open
    */
   if (curr_conn) {
      conntrack_hook_conn_del(curr_conn, split_print_po);
      conntrack_hook_conn_del(curr_conn, join_print_po);
      curr_conn->flags &= ~CONN_VIEWING;
   }

   curr_conn = co;
   curr_conn->flags |= CONN_VIEWING;

   /* default is split view */
   gtkui_connection_data_split();
}

/* remove every child of the data window's content box */
static void clear_data_window(void)
{
   GtkWidget *child;

   if (data_window == NULL)
      return;

   while ((child = gtk_widget_get_first_child(data_window)) != NULL)
      gtk_box_remove(GTK_BOX(data_window), child);
}

/* build one text view with its blue/monospace tags, into a scroller */
static GtkWidget *make_data_view(GtkWidget **view_out, GtkTextBuffer **buf_out,
      GtkTextMark **mark_out)
{
   GtkWidget *scrolled, *view;
   GtkTextBuffer *buf;
   GtkTextIter iter;

   view = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(view), GTK_WRAP_CHAR);
   gtk_text_view_set_editable(GTK_TEXT_VIEW(view), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(view), FALSE);
   gtk_text_view_set_right_margin(GTK_TEXT_VIEW(view), 5);

   buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(view));
   gtk_text_buffer_create_tag(buf, "blue_fg", "foreground", "blue", NULL);
   gtk_text_buffer_create_tag(buf, "monospace", "family", "monospace", NULL);
   gtk_text_buffer_get_end_iter(buf, &iter);

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), view);
   gtk_widget_set_vexpand(scrolled, TRUE);

   *view_out = view;
   *buf_out = buf;
   *mark_out = gtk_text_buffer_create_mark(buf, "end", &iter, FALSE);

   return scrolled;
}

static void gtkui_connection_data_split(void)
{
   GtkWidget *vbox, *label, *hbox_big, *hbox_small, *button;
   char tmp[MAX_ASCII_ADDR_LEN];
   char title[MAX_ASCII_ADDR_LEN + 6];
   static gint scroll_split = 1;

   DEBUG_MSG("gtk_connection_data_split");

   /* if we're switching views, make sure the old hook is gone */
   conntrack_hook_conn_del(curr_conn, join_print_po);

   if (data_window) {
      clear_data_window();
      textview3 = NULL;
      joinedbuf = NULL;
      endmark3 = NULL;
   } else {
      data_window = gtkui_page_new("Connection data", &gtkui_destroy_conndata,
            &gtkui_connection_data_detach);
   }

   /* don't timeout this connection */
   curr_conn->flags |= CONN_VIEWING;

   hbox_big = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_widget_set_vexpand(hbox_big, TRUE);
   gtk_box_append(GTK_BOX(data_window), hbox_big);

   /* left side */
   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_hexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(hbox_big), vbox);

   snprintf(title, sizeof(title), "%s:%d",
         ip_addr_ntoa(&curr_conn->L3_addr1, tmp), ntohs(curr_conn->L4_addr1));
   label = gtk_label_new(title);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_append(GTK_BOX(vbox), label);

   gtk_box_append(GTK_BOX(vbox),
         make_data_view(&textview1, &splitbuf1, &endmark1));

   hbox_small = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_box_append(GTK_BOX(vbox), hbox_small);

   button = gtk_button_new_with_mnemonic("_Join Views");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_data_join), NULL);
   gtk_box_append(GTK_BOX(hbox_small), button);

   button = gtk_button_new_with_mnemonic("_Inject Data");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_inject), NULL);
   gtk_box_append(GTK_BOX(hbox_small), button);

   /* right side */
   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_hexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(hbox_big), vbox);

   snprintf(title, sizeof(title), "%s:%d",
         ip_addr_ntoa(&curr_conn->L3_addr2, tmp), ntohs(curr_conn->L4_addr2));
   label = gtk_label_new(title);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_append(GTK_BOX(vbox), label);

   gtk_box_append(GTK_BOX(vbox),
         make_data_view(&textview2, &splitbuf2, &endmark2));

   hbox_small = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_box_append(GTK_BOX(vbox), hbox_small);

   button = gtk_button_new_with_mnemonic("Inject _File");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_inject_file), NULL);
   gtk_box_append(GTK_BOX(hbox_small), button);

   button = gtk_button_new_with_mnemonic("_Kill Connection");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_kill_curr_conn), NULL);
   gtk_box_append(GTK_BOX(hbox_small), button);

   gtkui_page_present(data_window);

   /* after widgets are drawn, scroll to bottom */
   g_timeout_add(500, gtkui_connections_scroll, &scroll_split);

   /* print the old data */
   connbuf_print(&curr_conn->data, split_print);

   /* add the hook on the connection to receive data only from it */
   conntrack_hook_conn_add(curr_conn, split_print_po);
}

static void gtkui_connection_data_join(void)
{
   GtkWidget *vbox, *label, *hbox, *button;
   char src[MAX_ASCII_ADDR_LEN], dst[MAX_ASCII_ADDR_LEN];
   char title[(MAX_ASCII_ADDR_LEN * 2) + 6];
   static gint scroll_join = 2;

   DEBUG_MSG("gtk_connection_data_join");

   /* if we're switching views, make sure the old hook is gone */
   conntrack_hook_conn_del(curr_conn, split_print_po);

   if (data_window) {
      clear_data_window();
      textview1 = textview2 = NULL;
      splitbuf1 = splitbuf2 = NULL;
      endmark1 = endmark2 = NULL;
   } else {
      data_window = gtkui_page_new("Connection data", &gtkui_destroy_conndata,
            &gtkui_connection_data_detach);
   }

   curr_conn->flags |= CONN_VIEWING;

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_vexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(data_window), vbox);

   snprintf(title, sizeof(title), "%s:%d - %s:%d",
         ip_addr_ntoa(&curr_conn->L3_addr1, src), ntohs(curr_conn->L4_addr1),
         ip_addr_ntoa(&curr_conn->L3_addr2, dst), ntohs(curr_conn->L4_addr2));
   label = gtk_label_new(title);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_append(GTK_BOX(vbox), label);

   gtk_box_append(GTK_BOX(vbox),
         make_data_view(&textview3, &joinedbuf, &endmark3));

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_box_append(GTK_BOX(vbox), hbox);

   button = gtk_button_new_with_mnemonic("_Split View");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_data_split), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("_Kill Connection");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked",
         G_CALLBACK(gtkui_connection_kill_curr_conn), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   gtkui_page_present(data_window);

   /* after widgets are drawn, scroll to bottom */
   g_timeout_add(500, gtkui_connections_scroll, &scroll_join);

   /* print the old data */
   connbuf_print(&curr_conn->data, join_print);

   /* add the hook on the connection to receive data only from it */
   conntrack_hook_conn_add(curr_conn, join_print_po);
}

static void gtkui_connection_data_detach(GtkWidget *child)
{
   data_window = gtk_window_new();
   gtk_window_set_title(GTK_WINDOW(data_window), "Connection data");
   gtk_window_set_default_size(GTK_WINDOW(data_window), 600, 400);
   g_signal_connect(data_window, "close-request",
         G_CALLBACK(gtkui_destroy_conndata), NULL);

   gtkui_page_attach_shortcut(data_window, gtkui_connection_data_attach);

   gtk_window_set_child(GTK_WINDOW(data_window), child);

   gtk_window_present(GTK_WINDOW(data_window));
}

static void gtkui_connection_data_attach(void)
{
   if (curr_conn) {
      conntrack_hook_conn_del(curr_conn, split_print_po);
      conntrack_hook_conn_del(curr_conn, join_print_po);
   }

   if (data_window != NULL && GTK_IS_WINDOW(data_window))
      gtk_window_destroy(GTK_WINDOW(data_window));
   textview1 = textview2 = textview3 = NULL;
   data_window = NULL;

   gtkui_connection_data_split();
}

static void gtkui_destroy_conndata(void)
{
   DEBUG_MSG("gtkui_destroy_conndata");

   if (curr_conn) {
      conntrack_hook_conn_del(curr_conn, split_print_po);
      conntrack_hook_conn_del(curr_conn, join_print_po);
      curr_conn->flags &= ~CONN_VIEWING;
      curr_conn = NULL;
   }

   if (data_window != NULL) {
      if (GTK_IS_WINDOW(data_window))
         gtk_window_destroy(GTK_WINDOW(data_window));
      else
         gtkui_page_close(data_window, NULL);
   }

   textview1 = textview2 = textview3 = NULL;
   data_window = NULL;
}

/*
 * print connection data to one of the split or joined views
 * buffer: 1 left, 2 right, 3 joined; color: 2 for blue text
 */
static void gtkui_data_print(int buffer, char *data, int color)
{
   GtkTextIter iter;
   GtkTextBuffer *textbuf = NULL;
   GtkWidget *textview = NULL;
   GtkTextMark *endmark = NULL;
   char *unicode = NULL;

   switch (buffer) {
      case 1: textbuf = splitbuf1; textview = textview1; endmark = endmark1; break;
      case 2: textbuf = splitbuf2; textview = textview2; endmark = endmark2; break;
      case 3: textbuf = joinedbuf; textview = textview3; endmark = endmark3; break;
      default: return;
   }

   unicode = gtkui_utf8_validate(data);

   /* if interface has been destroyed or unicode conversion failed */
   if (!data_window || !textbuf || !textview || !endmark || !unicode)
      return;

   gtk_text_buffer_get_end_iter(textbuf, &iter);
   if (color == 2)
      gtk_text_buffer_insert_with_tags_by_name(textbuf, &iter, unicode, -1,
            "blue_fg", "monospace", NULL);
   else
      gtk_text_buffer_insert_with_tags_by_name(textbuf, &iter, unicode, -1,
            "monospace", NULL);

   gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(textview), endmark, 0, FALSE,
         0, 0);
}

static gboolean gtkui_connections_scroll(gpointer data)
{
   gint *type = data;

   if (type == NULL)
      return FALSE;

   if (*type == 1 && textview1 && endmark1 && textview2 && endmark2) {
      gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(textview1), endmark1, 0,
            FALSE, 0, 0);
      gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(textview2), endmark2, 0,
            FALSE, 0, 0);
   } else if (textview3 && endmark3) {
      gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(textview3), endmark3, 0,
            FALSE, 0, 0);
   }

   /* only execute once */
   return FALSE;
}

static void split_print(u_char *text, size_t len, struct ip_addr *L3_src)
{
   int ret;

   if (EC_GBL_OPTIONS->regex &&
       regexec(EC_GBL_OPTIONS->regex, (const char *)text, 0, NULL, 0) != 0)
      return;

   SAFE_REALLOC(dispbuf, hex_len(len) * sizeof(u_char) + 1);
   ret = EC_GBL_FORMAT(text, len, dispbuf);
   dispbuf[ret] = 0;

   if (!ip_addr_cmp(L3_src, &curr_conn->L3_addr1))
      gtkui_data_print(1, (char *)dispbuf, 0);
   else
      gtkui_data_print(2, (char *)dispbuf, 0);
}

static void split_print_po(struct packet_object *po)
{
   int ret;

   if (!data_window)
      return;

   if (EC_GBL_OPTIONS->regex &&
       regexec(EC_GBL_OPTIONS->regex, (const char *)po->DATA.disp_data,
          0, NULL, 0) != 0)
      return;

   SAFE_REALLOC(dispbuf, hex_len(po->DATA.disp_len) * sizeof(u_char) + 1);
   ret = EC_GBL_FORMAT(po->DATA.disp_data, po->DATA.disp_len, dispbuf);
   dispbuf[ret] = 0;

   if (!ip_addr_cmp(&po->L3.src, &curr_conn->L3_addr1))
      gtkui_data_print(1, (char *)dispbuf, 0);
   else
      gtkui_data_print(2, (char *)dispbuf, 0);
}

static void join_print(u_char *text, size_t len, struct ip_addr *L3_src)
{
   int ret;

   if (EC_GBL_OPTIONS->regex &&
       regexec(EC_GBL_OPTIONS->regex, (const char *)text, 0, NULL, 0) != 0)
      return;

   SAFE_REALLOC(dispbuf, hex_len(len) * sizeof(u_char) + 1);
   ret = EC_GBL_FORMAT(text, len, dispbuf);
   dispbuf[ret] = 0;

   if (!ip_addr_cmp(L3_src, &curr_conn->L3_addr1))
      gtkui_data_print(3, (char *)dispbuf, 1);
   else
      gtkui_data_print(3, (char *)dispbuf, 2);
}

static void join_print_po(struct packet_object *po)
{
   int ret;

   if (!data_window)
      return;

   if (EC_GBL_OPTIONS->regex &&
       regexec(EC_GBL_OPTIONS->regex, (const char *)po->DATA.disp_data,
          0, NULL, 0) != 0)
      return;

   SAFE_REALLOC(dispbuf, hex_len(po->DATA.disp_len) * sizeof(u_char) + 1);
   ret = EC_GBL_FORMAT(po->DATA.disp_data, po->DATA.disp_len, dispbuf);
   dispbuf[ret] = 0;

   if (!ip_addr_cmp(&po->L3.src, &curr_conn->L3_addr1))
      gtkui_data_print(3, (char *)dispbuf, 1);
   else
      gtkui_data_print(3, (char *)dispbuf, 2);
}

/*******************************************/
/* purge / kill                                                            */
/*******************************************/

static void gtkui_connection_purge(void)
{
   DEBUG_MSG("gtkui_connection_purge");

   conntrack_purge();

   if (ls_conns != NULL)
      g_list_store_remove_all(ls_conns);
}

static void gtkui_connection_kill(void)
{
   struct conn_object *co;

   DEBUG_MSG("gtkui_connection_kill");

   co = selected_conn();
   if (co == NULL)
      return;

   switch (user_kill(co)) {
      case E_SUCCESS:
         co->status = CONN_KILLED;
         gtkui_message("The connection was killed !!");
         break;
      case -E_FATAL:
         gtkui_message("Cannot kill UDP connections !!");
         break;
   }
}

static void gtkui_connection_kill_curr_conn(void)
{
   DEBUG_MSG("gtkui_connection_kill_curr_conn");

   if (curr_conn == NULL)
      return;

   switch (user_kill(curr_conn)) {
      case E_SUCCESS:
         curr_conn->status = CONN_KILLED;
         gtkui_message("The connection was killed !!");
         break;
      case -E_FATAL:
         gtkui_message("Cannot kill UDP connections !!");
         break;
   }
}

/*******************************************/
/* injection                                                               */
/*******************************************/

/*
 * The two injection dialogs share the "which endpoint" chooser. Under GTK3
 * these were GtkRadioButtons; here they are grouped GtkCheckButtons, which
 * is how GTK4 spells a radio group.
 */
struct inject_ctx {
   GtkWidget *to_dst;   /* inject toward L3_addr2 (side 1) */
   GtkWidget *to_src;   /* inject toward L3_addr1 (side 2) */
   GtkWidget *text;     /* GtkTextView, for interactive injection */
   GtkWidget *entry;    /* GtkEntry, for file injection */
};

static GtkWidget *inject_destination(struct inject_ctx *ctx)
{
   GtkWidget *box;
   char tmp[MAX_ASCII_ADDR_LEN];

   box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);

   ctx->to_dst = gtk_check_button_new_with_label(
         ip_addr_ntoa(&curr_conn->L3_addr2, tmp));
   ctx->to_src = gtk_check_button_new_with_label(
         ip_addr_ntoa(&curr_conn->L3_addr1, tmp));
   gtk_check_button_set_group(GTK_CHECK_BUTTON(ctx->to_src),
         GTK_CHECK_BUTTON(ctx->to_dst));
   gtk_check_button_set_active(GTK_CHECK_BUTTON(ctx->to_dst), TRUE);

   gtk_box_append(GTK_BOX(box), ctx->to_dst);
   gtk_box_append(GTK_BOX(box), ctx->to_src);

   return box;
}

static int inject_side(struct inject_ctx *ctx)
{
   if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ctx->to_dst)))
      return 1;
   if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ctx->to_src)))
      return 2;
   return 0;
}

static void on_inject_response(gboolean confirmed, gpointer data)
{
   struct inject_ctx *ctx = data;
   GtkTextBuffer *buf;
   GtkTextIter start, end;
   int side;

   if (!confirmed)
      return;

   side = inject_side(ctx);
   if (side == 0)
      return;

   SAFE_REALLOC(injectbuf, 501 * sizeof(char));
   memset(injectbuf, 0, 501);

   buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ctx->text));
   gtk_text_buffer_get_start_iter(buf, &start);
   gtk_text_buffer_get_start_iter(buf, &end);
   gtk_text_iter_forward_chars(&end, 500);

   strncpy((char *)injectbuf,
         gtk_text_buffer_get_text(buf, &start, &end, FALSE), 501);
   injectbuf[500] = '\0';

   gtkui_inject_user(side);
}

static void gtkui_connection_inject(void)
{
   struct inject_ctx *ctx;
   GtkWidget *vbox, *label, *frame;

   DEBUG_MSG("gtk_connection_inject");

   if (curr_conn == NULL)
      return;

   SAFE_CALLOC(ctx, 1, sizeof(struct inject_ctx));

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

   label = gtk_label_new("Packet destination:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_append(GTK_BOX(vbox), label);
   gtk_box_append(GTK_BOX(vbox), inject_destination(ctx));

   label = gtk_label_new("Characters to be injected:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_append(GTK_BOX(vbox), label);

   ctx->text = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(ctx->text), GTK_WRAP_CHAR);
   gtk_widget_set_size_request(ctx->text, 300, 100);

   frame = gtk_frame_new(NULL);
   gtk_frame_set_child(GTK_FRAME(frame), ctx->text);
   gtk_widget_set_vexpand(frame, TRUE);
   gtk_box_append(GTK_BOX(vbox), frame);

   gtkui_dialog_confirm("Character Injection", NULL, vbox,
         on_inject_response, ctx, g_free);
}

static void gtkui_inject_user(int side)
{
   size_t len;

   /* escape the sequences in the buffer */
   len = strescape((char *)injectbuf, (char *)injectbuf,
         strlen((char *)injectbuf) + 1);

   if (side == 1 || side == 2)
      user_inject(injectbuf, len, curr_conn, side);
}

static char inject_filename[PATH_MAX];

static void on_inject_file_response(gboolean confirmed, gpointer data)
{
   struct inject_ctx *ctx = data;
   const char *filename;
   int side;

   if (!confirmed)
      return;

   side = inject_side(ctx);
   filename = gtk_editable_get_text(GTK_EDITABLE(ctx->entry));

   if (side != 0 && filename && strlen(filename) > 0)
      gtkui_inject_file(filename, side);
}

/*
 * The "..." browse button fills the entry via gtkui_filename_browse. The
 * browse is itself asynchronous, so its result lands in inject_filename and
 * is copied into the entry when it returns.
 */
static void on_browse_done(gboolean confirmed, gpointer data)
{
   GtkWidget *entry = data;

   if (confirmed)
      gtk_editable_set_text(GTK_EDITABLE(entry), inject_filename);
}

static void on_browse_clicked(GtkButton *button, gpointer data)
{
   GtkWidget *entry = data;

   (void) button;

   inject_filename[0] = '\0';
   gtkui_filename_browse("File to inject", FALSE, inject_filename,
         sizeof(inject_filename), on_browse_done, entry, NULL);
}

static void gtkui_connection_inject_file(void)
{
   struct inject_ctx *ctx;
   GtkWidget *vbox, *label, *hbox, *button;

   DEBUG_MSG("gtk_connection_inject_file");

   if (curr_conn == NULL)
      return;

   SAFE_CALLOC(ctx, 1, sizeof(struct inject_ctx));

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);

   label = gtk_label_new("Packet destination:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_append(GTK_BOX(vbox), label);
   gtk_box_append(GTK_BOX(vbox), inject_destination(ctx));

   label = gtk_label_new("File to inject:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_box_append(GTK_BOX(vbox), label);

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   ctx->entry = gtk_entry_new();
   gtk_widget_set_hexpand(ctx->entry, TRUE);
   gtk_box_append(GTK_BOX(hbox), ctx->entry);

   button = gtk_button_new_with_label("...");
   g_signal_connect(button, "clicked", G_CALLBACK(on_browse_clicked),
         ctx->entry);
   gtk_box_append(GTK_BOX(hbox), button);
   gtk_box_append(GTK_BOX(vbox), hbox);

   gtkui_dialog_confirm("Character Injection", NULL, vbox,
         on_inject_file_response, ctx, g_free);
}

static void gtkui_inject_file(const char *filename, int side)
{
   int fd;
   void *buf;
   size_t size, ret;

   DEBUG_MSG("inject_file %s", filename);

   if ((fd = open(filename, O_RDONLY | O_BINARY)) == -1) {
      ui_error("Can't load the file");
      return;
   }

   size = lseek(fd, 0, SEEK_END);
   SAFE_CALLOC(buf, size, sizeof(char));
   lseek(fd, 0, SEEK_SET);
   ret = read(fd, buf, size);
   close(fd);

   if (ret != size) {
      ui_error("Cannot read the file into memory");
      SAFE_FREE(buf);
      return;
   }

   if (side == 1 || side == 2)
      user_inject(buf, size, curr_conn, side);

   SAFE_FREE(buf);
}

/* EOF */

// vim:ts=3:expandtab
