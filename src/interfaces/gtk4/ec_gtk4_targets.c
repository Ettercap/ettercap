/*
    ettercap -- GTK4 GUI -- target selection

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

/* globals */
static char thost[MAX_ASCII_ADDR_LEN];

static GtkWidget  *targets_window = NULL;
static GListStore *store1 = NULL;
static GListStore *store2 = NULL;
static GtkSelectionModel *selection1 = NULL;
static GtkSelectionModel *selection2 = NULL;

/* proto */
static void set_targets(void);
static void gtkui_targets_destroy(void);
static void gtkui_targets_detach(GtkWidget *child);
static void gtkui_targets_attach(void);

/*******************************************/
/* EcTargetItem -- one address in a target list                            */
/*******************************************/

/*
 * Same reasoning as EcHostItem in ec_gtk4_hosts.c: GtkColumnView binds to
 * GObjects, and carrying the struct ip_list * on the object is both typed
 * and refcount-safe, where the GtkListStore version smuggled it through a
 * hidden G_TYPE_POINTER column.
 */
#define EC_TYPE_TARGET_ITEM (ec_target_item_get_type())
G_DECLARE_FINAL_TYPE(EcTargetItem, ec_target_item, EC, TARGET_ITEM, GObject)

struct _EcTargetItem {
   GObject parent_instance;
   char *addr;
   struct ip_list *il;   /* not owned */
};

G_DEFINE_FINAL_TYPE(EcTargetItem, ec_target_item, G_TYPE_OBJECT)

enum { TPROP_0, TPROP_ADDR, N_TPROPS };
static GParamSpec *target_props[N_TPROPS];

static void ec_target_item_finalize(GObject *object)
{
   EcTargetItem *self = EC_TARGET_ITEM(object);

   g_free(self->addr);

   G_OBJECT_CLASS(ec_target_item_parent_class)->finalize(object);
}

static void ec_target_item_get_property(GObject *object, guint prop_id,
      GValue *value, GParamSpec *pspec)
{
   EcTargetItem *self = EC_TARGET_ITEM(object);

   if (prop_id == TPROP_ADDR)
      g_value_set_string(value, self->addr);
   else
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
}

static void ec_target_item_set_property(GObject *object, guint prop_id,
      const GValue *value, GParamSpec *pspec)
{
   EcTargetItem *self = EC_TARGET_ITEM(object);

   if (prop_id == TPROP_ADDR) {
      g_free(self->addr);
      self->addr = g_value_dup_string(value);
   } else {
      G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
   }
}

static void ec_target_item_class_init(EcTargetItemClass *klass)
{
   GObjectClass *object_class = G_OBJECT_CLASS(klass);

   object_class->finalize = ec_target_item_finalize;
   object_class->get_property = ec_target_item_get_property;
   object_class->set_property = ec_target_item_set_property;

   target_props[TPROP_ADDR] = g_param_spec_string("addr", NULL, NULL, NULL,
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
   g_object_class_install_properties(object_class, N_TPROPS, target_props);
}

static void ec_target_item_init(EcTargetItem *self)
{
   (void) self;
}

static EcTargetItem *ec_target_item_new(struct ip_list *il, const char *addr)
{
   EcTargetItem *self = g_object_new(EC_TYPE_TARGET_ITEM, NULL);

   self->il = il;
   self->addr = g_strdup(addr);

   return self;
}

/*******************************************/

void toggle_reverse(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) data;

   g_simple_action_set_state(action, value);

   EC_GBL_OPTIONS->reversed ^= 1;
}

/*
 * wipe the targets struct setting both T1 and T2 to ANY/ANY/ANY
 */
void wipe_targets(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("wipe_targets");

   reset_display_filter(EC_GBL_TARGET1);
   reset_display_filter(EC_GBL_TARGET2);

   /* update the list models */
   gtkui_create_targets_array();

   /* display the message */
   gtkui_message("TARGETS were reset to ANY/ANY/ANY");
}

/*******************************************/
/* protocol selection                                                      */
/*******************************************/

struct proto_ctx {
   GtkWidget *all;
   GtkWidget *tcp;
   GtkWidget *udp;
};

static void on_protocol_response(gboolean confirmed, gpointer data)
{
   struct proto_ctx *ctx = data;
   const char *proto = "all";

   if (!confirmed)
      return;

   if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ctx->tcp)))
      proto = "tcp";
   else if (gtk_check_button_get_active(GTK_CHECK_BUTTON(ctx->udp)))
      proto = "udp";

   strncpy(EC_GBL_OPTIONS->proto, proto, 4);
}

/*
 * display the protocol dialog
 */
void gtkui_select_protocol(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   struct proto_ctx *ctx;
   GtkWidget *box;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_select_protocol");

   /* this will contain 'all', 'tcp' or 'udp' */
   if (!EC_GBL_OPTIONS->proto) {
      SAFE_CALLOC(EC_GBL_OPTIONS->proto, 4, sizeof(char));
      strncpy(EC_GBL_OPTIONS->proto, "all", 4);
   }

   SAFE_CALLOC(ctx, 1, sizeof(struct proto_ctx));

   /*
    * GtkRadioButton was removed in GTK4. A GtkCheckButton joined to a group
    * behaves as a radio button and renders as one -- there is no separate
    * widget class any more.
    */
   ctx->all = gtk_check_button_new_with_mnemonic("a_ll");
   ctx->tcp = gtk_check_button_new_with_mnemonic("_tcp");
   ctx->udp = gtk_check_button_new_with_mnemonic("_udp");

   gtk_check_button_set_group(GTK_CHECK_BUTTON(ctx->tcp),
         GTK_CHECK_BUTTON(ctx->all));
   gtk_check_button_set_group(GTK_CHECK_BUTTON(ctx->udp),
         GTK_CHECK_BUTTON(ctx->all));

   if (!strncasecmp(EC_GBL_OPTIONS->proto, "tcp", 4))
      gtk_check_button_set_active(GTK_CHECK_BUTTON(ctx->tcp), TRUE);
   else if (!strncasecmp(EC_GBL_OPTIONS->proto, "udp", 4))
      gtk_check_button_set_active(GTK_CHECK_BUTTON(ctx->udp), TRUE);
   else
      gtk_check_button_set_active(GTK_CHECK_BUTTON(ctx->all), TRUE);

   box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
   gtk_widget_set_halign(box, GTK_ALIGN_CENTER);
   gtk_box_append(GTK_BOX(box), ctx->all);
   gtk_box_append(GTK_BOX(box), ctx->tcp);
   gtk_box_append(GTK_BOX(box), ctx->udp);

   gtkui_dialog_confirm("Set protocol", "Select the protocol", box,
         on_protocol_response, ctx, g_free);
}

/*******************************************/
/* target entry                                                            */
/*******************************************/

#define TARGET_LEN ETH_ASCII_ADDR_LEN + 1 + \
                   IP_ASCII_ADDR_LEN + 1 + \
                   IP6_ASCII_ADDR_LEN + 1 + \
                   5 + 1

struct targets_ctx {
   GtkWidget *t1_mac, *t1_ip, *t1_port;
   GtkWidget *t2_mac, *t2_ip, *t2_port;
#ifdef WITH_IPV6
   GtkWidget *t1_ipv6, *t2_ipv6;
#endif
};

static const char *entry_text(GtkWidget *entry)
{
   return gtk_editable_get_text(GTK_EDITABLE(entry));
}

static void on_targets_response(gboolean confirmed, gpointer data)
{
   struct targets_ctx *ctx = data;

   if (!confirmed)
      return;

   SAFE_FREE(EC_GBL_OPTIONS->target1);
   SAFE_FREE(EC_GBL_OPTIONS->target2);

   SAFE_CALLOC(EC_GBL_OPTIONS->target1, TARGET_LEN, sizeof(char));
   SAFE_CALLOC(EC_GBL_OPTIONS->target2, TARGET_LEN, sizeof(char));

#ifdef WITH_IPV6
   snprintf(EC_GBL_OPTIONS->target1, TARGET_LEN, "%s/%s/%s/%s",
         entry_text(ctx->t1_mac), entry_text(ctx->t1_ip),
         entry_text(ctx->t1_ipv6), entry_text(ctx->t1_port));
   snprintf(EC_GBL_OPTIONS->target2, TARGET_LEN, "%s/%s/%s/%s",
         entry_text(ctx->t2_mac), entry_text(ctx->t2_ip),
         entry_text(ctx->t2_ipv6), entry_text(ctx->t2_port));
#else
   snprintf(EC_GBL_OPTIONS->target1, TARGET_LEN, "%s/%s/%s",
         entry_text(ctx->t1_mac), entry_text(ctx->t1_ip),
         entry_text(ctx->t1_port));
   snprintf(EC_GBL_OPTIONS->target2, TARGET_LEN, "%s/%s/%s",
         entry_text(ctx->t2_mac), entry_text(ctx->t2_ip),
         entry_text(ctx->t2_port));
#endif

   set_targets();
}

static GtkWidget *labelled_entry(GtkWidget *grid, int row, const char *text)
{
   GtkWidget *label, *entry;

   label = gtk_label_new(text);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1);

   entry = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(entry), MAX_ASCII_ADDR_LEN);
   gtk_editable_set_width_chars(GTK_EDITABLE(entry), MAX_ASCII_ADDR_LEN);
   gtk_grid_attach(GTK_GRID(grid), entry, 1, row, 1, 1);

   return entry;
}

/*
 * Split a stored "mac/ip[/ipv6]/port" spec back into the entries.
 *
 * g_strsplit is asked for at most `nfields` pieces, but a malformed or
 * truncated stored value can still yield fewer -- the GTK3 code walked the
 * result with *p++ regardless and would read past the NULL terminator on a
 * short split. Count first.
 */
static void fill_target_entries(const char *spec, int nfields,
      GtkWidget **entries)
{
   gchar **tokens;
   int i, n;

   if (spec == NULL)
      return;

   tokens = g_strsplit(spec, "/", nfields);
   for (n = 0; tokens[n] != NULL; n++)
      ;

   for (i = 0; i < nfields && i < n; i++)
      gtk_editable_set_text(GTK_EDITABLE(entries[i]), tokens[i]);

   g_strfreev(tokens);
}

static GtkWidget *target_frame(const char *title, GtkWidget **mac,
      GtkWidget **ip, GtkWidget **ipv6, GtkWidget **port)
{
   GtkWidget *frame, *grid;
   int row = 0;

   (void) ipv6;

   frame = gtk_frame_new(title);
   gtk_widget_set_margin_bottom(frame, 10);

   grid = gtk_grid_new();
   gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 5);
   gtk_widget_set_margin_top(grid, 8);
   gtk_widget_set_margin_bottom(grid, 8);
   gtk_widget_set_margin_start(grid, 8);
   gtk_widget_set_margin_end(grid, 8);
   gtk_frame_set_child(GTK_FRAME(frame), grid);

   *mac = labelled_entry(grid, row++, "MAC:");
   *ip = labelled_entry(grid, row++, "IP address:");
#ifdef WITH_IPV6
   *ipv6 = labelled_entry(grid, row++, "IPv6 address:");
#endif
   *port = labelled_entry(grid, row++, "Port:");

   return frame;
}

/*
 * display the TARGET(s) dialog
 */
void gtkui_select_targets(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   struct targets_ctx *ctx;
   GtkWidget *box, *frame;
   GtkWidget *entries[4];
   int nfields;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_select_targets");

   SAFE_CALLOC(ctx, 1, sizeof(struct targets_ctx));

   box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

#ifdef WITH_IPV6
   nfields = 4;
   frame = target_frame("Target 1", &ctx->t1_mac, &ctx->t1_ip, &ctx->t1_ipv6,
         &ctx->t1_port);
   gtk_box_append(GTK_BOX(box), frame);
   entries[0] = ctx->t1_mac; entries[1] = ctx->t1_ip;
   entries[2] = ctx->t1_ipv6; entries[3] = ctx->t1_port;
   fill_target_entries(EC_GBL_OPTIONS->target1, nfields, entries);

   frame = target_frame("Target 2", &ctx->t2_mac, &ctx->t2_ip, &ctx->t2_ipv6,
         &ctx->t2_port);
   gtk_box_append(GTK_BOX(box), frame);
   entries[0] = ctx->t2_mac; entries[1] = ctx->t2_ip;
   entries[2] = ctx->t2_ipv6; entries[3] = ctx->t2_port;
   fill_target_entries(EC_GBL_OPTIONS->target2, nfields, entries);
#else
   nfields = 3;
   frame = target_frame("Target 1", &ctx->t1_mac, &ctx->t1_ip, NULL,
         &ctx->t1_port);
   gtk_box_append(GTK_BOX(box), frame);
   entries[0] = ctx->t1_mac; entries[1] = ctx->t1_ip; entries[2] = ctx->t1_port;
   fill_target_entries(EC_GBL_OPTIONS->target1, nfields, entries);

   frame = target_frame("Target 2", &ctx->t2_mac, &ctx->t2_ip, NULL,
         &ctx->t2_port);
   gtk_box_append(GTK_BOX(box), frame);
   entries[0] = ctx->t2_mac; entries[1] = ctx->t2_ip; entries[2] = ctx->t2_port;
   fill_target_entries(EC_GBL_OPTIONS->target2, nfields, entries);
#endif

   gtkui_dialog_confirm("Enter Targets", NULL, box, on_targets_response,
         ctx, g_free);
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

   if (!strcmp(EC_GBL_OPTIONS->target2, ""))
      SAFE_FREE(EC_GBL_OPTIONS->target2);

   /* compile the filters */
   compile_display_filter();

   /* if the 'current targets' window is displayed, refresh it */
   if (targets_window)
      gtkui_current_targets(NULL, NULL, NULL);
}

/*******************************************/
/* the current-targets view                                                */
/*******************************************/

static void on_target_setup(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_label_new(NULL);

   (void) factory;
   (void) data;

   gtk_label_set_xalign(GTK_LABEL(label), 0.0);
   gtk_list_item_set_child(item, label);
}

static void on_target_bind(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_list_item_get_child(item);
   EcTargetItem *obj = gtk_list_item_get_item(item);

   (void) factory;
   (void) data;

   if (obj != NULL && label != NULL)
      gtk_label_set_text(GTK_LABEL(label), obj->addr);
}

static GtkWidget *target_column_view(const char *title, GListStore *store,
      GtkSelectionModel **selection_out)
{
   GtkWidget *view;
   GtkListItemFactory *factory;
   GtkColumnViewColumn *column;
   GtkSortListModel *sortmodel;
   GtkExpression *expression;
   GtkSorter *sorter;

   view = gtk_column_view_new(NULL);

   sortmodel = gtk_sort_list_model_new(
         G_LIST_MODEL(g_object_ref(store)),
         g_object_ref(gtk_column_view_get_sorter(GTK_COLUMN_VIEW(view))));

   *selection_out = GTK_SELECTION_MODEL(
         gtk_multi_selection_new(G_LIST_MODEL(sortmodel)));
   gtk_column_view_set_model(GTK_COLUMN_VIEW(view), *selection_out);

   factory = gtk_signal_list_item_factory_new();
   g_signal_connect(factory, "setup", G_CALLBACK(on_target_setup), NULL);
   g_signal_connect(factory, "bind", G_CALLBACK(on_target_bind), NULL);

   column = gtk_column_view_column_new(title, factory);
   gtk_column_view_column_set_expand(column, TRUE);

   expression = gtk_property_expression_new(EC_TYPE_TARGET_ITEM, NULL, "addr");
   sorter = GTK_SORTER(gtk_string_sorter_new(expression));
   gtk_column_view_column_set_sorter(column, sorter);
   g_object_unref(sorter);

   gtk_column_view_append_column(GTK_COLUMN_VIEW(view), column);
   g_object_unref(column);

   return view;
}

static void delete_from_target(GtkSelectionModel *selection,
      GListStore *store, struct target_env *target)
{
   GtkBitset *bitset;
   GtkBitsetIter iter;
   GPtrArray *items;
   guint position, i, pos;

   if (selection == NULL)
      return;

   /*
    * Resolve the selection to items before touching the store: positions
    * are into the sorted model and every removal invalidates the ones after
    * it.
    */
   items = g_ptr_array_new_with_free_func(g_object_unref);
   bitset = gtk_selection_model_get_selection(selection);
   if (gtk_bitset_iter_init_first(&iter, bitset, &position)) {
      do {
         gpointer item = g_list_model_get_item(G_LIST_MODEL(selection),
               position);
         if (item != NULL)
            g_ptr_array_add(items, item);
      } while (gtk_bitset_iter_next(&iter, &position));
   }
   gtk_bitset_unref(bitset);

   for (i = 0; i < items->len; i++) {
      EcTargetItem *item = g_ptr_array_index(items, i);

      if (item->il == NULL)
         continue;

      /* remove the host from the list */
      del_ip_list(&item->il->ip, target);

      if (g_list_store_find(store, item, &pos))
         g_list_store_remove(store, pos);
   }

   g_ptr_array_unref(items);
}

static void on_delete_target1(GtkButton *button, gpointer data)
{
   (void) button; (void) data;

   DEBUG_MSG("gtkui_delete_target: list 1");
   delete_from_target(selection1, store1, EC_GBL_TARGET1);
}

static void on_delete_target2(GtkButton *button, gpointer data)
{
   (void) button; (void) data;

   DEBUG_MSG("gtkui_delete_target: list 2");
   delete_from_target(selection2, store2, EC_GBL_TARGET2);
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
      gtkui_message("Invalid ip address");
      return;
   }

   add_ip_list(&host, EC_GBL_TARGET2);

   gtkui_create_targets_array();
}

static void on_add_target1(GtkButton *button, gpointer data)
{
   (void) button; (void) data;

   DEBUG_MSG("gtk_add_target1");
   thost[0] = '\0';
   gtkui_input("IP address :", thost, MAX_ASCII_ADDR_LEN, add_target1);
}

static void on_add_target2(GtkButton *button, gpointer data)
{
   (void) button; (void) data;

   DEBUG_MSG("gtk_add_target2");
   thost[0] = '\0';
   gtkui_input("IP address :", thost, MAX_ASCII_ADDR_LEN, add_target2);
}

/*
 * display the list of current targets
 */
void gtkui_current_targets(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   GtkWidget *vbox, *hbox, *button, *scrolled, *view;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_current_targets");

   /* prepare the list models for the target lists */
   gtkui_create_targets_array();

   if (targets_window) {
      if (GTK_IS_WINDOW(targets_window))
         gtk_window_present(GTK_WINDOW(targets_window));
      else
         gtkui_page_present(targets_window);
      return;
   }

   targets_window = gtkui_page_new("Targets", &gtkui_targets_destroy,
         &gtkui_targets_detach);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_vexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(targets_window), vbox);

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_widget_set_vexpand(hbox, TRUE);
   gtk_box_append(GTK_BOX(vbox), hbox);

   /* list one */
   view = target_column_view("Target 1", store1, &selection1);
   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), view);
   gtk_widget_set_hexpand(scrolled, TRUE);
   gtk_box_append(GTK_BOX(hbox), scrolled);

   /* list two */
   view = target_column_view("Target 2", store2, &selection2);
   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), view);
   gtk_widget_set_hexpand(scrolled, TRUE);
   gtk_box_append(GTK_BOX(hbox), scrolled);

   /* buttons */
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_widget_set_margin_top(hbox, 6);
   gtk_widget_set_margin_bottom(hbox, 6);
   gtk_widget_set_margin_start(hbox, 6);
   gtk_widget_set_margin_end(hbox, 6);
   gtk_box_append(GTK_BOX(vbox), hbox);

   button = gtk_button_new_with_mnemonic("Delete");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked", G_CALLBACK(on_delete_target1), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("Add");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked", G_CALLBACK(on_add_target1), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("Delete");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked", G_CALLBACK(on_delete_target2), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("Add");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked", G_CALLBACK(on_add_target2), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   gtkui_page_present(targets_window);
}

static void gtkui_targets_detach(GtkWidget *child)
{
   targets_window = gtk_window_new();
   gtk_window_set_title(GTK_WINDOW(targets_window), "Current Targets");
   gtk_window_set_default_size(GTK_WINDOW(targets_window), 400, 300);
   g_signal_connect(targets_window, "close-request",
         G_CALLBACK(gtkui_targets_destroy), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(targets_window, gtkui_targets_attach);

   gtk_window_set_child(GTK_WINDOW(targets_window), child);

   gtk_window_present(GTK_WINDOW(targets_window));
}

static void gtkui_targets_attach(void)
{
   gtkui_targets_destroy();
   gtkui_current_targets(NULL, NULL, NULL);
}

static void gtkui_targets_destroy(void)
{
   if (targets_window == NULL)
      return;

   if (GTK_IS_WINDOW(targets_window))
      gtk_window_destroy(GTK_WINDOW(targets_window));
   else
      gtkui_page_close(targets_window, NULL);

   targets_window = NULL;
   selection1 = NULL;
   selection2 = NULL;
}

/*
 * (re)build the list models backing the two target views
 */
static void fill_target_store(GListStore *store, struct target_env *target)
{
   struct ip_list *il;
   char tmp[MAX_ASCII_ADDR_LEN];
   EcTargetItem *item;

   g_list_store_remove_all(store);

   LIST_FOREACH(il, &target->ips, next) {
      item = ec_target_item_new(il, ip_addr_ntoa(&il->ip, tmp));
      g_list_store_append(store, item);
      g_object_unref(item);
   }

#ifdef WITH_IPV6
   LIST_FOREACH(il, &target->ip6, next) {
      item = ec_target_item_new(il, ip_addr_ntoa(&il->ip, tmp));
      g_list_store_append(store, item);
      g_object_unref(item);
   }
#endif
}

void gtkui_create_targets_array(void)
{
   DEBUG_MSG("gtk_create_targets_array");

   if (store1 == NULL)
      store1 = g_list_store_new(EC_TYPE_TARGET_ITEM);
   if (store2 == NULL)
      store2 = g_list_store_new(EC_TYPE_TARGET_ITEM);

   fill_target_store(store1, EC_GBL_TARGET1);
   fill_target_store(store2, EC_GBL_TARGET2);
}

/* EOF */

// vim:ts=3:expandtab
