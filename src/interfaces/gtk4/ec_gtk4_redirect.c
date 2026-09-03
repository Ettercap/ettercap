/*
    ettercap -- GTK4 GUI -- SSL interception traffic redirects

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
#include <ec_redirect.h>

/* proto */
static void gtkui_sslredir_close(void);
static void gtkui_sslredir_detach(GtkWidget *child);
static void gtkui_sslredir_attach(void);
static void gtkui_sslredir_add(void);
static void gtkui_sslredir_del(void);
static void gtkui_sslredir_del_all(void);
static void gtkui_sslredir_add_list(struct redir_entry *re);
static void gtkui_sslredir_add_service(struct serv_entry *se);
static void gtkui_sslredir_create_lists(void);
static void gtkui_sslredir_refresh_lists(void);

/* globals */
static GtkWidget  *sslredir_window = NULL;
static GtkWidget  *redir_view = NULL;
static GListStore *redirrules = NULL;    /* of EcRedirItem */
static GListStore *proto_list = NULL;     /* of EcServiceItem */
static GtkSelectionModel *redir_selection = NULL;

/*******************************************/
/* EcServiceItem -- a registered service and its ports                     */
/*******************************************/

/*
 * The GTK3 code carried services and rules in GtkListStores whose columns
 * held G_TYPE_VARIANT-boxed uint16 ports -- a lot of ceremony to move two
 * integers through a widget. Real GObjects with typed fields hold the same
 * data plainly, and GtkDropDown/GtkColumnView bind to them directly.
 */
#define EC_TYPE_SERVICE_ITEM (ec_service_item_get_type())
G_DECLARE_FINAL_TYPE(EcServiceItem, ec_service_item, EC, SERVICE_ITEM, GObject)

struct _EcServiceItem {
   GObject parent_instance;
   char *name_lc;   /* lower case, as ec_redirect wants it */
   char *name_uc;   /* upper case, for display */
   guint16 from_port;
   guint16 to_port;
};

G_DEFINE_FINAL_TYPE(EcServiceItem, ec_service_item, G_TYPE_OBJECT)

static void ec_service_item_finalize(GObject *object)
{
   EcServiceItem *self = EC_SERVICE_ITEM(object);

   g_free(self->name_lc);
   g_free(self->name_uc);

   G_OBJECT_CLASS(ec_service_item_parent_class)->finalize(object);
}

static void ec_service_item_class_init(EcServiceItemClass *klass)
{
   G_OBJECT_CLASS(klass)->finalize = ec_service_item_finalize;
}

static void ec_service_item_init(EcServiceItem *self)
{
   (void) self;
}

static EcServiceItem *ec_service_item_new(const char *lc, const char *uc,
      guint16 from_port, guint16 to_port)
{
   EcServiceItem *self = g_object_new(EC_TYPE_SERVICE_ITEM, NULL);

   self->name_lc = g_strdup(lc);
   self->name_uc = g_strdup(uc);
   self->from_port = from_port;
   self->to_port = to_port;

   return self;
}

/*******************************************/
/* EcRedirItem -- one active redirect rule                                 */
/*******************************************/

#define EC_TYPE_REDIR_ITEM (ec_redir_item_get_type())
G_DECLARE_FINAL_TYPE(EcRedirItem, ec_redir_item, EC, REDIR_ITEM, GObject)

struct _EcRedirItem {
   GObject parent_instance;
   ec_redir_proto_t proto;
   char *version;      /* "IPv4"/"IPv6", for display and sorting */
   char *server;
   char *name_lc;
   char *service;      /* upper case, for display */
   guint16 from_port;
   guint16 to_port;
};

G_DEFINE_FINAL_TYPE(EcRedirItem, ec_redir_item, G_TYPE_OBJECT)

static void ec_redir_item_finalize(GObject *object)
{
   EcRedirItem *self = EC_REDIR_ITEM(object);

   g_free(self->version);
   g_free(self->server);
   g_free(self->name_lc);
   g_free(self->service);

   G_OBJECT_CLASS(ec_redir_item_parent_class)->finalize(object);
}

static void ec_redir_item_class_init(EcRedirItemClass *klass)
{
   G_OBJECT_CLASS(klass)->finalize = ec_redir_item_finalize;
}

static void ec_redir_item_init(EcRedirItem *self)
{
   (void) self;
}

static EcRedirItem *ec_redir_item_new(ec_redir_proto_t proto,
      const char *server, const char *name_lc, const char *service,
      guint16 from_port, guint16 to_port)
{
   EcRedirItem *self = g_object_new(EC_TYPE_REDIR_ITEM, NULL);

   self->proto = proto;
   self->version = g_strdup(proto == EC_REDIR_PROTO_IPV4 ? "IPv4" : "IPv6");
   self->server = g_strdup(server);
   self->name_lc = g_strdup(name_lc);
   self->service = g_strdup(service);
   self->from_port = from_port;
   self->to_port = to_port;

   return self;
}

/*******************************************/
/* the rules column view                                                   */
/*******************************************/

/*
 * A getter turns each item into the text for one column. Passing the getter
 * as the factory's user data means one setup/bind pair serves every column.
 */
typedef const char *(*redir_getter)(EcRedirItem *item);

static const char *redir_get_version(EcRedirItem *i) { return i->version; }
static const char *redir_get_server(EcRedirItem *i)  { return i->server; }
static const char *redir_get_service(EcRedirItem *i) { return i->service; }

static void on_redir_setup(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_label_new(NULL);

   (void) factory;
   (void) data;

   gtk_label_set_xalign(GTK_LABEL(label), 0.0);
   gtk_list_item_set_child(item, label);
}

static void on_redir_bind(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   redir_getter getter = data;
   GtkWidget *label = gtk_list_item_get_child(item);
   EcRedirItem *obj = gtk_list_item_get_item(item);

   (void) factory;

   if (obj != NULL && label != NULL)
      gtk_label_set_text(GTK_LABEL(label), getter(obj));
}

static void add_redir_column(GtkColumnView *view, const char *title,
      redir_getter getter)
{
   GtkListItemFactory *factory;
   GtkColumnViewColumn *column;

   factory = gtk_signal_list_item_factory_new();
   g_signal_connect(factory, "setup", G_CALLBACK(on_redir_setup), NULL);
   g_signal_connect(factory, "bind", G_CALLBACK(on_redir_bind), getter);

   column = gtk_column_view_column_new(title, factory);
   gtk_column_view_column_set_resizable(column, TRUE);
   gtk_column_view_column_set_expand(column, TRUE);
   gtk_column_view_append_column(view, column);
   g_object_unref(column);
}

/*******************************************/

/*
 * tab to configure traffic redirection for SSL interception
 */
void gtkui_sslredir_show(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *scrolled, *vbox, *hbox, *button;
   GtkSortListModel *sortmodel;
   GtkEventController *keys;
   GSimpleActionGroup *actions;
   GMenu *menu;
   GtkWidget *popover;
   GtkGesture *gesture;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_sslredir_show()");

   if (sslredir_window) {
      if (GTK_IS_WINDOW(sslredir_window))
         gtk_window_present(GTK_WINDOW(sslredir_window));
      else
         gtkui_page_present(sslredir_window);
      return;
   }

   sslredir_window = gtkui_page_new("SSL Intercept", &gtkui_sslredir_close,
         &gtkui_sslredir_detach);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_vexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(sslredir_window), vbox);

   gtkui_sslredir_create_lists();

   redir_view = gtk_column_view_new(NULL);
   gtk_column_view_set_show_row_separators(GTK_COLUMN_VIEW(redir_view), TRUE);

   sortmodel = gtk_sort_list_model_new(
         G_LIST_MODEL(g_object_ref(redirrules)),
         g_object_ref(gtk_column_view_get_sorter(GTK_COLUMN_VIEW(redir_view))));
   redir_selection = GTK_SELECTION_MODEL(
         gtk_multi_selection_new(G_LIST_MODEL(sortmodel)));
   gtk_column_view_set_model(GTK_COLUMN_VIEW(redir_view), redir_selection);

   add_redir_column(GTK_COLUMN_VIEW(redir_view), "IP Version",
         redir_get_version);
   add_redir_column(GTK_COLUMN_VIEW(redir_view), "Server IP",
         redir_get_server);
   add_redir_column(GTK_COLUMN_VIEW(redir_view), "Service",
         redir_get_service);

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), redir_view);
   gtk_widget_set_vexpand(scrolled, TRUE);
   gtk_box_append(GTK_BOX(vbox), scrolled);

   /* buttons */
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
   gtk_widget_set_margin_top(hbox, 6);
   gtk_widget_set_margin_bottom(hbox, 6);
   gtk_widget_set_margin_start(hbox, 6);
   gtk_widget_set_margin_end(hbox, 6);
   gtk_box_append(GTK_BOX(vbox), hbox);

   button = gtk_button_new_with_mnemonic("_Insert new redirect");
   gtk_widget_set_hexpand(button, TRUE);
   gtk_widget_set_sensitive(button, proto_list != NULL);
   g_signal_connect_swapped(button, "clicked",
         G_CALLBACK(gtkui_sslredir_add), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("_Remove redirect");
   gtk_widget_set_hexpand(button, TRUE);
   gtk_widget_set_sensitive(button, proto_list != NULL);
   g_signal_connect_swapped(button, "clicked",
         G_CALLBACK(gtkui_sslredir_del), NULL);
   gtk_box_append(GTK_BOX(hbox), button);

   /*
    * The rule actions are exposed as a GActionGroup on the view so the
    * context menu and the keyboard shortcuts drive the same code. The
    * helpers take no arguments, so each action's "activate" is connected
    * swapped -- the action and parameter are ignored.
    */
   actions = g_simple_action_group_new();
   {
      GSimpleAction *a;

      a = g_simple_action_new("remove", NULL);
      g_signal_connect_swapped(a, "activate",
            G_CALLBACK(gtkui_sslredir_del), NULL);
      g_action_map_add_action(G_ACTION_MAP(actions), G_ACTION(a));
      g_object_unref(a);

      a = g_simple_action_new("remove-all", NULL);
      g_signal_connect_swapped(a, "activate",
            G_CALLBACK(gtkui_sslredir_del_all), NULL);
      g_action_map_add_action(G_ACTION_MAP(actions), G_ACTION(a));
      g_object_unref(a);

      a = g_simple_action_new("insert", NULL);
      g_signal_connect_swapped(a, "activate",
            G_CALLBACK(gtkui_sslredir_add), NULL);
      g_action_map_add_action(G_ACTION_MAP(actions), G_ACTION(a));
      g_object_unref(a);

      a = g_simple_action_new("refresh", NULL);
      g_signal_connect_swapped(a, "activate",
            G_CALLBACK(gtkui_sslredir_refresh_lists), NULL);
      g_action_map_add_action(G_ACTION_MAP(actions), G_ACTION(a));
      g_object_unref(a);
   }
   gtk_widget_insert_action_group(redir_view, "redir",
         G_ACTION_GROUP(actions));

   menu = g_menu_new();
   g_menu_append(menu, "Remove redirect", "redir.remove");
   g_menu_append(menu, "Remove all redirects", "redir.remove-all");
   g_menu_append(menu, "Refresh redirects", "redir.refresh");

   popover = gtk_popover_menu_new_from_model(G_MENU_MODEL(menu));
   gtk_widget_set_parent(popover, redir_view);
   gtk_popover_set_has_arrow(GTK_POPOVER(popover), FALSE);
   gtk_widget_set_halign(popover, GTK_ALIGN_START);

   gesture = gtk_gesture_click_new();
   gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(gesture),
         GDK_BUTTON_SECONDARY);
   g_signal_connect_swapped(gesture, "pressed",
         G_CALLBACK(gtk_popover_popup), popover);
   gtk_widget_add_controller(redir_view, GTK_EVENT_CONTROLLER(gesture));

   /*
    * Delete / Insert / F5 shortcuts. GTK3 read these off a
    * key-press-event; GTK4 uses a key event controller, and the action
    * group above lets the same handlers serve both the menu and the keys.
    */
   keys = gtk_shortcut_controller_new();
   gtk_shortcut_controller_add_shortcut(GTK_SHORTCUT_CONTROLLER(keys),
         gtk_shortcut_new(gtk_keyval_trigger_new(GDK_KEY_Delete, 0),
            gtk_named_action_new("redir.remove")));
   gtk_shortcut_controller_add_shortcut(GTK_SHORTCUT_CONTROLLER(keys),
         gtk_shortcut_new(gtk_keyval_trigger_new(GDK_KEY_Insert, 0),
            gtk_named_action_new("redir.insert")));
   gtk_shortcut_controller_add_shortcut(GTK_SHORTCUT_CONTROLLER(keys),
         gtk_shortcut_new(gtk_keyval_trigger_new(GDK_KEY_F5, 0),
            gtk_named_action_new("redir.refresh")));
   gtk_widget_add_controller(redir_view, keys);

   g_object_unref(actions);
   g_object_unref(menu);

   gtkui_page_present(sslredir_window);
}

/*******************************************/
/* add a rule                                                              */
/*******************************************/

struct af_choice {
   const char *label;
   ec_redir_proto_t proto;
   const char *preset;
};

static const struct af_choice af_choices[] = {
   { "IPv4", EC_REDIR_PROTO_IPV4, "0.0.0.0/0" },
#ifdef WITH_IPV6
   { "IPv6", EC_REDIR_PROTO_IPV6, "::/0" },
#endif
};

struct add_ctx {
   GtkWidget *af;       /* GtkDropDown over af_choices */
   GtkWidget *proto;    /* GtkDropDown over proto_list */
   GtkWidget *server;   /* GtkEntry */
};

/*
 * When the address family changes, refresh the server entry's preset -- but
 * only if the user has not typed over it. The GTK3 code always clobbered it.
 */
static void on_af_changed(GtkDropDown *dropdown, GParamSpec *pspec,
      gpointer data)
{
   struct add_ctx *ctx = data;
   guint idx = gtk_drop_down_get_selected(dropdown);
   const char *current;
   guint i;

   (void) pspec;

   if (idx >= G_N_ELEMENTS(af_choices))
      return;

   current = gtk_editable_get_text(GTK_EDITABLE(ctx->server));

   /* leave anything the user typed alone; only replace a known preset */
   for (i = 0; i < G_N_ELEMENTS(af_choices); i++) {
      if (!strcmp(current, af_choices[i].preset)) {
         gtk_editable_set_text(GTK_EDITABLE(ctx->server),
               af_choices[idx].preset);
         break;
      }
   }
}

static void on_add_response(gboolean confirmed, gpointer data)
{
   struct add_ctx *ctx = data;
   const struct af_choice *af;
   EcServiceItem *service;
   const char *server;
   guint af_idx;
   int ret;

   if (!confirmed)
      return;

   af_idx = gtk_drop_down_get_selected(GTK_DROP_DOWN(ctx->af));
   if (af_idx >= G_N_ELEMENTS(af_choices))
      return;
   af = &af_choices[af_idx];

   service = gtk_drop_down_get_selected_item(GTK_DROP_DOWN(ctx->proto));
   if (service == NULL)
      return;

   server = gtk_editable_get_text(GTK_EDITABLE(ctx->server));

   ret = ec_redirect(EC_REDIR_ACTION_INSERT, service->name_lc, af->proto,
         server, service->from_port, service->to_port);

   if (ret != E_SUCCESS) {
      gtkui_toast_error("Insertion of redirect rule failed.");
      return;
   }

   /* otherwise add the rule to the list */
   {
      EcRedirItem *rule = ec_redir_item_new(af->proto, server,
            service->name_lc, service->name_uc,
            service->from_port, service->to_port);
      g_list_store_append(redirrules, rule);
      g_object_unref(rule);
   }
}

/* factory for the service dropdown: show the upper-case protocol name */
static void on_service_setup(GtkSignalListItemFactory *f, GtkListItem *item,
      gpointer data)
{
   (void) f;
   (void) data;
   gtk_list_item_set_child(item, gtk_label_new(NULL));
}

static void on_service_bind(GtkSignalListItemFactory *f, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_list_item_get_child(item);
   EcServiceItem *obj = gtk_list_item_get_item(item);

   (void) f;
   (void) data;

   if (obj != NULL && label != NULL)
      gtk_label_set_text(GTK_LABEL(label), obj->name_uc);
}

/* Add a new redirect rule */
static void gtkui_sslredir_add(void)
{
   struct add_ctx *ctx;
   GtkWidget *grid, *label;
   GtkStringList *af_names;
   GtkListItemFactory *factory;
   guint i;

   DEBUG_MSG("gtkui_sslredir_add()");

   if (proto_list == NULL)
      return;

   SAFE_CALLOC(ctx, 1, sizeof(struct add_ctx));

   af_names = gtk_string_list_new(NULL);
   for (i = 0; i < G_N_ELEMENTS(af_choices); i++)
      gtk_string_list_append(af_names, af_choices[i].label);
   ctx->af = gtk_drop_down_new(G_LIST_MODEL(af_names), NULL);

   factory = gtk_signal_list_item_factory_new();
   g_signal_connect(factory, "setup", G_CALLBACK(on_service_setup), NULL);
   g_signal_connect(factory, "bind", G_CALLBACK(on_service_bind), NULL);
   ctx->proto = gtk_drop_down_new(
         G_LIST_MODEL(g_object_ref(proto_list)), NULL);
   gtk_drop_down_set_factory(GTK_DROP_DOWN(ctx->proto), factory);
   g_object_unref(factory);

   ctx->server = gtk_entry_new();
   gtk_editable_set_text(GTK_EDITABLE(ctx->server), af_choices[0].preset);

   g_signal_connect(ctx->af, "notify::selected",
         G_CALLBACK(on_af_changed), ctx);

   grid = gtk_grid_new();
   gtk_grid_set_row_spacing(GTK_GRID(grid), 5);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 5);

   label = gtk_label_new("IP Version:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 1, 1);
   gtk_grid_attach(GTK_GRID(grid), ctx->af, 1, 0, 1, 1);

   label = gtk_label_new("Server IP:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, 1, 1, 1);
   gtk_grid_attach(GTK_GRID(grid), ctx->server, 1, 1, 1, 1);

   label = gtk_label_new("Service:");
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, 2, 1, 1);
   gtk_grid_attach(GTK_GRID(grid), ctx->proto, 1, 2, 1, 1);

   gtkui_dialog_confirm("Create new redirect rule", "Redirect specification",
         grid, on_add_response, ctx, g_free);
}

/*******************************************/
/* remove rules                                                            */
/*******************************************/

static void gtkui_sslredir_del(void)
{
   GtkBitset *bitset;
   GtkBitsetIter iter;
   GPtrArray *items;
   guint position, i, pos;

   DEBUG_MSG("gtkui_sslredir_del()");

   if (redir_selection == NULL)
      return;

   /* resolve the selection before mutating the store */
   items = g_ptr_array_new_with_free_func(g_object_unref);
   bitset = gtk_selection_model_get_selection(redir_selection);
   if (gtk_bitset_iter_init_first(&iter, bitset, &position)) {
      do {
         gpointer item = g_list_model_get_item(
               G_LIST_MODEL(redir_selection), position);
         if (item != NULL)
            g_ptr_array_add(items, item);
      } while (gtk_bitset_iter_next(&iter, &position));
   }
   gtk_bitset_unref(bitset);

   for (i = 0; i < items->len; i++) {
      EcRedirItem *rule = g_ptr_array_index(items, i);
      int ret;

      ret = ec_redirect(EC_REDIR_ACTION_REMOVE, rule->name_lc, rule->proto,
            rule->server, rule->from_port, rule->to_port);

      if (ret != E_SUCCESS) {
         gtkui_toast_error("Removal of redirect rule failed.");
         continue;
      }

      if (g_list_store_find(redirrules, rule, &pos))
         g_list_store_remove(redirrules, pos);
   }

   g_ptr_array_unref(items);
}

static void gtkui_sslredir_del_all(void)
{
   DEBUG_MSG("gtkui_sslredir_del_all()");

   if (redir_selection != NULL)
      gtk_selection_model_select_all(redir_selection);

   gtkui_sslredir_del();
}

/*******************************************/

static void gtkui_sslredir_detach(GtkWidget *child)
{
   sslredir_window = gtk_window_new();
   gtk_window_set_title(GTK_WINDOW(sslredir_window), "SSL Intercept");
   gtk_window_set_default_size(GTK_WINDOW(sslredir_window), 500, 250);
   g_signal_connect(sslredir_window, "close-request",
         G_CALLBACK(gtkui_sslredir_close), NULL);

   gtkui_page_attach_shortcut(sslredir_window, gtkui_sslredir_attach);

   gtk_window_set_child(GTK_WINDOW(sslredir_window), child);
   gtk_window_present(GTK_WINDOW(sslredir_window));
}

static void gtkui_sslredir_attach(void)
{
   gtkui_sslredir_close();
   gtkui_sslredir_show(NULL, NULL, NULL);
}

static void gtkui_sslredir_close(void)
{
   DEBUG_MSG("gtk_sslredir_close");

   if (sslredir_window == NULL)
      return;

   if (GTK_IS_WINDOW(sslredir_window))
      gtk_window_destroy(GTK_WINDOW(sslredir_window));
   else
      gtkui_page_close(sslredir_window, NULL);

   sslredir_window = NULL;
   redir_view = NULL;
   redir_selection = NULL;
}

/*
 * create the models backing the rules view and the service dropdown
 */
static void gtkui_sslredir_create_lists(void)
{
   DEBUG_MSG("gtk_sslredir_create_lists()");

   if (redirrules == NULL)
      redirrules = g_list_store_new(EC_TYPE_REDIR_ITEM);
   if (proto_list == NULL)
      proto_list = g_list_store_new(EC_TYPE_SERVICE_ITEM);

   gtkui_sslredir_refresh_lists();
}

/*
 * rebuild the models from the registered redirects and services
 */
static void gtkui_sslredir_refresh_lists(void)
{
   int res;

   if (redirrules == NULL || proto_list == NULL)
      return;

   g_list_store_remove_all(redirrules);
   g_list_store_remove_all(proto_list);

   /* walk registered redirects */
   res = ec_walk_redirects(&gtkui_sslredir_add_list);
   if (res == -E_NOTFOUND) {
      DEBUG_MSG("gtk_sslredir_create_lists(): no redirects registered");
      gtkui_toast("No traffic redirects. Maybe not enabled in etter.conf!");
   }

   /* walk registered services */
   res = ec_walk_redirect_services(&gtkui_sslredir_add_service);
   if (res == -E_NOTFOUND) {
      g_object_unref(proto_list);
      proto_list = NULL;
   }
}

static void gtkui_sslredir_add_service(struct serv_entry *se)
{
   EcServiceItem *item;

   DEBUG_MSG("gtkui_sslredir_add_service(%s)", se->name);

   item = ec_service_item_new(ec_strlc(se->name), ec_struc(se->name),
         se->from_port, se->to_port);
   g_list_store_append(proto_list, item);
   g_object_unref(item);
}

static void gtkui_sslredir_add_list(struct redir_entry *re)
{
   EcRedirItem *item;

   DEBUG_MSG("gtkui_sslredir_add_list(%s)", re->name);

   item = ec_redir_item_new(re->proto, re->destination,
         ec_strlc(re->name), ec_struc(re->name),
         re->from_port, re->to_port);
   g_list_store_append(redirrules, item);
   g_object_unref(item);
}

/* EOF */

// vim:ts=3:expandtab
