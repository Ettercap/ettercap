/*
    ettercap -- GTK4 GUI -- the host list

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
 * This is the first of the list views to move from GtkTreeView/GtkListStore
 * to GtkColumnView over a GListModel, and it is the template the others
 * follow.
 *
 * The shape of the change: instead of a store of loosely typed columns plus
 * a hidden pointer column holding the struct hosts_list *, rows are real
 * GObjects (EcHostItem) that own their strings and reference the underlying
 * host. That removes three sharp edges the GTK3 code had to work around:
 *
 *   - The hidden 4th column. GtkListStore had no type for "the thing this
 *     row is about", so the pointer rode along as G_TYPE_POINTER and every
 *     read had to remember which column index it lived in.
 *   - Iterators outliving their rows. Deferred name resolution held a
 *     GtkTreeIter; deleting the host before the name arrived left the timer
 *     writing through a stale iter. Items are refcounted, so the pending
 *     resolution simply keeps its row alive.
 *   - Sorting by column index. Sorters are expressions over properties now,
 *     so "sort by MAC" cannot silently become "sort by column 1" if the
 *     column order changes.
 */

#include <ec.h>
#include <ec_gtk4.h>
#include <ec_scan.h>

/* proto */
static void gtkui_hosts_destroy(void);
static void gtkui_hosts_detach(GtkWidget *child);
static void gtkui_hosts_attach(void);

/* globals */
static GtkWidget       *hosts_window = NULL;
static GtkWidget       *hosts_view = NULL;
static GListStore      *hosts_store = NULL;
static GtkSelectionModel *hosts_selection = NULL;

enum { HOST_DELETE, HOST_TARGET1, HOST_TARGET2 };

/*******************************************/
/* EcHostItem                                                              */
/*******************************************/

struct _EcHostItem {
   GObject parent_instance;

   char *ip;
   char *mac;
   char *name;

   /* the entry this row stands for; not owned */
   struct hosts_list *hl;
};

G_DEFINE_FINAL_TYPE(EcHostItem, ec_host_item, G_TYPE_OBJECT)

enum {
   PROP_0,
   PROP_IP,
   PROP_MAC,
   PROP_NAME,
   N_PROPS
};

static GParamSpec *host_props[N_PROPS];

static void ec_host_item_finalize(GObject *object)
{
   EcHostItem *self = EC_HOST_ITEM(object);

   g_free(self->ip);
   g_free(self->mac);
   g_free(self->name);

   G_OBJECT_CLASS(ec_host_item_parent_class)->finalize(object);
}

static void ec_host_item_get_property(GObject *object, guint prop_id,
      GValue *value, GParamSpec *pspec)
{
   EcHostItem *self = EC_HOST_ITEM(object);

   switch (prop_id) {
      case PROP_IP:   g_value_set_string(value, self->ip); break;
      case PROP_MAC:  g_value_set_string(value, self->mac); break;
      case PROP_NAME: g_value_set_string(value, self->name); break;
      default: G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
   }
}

static void ec_host_item_set_property(GObject *object, guint prop_id,
      const GValue *value, GParamSpec *pspec)
{
   EcHostItem *self = EC_HOST_ITEM(object);

   switch (prop_id) {
      case PROP_IP:
         g_free(self->ip);
         self->ip = g_value_dup_string(value);
         break;
      case PROP_MAC:
         g_free(self->mac);
         self->mac = g_value_dup_string(value);
         break;
      case PROP_NAME:
         g_free(self->name);
         self->name = g_value_dup_string(value);
         break;
      default: G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
   }
}

static void ec_host_item_class_init(EcHostItemClass *klass)
{
   GObjectClass *object_class = G_OBJECT_CLASS(klass);

   object_class->finalize = ec_host_item_finalize;
   object_class->get_property = ec_host_item_get_property;
   object_class->set_property = ec_host_item_set_property;

   host_props[PROP_IP] = g_param_spec_string("ip", NULL, NULL, NULL,
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
   host_props[PROP_MAC] = g_param_spec_string("mac", NULL, NULL, NULL,
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
   host_props[PROP_NAME] = g_param_spec_string("name", NULL, NULL, NULL,
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);

   g_object_class_install_properties(object_class, N_PROPS, host_props);
}

static void ec_host_item_init(EcHostItem *self)
{
   (void) self;
}

static EcHostItem *ec_host_item_new(struct hosts_list *hl, const char *ip,
      const char *mac, const char *name)
{
   EcHostItem *self = g_object_new(EC_TYPE_HOST_ITEM, NULL);

   self->hl = hl;
   self->ip = g_strdup(ip);
   self->mac = g_strdup(mac);
   self->name = g_strdup(name);

   return self;
}

/*******************************************/
/* column view plumbing                                                    */
/*******************************************/

/*
 * One factory serves every text column; which property it shows is attached
 * to the factory. Writing three near-identical factories is how these files
 * grow, and the columns differ only in that one name.
 */
static void on_item_setup(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_label_new(NULL);

   (void) factory;
   (void) data;

   gtk_label_set_xalign(GTK_LABEL(label), 0.0);
   gtk_label_set_ellipsize(GTK_LABEL(label), PANGO_ELLIPSIZE_END);
   gtk_list_item_set_child(item, label);
}

static void on_item_bind(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   const char *property = data;
   GtkWidget *label = gtk_list_item_get_child(item);
   GObject *obj = gtk_list_item_get_item(item);
   GBinding *binding;

   (void) factory;

   if (obj == NULL || label == NULL)
      return;

   /*
    * Bind rather than copy: deferred name resolution writes the "name"
    * property later, and a binding makes the row pick that up on its own.
    * The binding is stashed so it can be dropped when the row is recycled --
    * GtkColumnView reuses row widgets aggressively, and a binding left in
    * place would keep updating a label that now shows a different host.
    */
   binding = g_object_bind_property(obj, property, label, "label",
         G_BINDING_SYNC_CREATE);
   g_object_set_data(G_OBJECT(item), "binding", binding);
}

static void on_item_unbind(GtkListItemFactory *factory, GtkListItem *item,
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

static void add_text_column(GtkColumnView *view, const char *title,
      const char *property, gboolean expand)
{
   GtkListItemFactory *factory;
   GtkColumnViewColumn *column;
   GtkExpression *expression;
   GtkSorter *sorter;

   factory = gtk_signal_list_item_factory_new();
   g_signal_connect(factory, "setup", G_CALLBACK(on_item_setup), NULL);
   g_signal_connect(factory, "bind", G_CALLBACK(on_item_bind),
         (gpointer)property);
   g_signal_connect(factory, "unbind", G_CALLBACK(on_item_unbind), NULL);

   column = gtk_column_view_column_new(title, factory);
   gtk_column_view_column_set_resizable(column, TRUE);
   gtk_column_view_column_set_expand(column, expand);

   /*
    * Sorting is expressed over the property, not over a column index, so
    * reordering the columns cannot silently change what a sort does.
    */
   expression = gtk_property_expression_new(EC_TYPE_HOST_ITEM, NULL, property);
   sorter = GTK_SORTER(gtk_string_sorter_new(expression));
   gtk_column_view_column_set_sorter(column, sorter);
   g_object_unref(sorter);

   gtk_column_view_append_column(view, column);
   g_object_unref(column);
}

/*******************************************/

#ifdef WITH_IPV6
void toggle_ip6scan(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) data;

   g_simple_action_set_state(action, value);

   EC_GBL_OPTIONS->ip6scan ^= 1;
}
#endif

/*
 * scan the lan for hosts
 */
void gtkui_scan(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   /* no target defined...  force a full scan */
   if (EC_GBL_TARGET1->all_ip && EC_GBL_TARGET2->all_ip &&
       EC_GBL_TARGET1->all_ip6 && EC_GBL_TARGET2->all_ip6 &&
      !EC_GBL_TARGET1->scan_all && !EC_GBL_TARGET2->scan_all) {
      EC_GBL_TARGET1->scan_all = 1;
      EC_GBL_TARGET2->scan_all = 1;
   }

   /* perform a new scan */
   build_hosts_list();
}

/*******************************************/
/* load / save                                                             */
/*******************************************/

static char hosts_filename[PATH_MAX];

static void load_hosts(const char *file)
{
   char *tmp;
   char current[PATH_MAX];

   DEBUG_MSG("load_hosts %s", file);

   SAFE_CALLOC(tmp, strlen(file) + 1, sizeof(char));

   /* get the current working directory */
   if (getcwd(current, PATH_MAX) == NULL)
      current[0] = '\0';

   /*
    * we are opening a file in the current dir.
    * use the relative path, so we can open files
    * in the current dir even if the complete path
    * is not traversable with ec_uid permissions
    */
   if (current[0] != '\0' && !strncmp(current, file, strlen(current)))
      snprintf(tmp, strlen(file) + 1, "./%s", file + strlen(current));
   else
      snprintf(tmp, strlen(file) + 1, "%s", file);

   DEBUG_MSG("load_hosts path == %s", tmp);

   /* wipe the current list */
   del_hosts_list();

   /* load the hosts list */
   scan_load_hosts(tmp);

   SAFE_FREE(tmp);

   gtkui_host_list(NULL, NULL, NULL);
}

static void on_hosts_loaded(gboolean confirmed, gpointer data)
{
   (void) data;

   if (!confirmed)
      return;

   load_hosts(hosts_filename);
   gtkui_refresh_host_list(NULL);
}

/*
 * display the file open dialog
 */
void gtkui_load_hosts(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_load_hosts");

   hosts_filename[0] = '\0';
   gtkui_filename_browse("Select a hosts file...", FALSE, hosts_filename,
         sizeof(hosts_filename), on_hosts_loaded, NULL, NULL);
}

static void save_hosts(void)
{
   FILE *f;

   /* check if the file is writeable */
   f = fopen(EC_GBL_OPTIONS->hostsfile, "w");
   if (f == NULL) {
      ui_error("Cannot write %s", EC_GBL_OPTIONS->hostsfile);
      SAFE_FREE(EC_GBL_OPTIONS->hostsfile);
      return;
   }

   /* if ok, delete it */
   fclose(f);
   unlink(EC_GBL_OPTIONS->hostsfile);

   scan_save_hosts(EC_GBL_OPTIONS->hostsfile);
}

static void on_hosts_saved(gboolean confirmed, gpointer data)
{
   (void) data;

   if (!confirmed)
      return;

   /*
    * The GTK3 code allocated a fixed 40-byte buffer and filled it with
    * memcpy(hostsfile, filename, FILE_LEN) -- a fixed-size copy from a
    * NUL-terminated string, over-reading on short names and truncating
    * without a terminator on long ones. strdup of the actual path avoids
    * both, and lifts the 40-character limit on where hosts can be saved.
    */
   SAFE_FREE(EC_GBL_OPTIONS->hostsfile);
   EC_GBL_OPTIONS->hostsfile = strdup(hosts_filename);

   save_hosts();
}

/*
 * display the write file menu
 */
void gtkui_save_hosts(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_save_hosts");

   hosts_filename[0] = '\0';
   gtkui_filename_browse("Save hosts to file...", TRUE, hosts_filename,
         sizeof(hosts_filename), on_hosts_saved, NULL, NULL);
}

/*******************************************/
/* actions on the selection                                                */
/*******************************************/

/*
 * Collect the selected rows as a plain list of items.
 *
 * The selection is expressed as a GtkBitset over the *sorted* model, so it
 * has to be resolved to items before anything mutates the store -- removing
 * a row shifts every later position, and the GTK3 code only got away with
 * iterating in place because it walked its selection backwards.
 */
static GPtrArray *selected_hosts(void)
{
   GPtrArray *items = g_ptr_array_new_with_free_func(g_object_unref);
   GtkBitset *bitset;
   GtkBitsetIter iter;
   guint position;

   if (hosts_selection == NULL)
      return items;

   bitset = gtk_selection_model_get_selection(hosts_selection);

   if (gtk_bitset_iter_init_first(&iter, bitset, &position)) {
      do {
         gpointer item = g_list_model_get_item(G_LIST_MODEL(hosts_selection),
               position);
         if (item != NULL)
            g_ptr_array_add(items, item);
      } while (gtk_bitset_iter_next(&iter, &position));
   }

   gtk_bitset_unref(bitset);

   return items;
}

static void hosts_action(gint type)
{
   GPtrArray *items;
   char tmp[MAX_ASCII_ADDR_LEN];
   guint i, pos;

   items = selected_hosts();

   for (i = 0; i < items->len; i++) {
      EcHostItem *item = g_ptr_array_index(items, i);
      struct hosts_list *hl = item->hl;

      if (hl == NULL)
         continue;

      switch (type) {
         case HOST_DELETE:
            DEBUG_MSG("hosts_action: delete host");
            if (g_list_store_find(hosts_store, item, &pos))
               g_list_store_remove(hosts_store, pos);

            /* remove the host from the list */
            LIST_REMOVE(hl, next);
            SAFE_FREE(hl->hostname);
            SAFE_FREE(hl);
            item->hl = NULL;
            break;

         case HOST_TARGET1:
            DEBUG_MSG("hosts_action: add target1");
            add_ip_list(&hl->ip, EC_GBL_TARGET1);
            gtkui_create_targets_array();
            USER_MSG("Host %s added to TARGET1\n", ip_addr_ntoa(&hl->ip, tmp));
            break;

         case HOST_TARGET2:
            DEBUG_MSG("hosts_action: add target2");
            add_ip_list(&hl->ip, EC_GBL_TARGET2);
            gtkui_create_targets_array();
            USER_MSG("Host %s added to TARGET2\n", ip_addr_ntoa(&hl->ip, tmp));
            break;
      }
   }

   g_ptr_array_unref(items);
}

static void on_delete_host(GSimpleAction *action, GVariant *value, gpointer d)
{
   (void) action; (void) value; (void) d;
   hosts_action(HOST_DELETE);
}

static void on_add_target1(GSimpleAction *action, GVariant *value, gpointer d)
{
   (void) action; (void) value; (void) d;
   hosts_action(HOST_TARGET1);
}

static void on_add_target2(GSimpleAction *action, GVariant *value, gpointer d)
{
   (void) action; (void) value; (void) d;
   hosts_action(HOST_TARGET2);
}

static void on_button_clicked(GtkButton *button, gpointer data)
{
   (void) button;

   hosts_action(GPOINTER_TO_INT(data));
}

/*
 * Right-click context menu.
 *
 * GTK4 has no GtkMenu and no button-press-event: a GtkPopoverMenu is
 * positioned by hand and raised from a GtkGestureClick.
 */
static void on_right_click(GtkGestureClick *gesture, gint n_press,
      gdouble x, gdouble y, gpointer data)
{
   GtkPopover *popover = data;
   GdkRectangle rect = { (int)x, (int)y, 1, 1 };

   (void) gesture;
   (void) n_press;

   gtk_popover_set_pointing_to(popover, &rect);
   gtk_popover_popup(popover);
}

/*******************************************/

/*
 * display the host list
 */
void gtkui_host_list(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *scrolled, *vbox, *hbox, *button, *popover;
   GtkSortListModel *sortmodel;
   GtkGesture *gesture;
   GSimpleActionGroup *actions;
   GMenu *menu;

   static GActionEntry host_actions[] = {
      {"target1", on_add_target1, NULL, NULL, NULL, {}},
      {"target2", on_add_target2, NULL, NULL, NULL, {}},
      {"delete",  on_delete_host, NULL, NULL, NULL, {}}
   };

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_host_list");

   if (hosts_window) {
      if (GTK_IS_WINDOW(hosts_window))
         gtk_window_present(GTK_WINDOW(hosts_window));
      else
         gtkui_page_present(hosts_window);
      return;
   }

   hosts_window = gtkui_page_new("Host List", &gtkui_hosts_destroy,
         &gtkui_hosts_detach);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_vexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(hosts_window), vbox);

   /* populate the store before the view is wired to it */
   gtkui_refresh_host_list(NULL);

   /*
    * The model chain is store -> sorter -> selection. The sort model is
    * handed the column view's own sorter, which is what makes clicking a
    * column header sort the rows.
    */
   hosts_view = gtk_column_view_new(NULL);
   gtk_column_view_set_show_row_separators(GTK_COLUMN_VIEW(hosts_view), TRUE);

   sortmodel = gtk_sort_list_model_new(
         G_LIST_MODEL(g_object_ref(hosts_store)),
         g_object_ref(gtk_column_view_get_sorter(GTK_COLUMN_VIEW(hosts_view))));

   hosts_selection = GTK_SELECTION_MODEL(
         gtk_multi_selection_new(G_LIST_MODEL(sortmodel)));
   gtk_column_view_set_model(GTK_COLUMN_VIEW(hosts_view), hosts_selection);

   add_text_column(GTK_COLUMN_VIEW(hosts_view), "IP Address", "ip", FALSE);
   add_text_column(GTK_COLUMN_VIEW(hosts_view), "MAC Address", "mac", FALSE);
   add_text_column(GTK_COLUMN_VIEW(hosts_view), "Description", "name", TRUE);

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), hosts_view);
   gtk_widget_set_vexpand(scrolled, TRUE);
   gtk_box_append(GTK_BOX(vbox), scrolled);

   /* buttons */
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
   gtk_widget_set_margin_top(hbox, 6);
   gtk_widget_set_margin_bottom(hbox, 6);
   gtk_widget_set_margin_start(hbox, 6);
   gtk_widget_set_margin_end(hbox, 6);
   gtk_box_append(GTK_BOX(vbox), hbox);

   button = gtk_button_new_with_mnemonic("_Delete Host");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked),
         GINT_TO_POINTER(HOST_DELETE));
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("Add to Target _1");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked),
         GINT_TO_POINTER(HOST_TARGET1));
   gtk_box_append(GTK_BOX(hbox), button);

   button = gtk_button_new_with_mnemonic("Add to Target _2");
   gtk_widget_set_hexpand(button, TRUE);
   g_signal_connect(button, "clicked", G_CALLBACK(on_button_clicked),
         GINT_TO_POINTER(HOST_TARGET2));
   gtk_box_append(GTK_BOX(hbox), button);

   /* context menu */
   actions = g_simple_action_group_new();
   g_action_map_add_action_entries(G_ACTION_MAP(actions), host_actions,
         G_N_ELEMENTS(host_actions), NULL);
   gtk_widget_insert_action_group(hosts_view, "host", G_ACTION_GROUP(actions));

   menu = g_menu_new();
   g_menu_append(menu, "Add to Target 1", "host.target1");
   g_menu_append(menu, "Add to Target 2", "host.target2");
   g_menu_append(menu, "Delete host", "host.delete");

   popover = gtk_popover_menu_new_from_model(G_MENU_MODEL(menu));
   gtk_widget_set_parent(popover, hosts_view);
   gtk_popover_set_has_arrow(GTK_POPOVER(popover), FALSE);
   gtk_widget_set_halign(popover, GTK_ALIGN_START);

   gesture = gtk_gesture_click_new();
   gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(gesture), GDK_BUTTON_SECONDARY);
   g_signal_connect(gesture, "pressed", G_CALLBACK(on_right_click), popover);
   gtk_widget_add_controller(hosts_view, GTK_EVENT_CONTROLLER(gesture));

   g_object_unref(actions);
   g_object_unref(menu);

   gtkui_page_present(hosts_window);
}

static void gtkui_hosts_detach(GtkWidget *child)
{
   hosts_window = gtk_window_new();
   gtk_window_set_title(GTK_WINDOW(hosts_window), "Hosts list");
   gtk_window_set_default_size(GTK_WINDOW(hosts_window), 400, 300);
   g_signal_connect(hosts_window, "close-request",
         G_CALLBACK(gtkui_hosts_destroy), NULL);

   gtk_window_set_child(GTK_WINDOW(hosts_window), child);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(hosts_window, gtkui_hosts_attach);

   gtk_window_present(GTK_WINDOW(hosts_window));
}

static void gtkui_hosts_attach(void)
{
   /* destroy the current window */
   gtkui_hosts_destroy();

   /* recreate the tab */
   gtkui_host_list(NULL, NULL, NULL);
}

static void gtkui_hosts_destroy(void)
{
   if (hosts_window == NULL)
      return;

   if (GTK_IS_WINDOW(hosts_window))
      gtk_window_destroy(GTK_WINDOW(hosts_window));
   else
      gtkui_page_close(hosts_window, NULL);

   hosts_window = NULL;
   hosts_view = NULL;
   hosts_selection = NULL;
}

/*
 * populate the list
 */
gboolean gtkui_refresh_host_list(gpointer data)
{
   struct hosts_list *hl;
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];
   char name[MAX_HOSTNAME_LEN];

   (void) data;

   DEBUG_MSG("gtk_refresh_host_list");

   if (hosts_store == NULL)
      hosts_store = g_list_store_new(EC_TYPE_HOST_ITEM);
   else
      g_list_store_remove_all(hosts_store);

   /* walk the hosts list */
   LIST_FOREACH(hl, &EC_GBL_HOSTLIST, next) {
      EcHostItem *item;
      const char *description = NULL;
      gboolean resolving = FALSE;

      if (hl->hostname) {
         description = hl->hostname;
      } else if (host_iptoa(&hl->ip, name) == -E_NOMATCH) {
         description = "resolving...";
         resolving = TRUE;
      } else {
         description = name;
      }

      item = ec_host_item_new(hl, ip_addr_ntoa(&hl->ip, tmp),
            mac_addr_ntoa(hl->mac, tmp2), description);

      g_list_store_append(hosts_store, item);

      if (resolving) {
         struct resolv_object *ro;

         SAFE_CALLOC(ro, 1, sizeof(struct resolv_object));
         /* the timer holds a reference, so the row cannot be freed under it */
         ro->item = g_object_ref(G_OBJECT(item));
         ro->property = "name";
         ro->ip = &hl->ip;
         g_timeout_add(1000, gtkui_iptoa_deferred, ro);
      }

      g_object_unref(item);
   }

   /* return FALSE so that g_idle_add() only calls it once */
   return FALSE;
}

/* EOF */

// vim:ts=3:expandtab
