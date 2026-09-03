/*
    ettercap -- GTK4 GUI -- plugin management

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
#include <ec_file.h>
#include <ec_plugins.h>

/* proto */
static void gtkui_load_plugin(char *full);
static void gtkui_add_plugin(char active, struct plugin_ops *ops);
static void gtkui_plug_destroy(void);
static void gtkui_plugins_detach(GtkWidget *child);
static void gtkui_plugins_attach(void);
static int  gtkui_select_plugin(char *plugin);
static void gtkui_create_plug_array(void);

/* globals */
static GtkWidget  *plugins_window = NULL;
static GtkWidget  *plugins_view = NULL;
static GListStore *ls_plugins = NULL;      /* of EcPluginItem */
static GtkSingleSelection *plugins_selection = NULL;

/*******************************************/
/* EcPluginItem                                                            */
/*******************************************/

#define EC_TYPE_PLUGIN_ITEM (ec_plugin_item_get_type())
G_DECLARE_FINAL_TYPE(EcPluginItem, ec_plugin_item, EC, PLUGIN_ITEM, GObject)

struct _EcPluginItem {
   GObject parent_instance;
   char *active;    /* "*" or " " */
   char *name;
   char *version;
   char *info;
};

G_DEFINE_FINAL_TYPE(EcPluginItem, ec_plugin_item, G_TYPE_OBJECT)

static void ec_plugin_item_finalize(GObject *object)
{
   EcPluginItem *self = EC_PLUGIN_ITEM(object);

   g_free(self->active);
   g_free(self->name);
   g_free(self->version);
   g_free(self->info);

   G_OBJECT_CLASS(ec_plugin_item_parent_class)->finalize(object);
}

static void ec_plugin_item_class_init(EcPluginItemClass *klass)
{
   G_OBJECT_CLASS(klass)->finalize = ec_plugin_item_finalize;
}

static void ec_plugin_item_init(EcPluginItem *self)
{
   (void) self;
}

static EcPluginItem *ec_plugin_item_new(const char *active, const char *name,
      const char *version, const char *info)
{
   EcPluginItem *self = g_object_new(EC_TYPE_PLUGIN_ITEM, NULL);

   self->active = g_strdup(active);
   self->name = g_strdup(name);
   self->version = g_strdup(version);
   self->info = g_strdup(info);

   return self;
}

/*******************************************/
/* column view                                                             */
/*******************************************/

typedef const char *(*plugin_getter)(EcPluginItem *item);

static const char *plug_get_active(EcPluginItem *i)  { return i->active; }
static const char *plug_get_name(EcPluginItem *i)    { return i->name; }
static const char *plug_get_version(EcPluginItem *i) { return i->version; }
static const char *plug_get_info(EcPluginItem *i)    { return i->info; }

static void on_plug_setup(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_label_new(NULL);

   (void) factory;
   (void) data;

   gtk_label_set_xalign(GTK_LABEL(label), 0.0);
   gtk_list_item_set_child(item, label);
}

static void on_plug_bind(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   plugin_getter getter = data;
   GtkWidget *label = gtk_list_item_get_child(item);
   EcPluginItem *obj = gtk_list_item_get_item(item);

   (void) factory;

   if (obj != NULL && label != NULL)
      gtk_label_set_text(GTK_LABEL(label), getter(obj));
}

static void add_plug_column(GtkColumnView *view, const char *title,
      plugin_getter getter, gboolean expand)
{
   GtkListItemFactory *factory;
   GtkColumnViewColumn *column;

   factory = gtk_signal_list_item_factory_new();
   g_signal_connect(factory, "setup", G_CALLBACK(on_plug_setup), NULL);
   g_signal_connect(factory, "bind", G_CALLBACK(on_plug_bind), getter);

   column = gtk_column_view_column_new(title, factory);
   gtk_column_view_column_set_resizable(column, TRUE);
   gtk_column_view_column_set_expand(column, expand);
   gtk_column_view_append_column(view, column);
   g_object_unref(column);
}

/*******************************************/

/*
 * The current selection's plugin name, or NULL.
 */
static char *selected_plugin(void)
{
   EcPluginItem *item;

   if (plugins_selection == NULL)
      return NULL;

   item = gtk_single_selection_get_selected_item(plugins_selection);
   return item != NULL ? item->name : NULL;
}

/*
 * double-click / Enter toggles the plugin
 */
static void on_row_activated(GtkColumnView *view, guint position,
      gpointer data)
{
   char *plugin;

   (void) view;
   (void) position;
   (void) data;

   plugin = selected_plugin();
   if (plugin != NULL)
      gtkui_select_plugin(plugin);
}

static void on_toggle_plugin(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   char *plugin;

   (void) action;
   (void) value;
   (void) data;

   plugin = selected_plugin();
   if (plugin != NULL)
      gtkui_select_plugin(plugin);
}

/*
 * The context menu shows a single Activate/Deactivate entry whose label
 * tracks the selected plugin's state. GtkPopoverMenu is rebuilt on each
 * right-click so the label is always right, replacing the GtkMenu the GTK3
 * code assembled in its button-press handler.
 */
static void on_right_click(GtkGestureClick *gesture, gint n_press,
      gdouble x, gdouble y, gpointer data)
{
   GtkPopover *popover = data;
   char *plugin;
   GMenu *menu;
   GdkRectangle rect = { (int)x, (int)y, 1, 1 };

   (void) gesture;
   (void) n_press;

   plugin = selected_plugin();
   if (plugin == NULL)
      return;

   menu = g_menu_new();
   g_menu_append(menu,
         plugin_is_activated(plugin) ? "Deactivate" : "Activate",
         "plugin.toggle");
   gtk_popover_menu_set_menu_model(GTK_POPOVER_MENU(popover),
         G_MENU_MODEL(menu));
   g_object_unref(menu);

   gtk_popover_set_pointing_to(popover, &rect);
   gtk_popover_popup(popover);
}

/*******************************************/

/*
 * display the file open dialog
 */
static char plugin_filename[PATH_MAX];

static void on_plugin_chosen(gboolean confirmed, gpointer data)
{
   (void) data;

   if (!confirmed)
      return;

   gtkui_load_plugin(plugin_filename);

   /* update the list */
   gtkui_create_plug_array();
}

void gtkui_plugin_load(GSimpleAction *action, GVariant *value, gpointer data)
{
   char *path;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_plugin_load");

#ifdef OS_WINDOWS
   path = get_full_path("/lib/", "");
#else
   path = strdup(INSTALL_LIBDIR "/" PROGRAM "/");
#endif

   if (path != NULL) {
      strncpy(plugin_filename, path, sizeof(plugin_filename) - 1);
      plugin_filename[sizeof(plugin_filename) - 1] = '\0';
      SAFE_FREE(path);
   } else {
      plugin_filename[0] = '\0';
   }

   gtkui_filename_browse("Select a plugin...", FALSE, plugin_filename,
         sizeof(plugin_filename), on_plugin_chosen, NULL, NULL);
}

static void gtkui_load_plugin(char *full)
{
   char *file;
   int ret;

#ifdef OS_WINDOWS
   file = strrchr(full, '\\');
#else
   file = strrchr(full, '/');
#endif
   if (file == NULL)
      return;

   /* split path and file: replace the last separator, advance to the name */
   *file++ = 0;

   DEBUG_MSG("gtk_load_plugin %s/%s", full, file);

   /* load the plugin */
   ret = plugin_load_single(full, file);

   switch (ret) {
      case E_SUCCESS:
         gtkui_message("Plugin loaded successfully");
         break;
      case -E_DUPLICATE:
         ui_error("plugin %s already loaded...", file);
         break;
      case -E_VERSION:
         ui_error("plugin %s was compiled for a different ettercap version...",
               file);
         break;
      case -E_INVALID:
      default:
         ui_error("Cannot load the plugin...\nthe file may be an invalid "
               "plugin\nor you don't have the permission to open it");
         break;
   }
}

/*
 * plugin management
 */
void gtkui_plugin_mgmt(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *scrolled, *vbox, *popover;
   GtkGesture *gesture;
   GSimpleActionGroup *actions;

   static GActionEntry plugin_actions[] = {
      {"toggle", on_toggle_plugin, NULL, NULL, NULL, {}}
   };

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_plugin_mgmt");

   if (plugins_window) {
      if (GTK_IS_WINDOW(plugins_window))
         gtk_window_present(GTK_WINDOW(plugins_window));
      else
         gtkui_page_present(plugins_window);
      return;
   }

   plugins_window = gtkui_page_new("Plugins", &gtkui_plug_destroy,
         &gtkui_plugins_detach);

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_widget_set_vexpand(vbox, TRUE);
   gtk_box_append(GTK_BOX(plugins_window), vbox);

   gtkui_create_plug_array();

   plugins_view = gtk_column_view_new(NULL);
   plugins_selection = gtk_single_selection_new(
         G_LIST_MODEL(g_object_ref(ls_plugins)));
   gtk_column_view_set_model(GTK_COLUMN_VIEW(plugins_view),
         GTK_SELECTION_MODEL(plugins_selection));

   add_plug_column(GTK_COLUMN_VIEW(plugins_view), " ", plug_get_active, FALSE);
   add_plug_column(GTK_COLUMN_VIEW(plugins_view), "Name", plug_get_name, FALSE);
   add_plug_column(GTK_COLUMN_VIEW(plugins_view), "Version",
         plug_get_version, FALSE);
   add_plug_column(GTK_COLUMN_VIEW(plugins_view), "Info", plug_get_info, TRUE);

   g_signal_connect(plugins_view, "activate",
         G_CALLBACK(on_row_activated), NULL);

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), plugins_view);
   gtk_widget_set_vexpand(scrolled, TRUE);
   gtk_box_append(GTK_BOX(vbox), scrolled);

   /* context menu */
   actions = g_simple_action_group_new();
   g_action_map_add_action_entries(G_ACTION_MAP(actions), plugin_actions,
         G_N_ELEMENTS(plugin_actions), NULL);
   gtk_widget_insert_action_group(plugins_view, "plugin",
         G_ACTION_GROUP(actions));

   popover = gtk_popover_menu_new_from_model(NULL);
   gtk_widget_set_parent(popover, plugins_view);
   gtk_popover_set_has_arrow(GTK_POPOVER(popover), FALSE);
   gtk_widget_set_halign(popover, GTK_ALIGN_START);

   gesture = gtk_gesture_click_new();
   gtk_gesture_single_set_button(GTK_GESTURE_SINGLE(gesture),
         GDK_BUTTON_SECONDARY);
   g_signal_connect(gesture, "pressed", G_CALLBACK(on_right_click), popover);
   gtk_widget_add_controller(plugins_view, GTK_EVENT_CONTROLLER(gesture));

   g_object_unref(actions);

   gtkui_page_present(plugins_window);
}

static void gtkui_plugins_detach(GtkWidget *child)
{
   plugins_window = gtk_window_new();
   gtk_window_set_title(GTK_WINDOW(plugins_window), "Select a plugin...");
   gtk_window_set_default_size(GTK_WINDOW(plugins_window), 400, 300);
   g_signal_connect(plugins_window, "close-request",
         G_CALLBACK(gtkui_plug_destroy), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(plugins_window, gtkui_plugins_attach);

   gtk_window_set_child(GTK_WINDOW(plugins_window), child);

   gtk_window_present(GTK_WINDOW(plugins_window));
}

static void gtkui_plugins_attach(void)
{
   gtkui_plug_destroy();
   gtkui_plugin_mgmt(NULL, NULL, NULL);
}

static void gtkui_plug_destroy(void)
{
   if (plugins_window == NULL)
      return;

   if (GTK_IS_WINDOW(plugins_window))
      gtk_window_destroy(GTK_WINDOW(plugins_window));
   else
      gtkui_page_close(plugins_window, NULL);

   plugins_window = NULL;
   plugins_view = NULL;
   plugins_selection = NULL;
}

/*
 * (re)build the plugin list model
 */
static void gtkui_create_plug_array(void)
{
   int res;

   DEBUG_MSG("gtk_create_plug_array");

   if (ls_plugins == NULL)
      ls_plugins = g_list_store_new(EC_TYPE_PLUGIN_ITEM);
   else
      g_list_store_remove_all(ls_plugins);

   /* go through the list of plugins */
   res = plugin_list_walk(PLP_MIN, PLP_MAX, &gtkui_add_plugin);
   if (res == -E_NOTFOUND) {
      EcPluginItem *item = ec_plugin_item_new(" ", "No Plugins Loaded",
            "", "");
      g_list_store_append(ls_plugins, item);
      g_object_unref(item);
   }
}

/*
 * callback for displaying the plugin list
 */
static void gtkui_add_plugin(char active, struct plugin_ops *ops)
{
   EcPluginItem *item;
   char active_str[2];

   active_str[0] = active ? '*' : ' ';
   active_str[1] = '\0';

   item = ec_plugin_item_new(active_str, ops->name, ops->version, ops->info);
   g_list_store_append(ls_plugins, item);
   g_object_unref(item);
}

/*
 * toggle state of a plugin
 */
static int gtkui_select_plugin(char *plugin)
{
   int ret;

   if (!plugin)
      return -E_NOTHANDLED;

   /* print the message */
   if (plugin_is_activated(plugin) == 0)
      INSTANT_USER_MSG("Activating %s plugin...\n", plugin);
   else
      INSTANT_USER_MSG("Deactivating %s plugin...\n", plugin);

   /*
    * pay attention on this !
    * if the plugin init does not return,
    * we are blocked here. So it is encouraged
    * to write plugins which spawn a thread
    * and immediately return
    */
   if (plugin_is_activated(plugin) == 1)
      ret = plugin_fini(plugin);
   else
      ret = plugin_init(plugin);

   /* refresh the list to mark plugin active */
   gtkui_create_plug_array();

   return ret;
}

/*
 * check if plugins have been supplied on the CLI
 * and try to start all provided plugins
 */
gboolean gtkui_plugins_autostart(gpointer data)
{
   struct plugin_list *plugin, *tmp;

   (void) data;

   DEBUG_MSG("gtkui_plugins_autostart()");

   /* if plugins have been defined on the CLI */
   if (!LIST_EMPTY(&EC_GBL_OPTIONS->plugins)) {
      LIST_FOREACH_SAFE(plugin, &EC_GBL_OPTIONS->plugins, next, tmp) {
         /* first check if the plugin exists */
         if (search_plugin(plugin->name) != E_SUCCESS) {
            plugin->exists = false;
            USER_MSG("Sorry, plugin '%s' can not be found - skipping!\n\n",
                  plugin->name);
         } else {
            /* now we can try to start the plugin */
            plugin->exists = true;
            if (gtkui_select_plugin(plugin->name) != PLUGIN_RUNNING) {
               USER_MSG("Plugin '%s' can not be started - skipping!\n\n",
                     plugin->name);
            }
         }
      }
   }

   return FALSE;
}

gboolean gtkui_refresh_plugin_list(gpointer data)
{
   (void) data;

   DEBUG_MSG("gtk_refresh_plugin_list");

   /* refresh the list to mark plugin active */
   gtkui_create_plug_array();

   /* return FALSE so g_idle_add() only calls it once */
   return FALSE;
}

/* EOF */

// vim:ts=3:expandtab
