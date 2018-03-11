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
#include <ec_file.h>
#include <ec_plugins.h>

#define MAX_DESC_LEN 75

/* proto */

static void gtkui_load_plugin(const char *full);
static void gtkui_add_plugin(char active, struct plugin_ops *ops);
static void gtkui_plug_destroy(void);
static void gtkui_plugins_detach(GtkWidget *child);
static void gtkui_plugins_attach(void);
static void gtkui_select_plugin(void);
static void gtkui_create_plug_array(void);
gboolean gtkui_plugin_context(GtkWidget *widget, GdkEventButton *event, gpointer data);

/* globals */

static GtkWidget   *plugins_window = NULL;
static GtkWidget         *treeview = NULL;
static GtkListStore    *ls_plugins = NULL;
static GtkTreeSelection *selection = NULL;

/*******************************************/

/*
 * display the file open dialog
 */
void gtkui_plugin_load(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *chooser, *content;
   gchar *filename;
   int response = 0;
#ifdef OS_WINDOWS
   char *path = get_full_path("/lib/", "");
#else
   char *path = INSTALL_LIBDIR "/" PROGRAM "/";
#endif
   
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_plugin_load");
   
   dialog = gtk_dialog_new_with_buttons("Select a plugin...",
         GTK_WINDOW(window), 
         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_USE_HEADER_BAR,
         "_Cancel", GTK_RESPONSE_CANCEL,
         "_OK",     GTK_RESPONSE_OK,
         NULL);
   gtk_container_set_border_width(GTK_CONTAINER(dialog), 10);

   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   chooser = gtk_file_chooser_widget_new(GTK_FILE_CHOOSER_ACTION_OPEN);
   gtk_container_add(GTK_CONTAINER(content), chooser);
   gtk_widget_show(chooser);

   gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(chooser), path);

#ifdef OS_WINDOWS
   SAFE_FREE(path);
#endif
   
   response = gtk_dialog_run (GTK_DIALOG (dialog));
   
   if (response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
      
      gtkui_load_plugin(filename);

      /* update the list */
      gtkui_create_plug_array();
      g_free(filename);
   }
   gtk_widget_destroy (dialog);
}

static void gtkui_load_plugin(const char *full)
{
   char *file;
   int ret;

#ifdef OS_WINDOWS
   file = strrchr(full, '\\');
#else
   file = strrchr(full, '/');
#endif
   /* remove the last /
      split path and file
      increment file pointer to point to filename */
   *file++ = 0;

   DEBUG_MSG("gtk_load_plugin %s/%s", full, file);

   /* load the plugin */
   ret = plugin_load_single(full, file);


   /* check the return code */
   switch (ret) {
      case E_SUCCESS:
         gtkui_message("Plugin loaded successfully");
         break;
      case -E_DUPLICATE:
         ui_error("plugin %s already loaded...", file);
         break;
      case -E_VERSION:
         ui_error("plugin %s was compiled for a different ettercap version...", file);
         break;
      case -E_INVALID:
      default:
         ui_error("Cannot load the plugin...\nthe file may be an invalid plugin\nor you don't have the permission to open it");
         break;
   }
}

/*
 * plugin management
 */
void gtkui_plugin_mgmt(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *scrolled, *vbox;
   GtkCellRenderer   *renderer;
   GtkTreeViewColumn *column;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_plugin_mgmt");
   
   /* if the object already exist, set the focus to it */
   if (plugins_window) {
      if(GTK_IS_WINDOW (plugins_window))
         gtk_window_present(GTK_WINDOW (plugins_window));
      else
         gtkui_page_present(plugins_window);
      return;
   }

   plugins_window = gtkui_page_new("Plugins", &gtkui_plug_destroy, &gtkui_plugins_detach);
   
   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_container_add(GTK_CONTAINER (plugins_window), vbox);
   gtk_widget_show(vbox);
   
  /* list */
   scrolled = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scrolled), GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);
   gtk_widget_show(scrolled);
   
   treeview = gtk_tree_view_new();
   gtk_container_add(GTK_CONTAINER (scrolled), treeview);
   gtk_widget_show(treeview);

   selection = gtk_tree_view_get_selection (GTK_TREE_VIEW (treeview));
   gtk_tree_selection_set_mode (selection, GTK_SELECTION_SINGLE);
   g_signal_connect (G_OBJECT (treeview), "row_activated", G_CALLBACK (gtkui_select_plugin), NULL);
   
   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes (" ", renderer, "text", 0, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 0);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Name", renderer, "text", 1, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 1);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Version", renderer, "text", 2, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 2);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Info", renderer, "text", 3, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 3);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   /* create the array for the list widget */
   /* or refreshes it if it exists */
   gtkui_create_plug_array();
   gtk_tree_view_set_model(GTK_TREE_VIEW (treeview), GTK_TREE_MODEL (ls_plugins));   

   g_signal_connect(G_OBJECT(treeview), "button-press-event", G_CALLBACK(gtkui_plugin_context), NULL);

   gtk_widget_show(plugins_window);
}

static void gtkui_plugins_detach(GtkWidget *child)
{
   plugins_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (plugins_window), "Select a plugin...");
   gtk_window_set_default_size(GTK_WINDOW (plugins_window), 400, 300);
   g_signal_connect (G_OBJECT (plugins_window), "delete_event", G_CALLBACK (gtkui_plug_destroy), NULL);

   /* make <ctrl>d shortcut turn the window back into a tab */
   gtkui_page_attach_shortcut(plugins_window, gtkui_plugins_attach);

   gtk_container_add(GTK_CONTAINER (plugins_window), child);

   gtk_window_present(GTK_WINDOW (plugins_window));
}

static void gtkui_plugins_attach(void)
{
   gtkui_plug_destroy();
   gtkui_plugin_mgmt(NULL, NULL, NULL);
}

static void gtkui_plug_destroy(void)
{
   gtk_widget_destroy(plugins_window);
   plugins_window = NULL;
}


/*
 * create the array for the widget.
 * erase any previously alloc'd array 
 */
static void gtkui_create_plug_array(void)
{
   GtkTreeIter iter;
   int res;
   static int blocked = 0;
   
   DEBUG_MSG("gtk_create_plug_array");
   
   if(ls_plugins)
      gtk_list_store_clear(GTK_LIST_STORE (ls_plugins));
   else
      ls_plugins = gtk_list_store_new (4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
   
   /* go thru the list of plugins */
   res = plugin_list_walk(PLP_MIN, PLP_MAX, &gtkui_add_plugin);
   if (res == -E_NOTFOUND) { 
      blocked = g_signal_handlers_block_by_func (G_OBJECT (treeview), G_CALLBACK (gtkui_select_plugin), NULL);
      gtk_list_store_append (ls_plugins, &iter);
      gtk_list_store_set (ls_plugins, &iter, 0, " ", 1, "No Plugins Loaded", -1);
   } else if(blocked > 0) {
      g_signal_handlers_unblock_by_func (G_OBJECT (treeview), G_CALLBACK (gtkui_select_plugin), NULL);
      blocked = 0;
   }
}

/*
 * callback function for displaying the plugin list 
 */
static void gtkui_add_plugin(char active, struct plugin_ops *ops)
{
   GtkTreeIter iter;
   char active_str[2];

   active_str[0] = (active)?'*':' ';
   active_str[1] = 0;

   gtk_list_store_append (ls_plugins, &iter);
   gtk_list_store_set (ls_plugins, &iter,
                       0, active_str,
                       1, ops->name,
                       2, ops->version,
                       3, ops->info, -1);
}

/*
 * callback function for a plugin 
 */
static void gtkui_select_plugin(void)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   char *plugin = NULL;

   model = GTK_TREE_MODEL (ls_plugins);

   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 1, &plugin, -1);
   } else
      return; /* nothing is selected */

   if(!plugin)
      return; /* bad pointer from gtk_tree_model_get, shouldn't happen */

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
      plugin_fini(plugin);   
   else
      plugin_init(plugin);
        
   /* refresh the list to mark plugin active */
   gtkui_create_plug_array();
}

gboolean gtkui_refresh_plugin_list(gpointer data)
{

   /* avoid warning */
   (void)data;

   DEBUG_MSG("gtk_refresh_plugin_list");
   /* refresh the list to mark plugin active */
   gtkui_create_plug_array();

   /* return FALSE so g_idle_add() only calls it once */
   return FALSE;
}

gboolean gtkui_plugin_context(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   GtkWidget *menu, *item;
   char *plugin = NULL;

   (void) widget;
   (void) data;

   model = GTK_TREE_MODEL(ls_plugins);

   menu = gtk_menu_new();
   item = gtk_menu_item_new();
   gtk_menu_shell_append(GTK_MENU_SHELL(menu), item);
   g_signal_connect(G_OBJECT(item), "activate", G_CALLBACK(gtkui_select_plugin), NULL);
   gtk_widget_show(item);


   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION(selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 1, &plugin, -1);
   } else
      return FALSE; /* nothing is selected */

   if(!plugin)
      return FALSE; /* bad pointer from gtk_tree_model_get, shouldn't happen */

   /* print the message */
   if (plugin_is_activated(plugin) == 0)
      gtk_menu_item_set_label(GTK_MENU_ITEM(item), "Activate");
   else
      gtk_menu_item_set_label(GTK_MENU_ITEM(item), "Deactivate");
         
   if (event->button == 3) {
#if GTK_CHECK_VERSION(3,22,0)
      gtk_menu_popup_at_pointer(GTK_MENU(menu), (GdkEvent*)event);
#else
      gtk_menu_popup(GTK_MENU(data), NULL, NULL, NULL, NULL, 3, event->time);
#endif
       /* 
        * button press event handle must return TRUE to keep the selection
        * active when pressing the mouse button 
        */
       return TRUE;
    }

    return FALSE;
}

/* EOF */

// vim:ts=3:expandtab

