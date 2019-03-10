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
#include <ec_redirect.h>

/* proto */

static void gtkui_sslredir_close(void);
static void gtkui_sslredir_detach(GtkWidget *child);
static void gtkui_sslredir_attach(void);
static void gtkui_sslredir_add(GtkWidget *widget, gpointer data);
static void gtkui_sslredir_del(GtkWidget *widget, gpointer data);
static void gtkui_sslredir_del_all(GtkWidget *widget, gpointer data);
static void gtkui_sslredir_add_list(struct redir_entry *re);
static void gtkui_sslredir_add_service(struct serv_entry *se);
static void gtkui_sslredir_create_lists(void);
static void gtkui_sslredir_af_changed(GtkWidget *widget, gpointer data);
static gboolean gtkui_sslredir_key_pressed(GtkWidget *widget,
      GdkEventKey *event, gpointer data);

/* globals */

static GtkWidget *sslredir_window = NULL;
static GtkWidget *treeview = NULL;
static GtkListStore *redirrules = NULL;
static GtkListStore *proto_list = NULL;
static GtkListStore *af_list = NULL;
static GtkTreeSelection *selection = NULL;



/*******************************************/


/*
 * tab to configure traffic redirection for SSL interception
 *    - no redirect of any interceptable traffic at startup
 *    - selective redirect avoids SSL errors for destinations
 *      not being subject of interception
 *
 */
void gtkui_sslredir_show(void)
{
   GtkWidget *scrolled, *vbox, *hbox, *button, *context_menu, *items;
   GtkTreeModel *model;
   GtkCellRenderer *renderer;
   GtkTreeViewColumn *column;

   DEBUG_MSG("gtk_sslredir_show()");

   /* if the object already exist, set the focus to it */
   if (sslredir_window) {
      if(GTK_IS_WINDOW (sslredir_window))
         gtk_window_present(GTK_WINDOW (sslredir_window));
      else
         gtkui_page_present(sslredir_window);
      return;
   }

   sslredir_window = gtkui_page_new("SSL Intercept", 
         &gtkui_sslredir_close, 
         &gtkui_sslredir_detach);

   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
   gtk_container_add(GTK_CONTAINER(sslredir_window), vbox);
   
   /* rules list */
   scrolled = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), 
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled),
         GTK_SHADOW_IN);
   gtk_box_pack_start(GTK_BOX(vbox), scrolled, TRUE, TRUE, 0);

   treeview = gtk_tree_view_new();
   gtk_container_add(GTK_CONTAINER(scrolled), treeview);


   selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(treeview));
   gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);

   renderer = gtk_cell_renderer_text_new();
   column = gtk_tree_view_column_new_with_attributes("IP Version", renderer,
         "text", 1, NULL);
   gtk_tree_view_column_set_sort_column_id(column, 0);
   gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new();
   column = gtk_tree_view_column_new_with_attributes("Source", renderer,
         "text", 2, NULL);
   gtk_tree_view_column_set_sort_column_id(column, 1);
   gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new();
   column = gtk_tree_view_column_new_with_attributes("Destination", renderer,
         "text", 3, NULL);
   gtk_tree_view_column_set_sort_column_id(column, 2);
   gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new();
   column = gtk_tree_view_column_new_with_attributes("Service", renderer,
         "text", 7, NULL);
   gtk_tree_view_column_set_sort_column_id(column, 3);
   gtk_tree_view_append_column(GTK_TREE_VIEW(treeview), column);

   gtkui_sslredir_create_lists();

   model = gtk_tree_model_sort_new_with_model(GTK_TREE_MODEL(redirrules));
   gtk_tree_view_set_model(GTK_TREE_VIEW(treeview), model);

   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 5, TRUE);
   gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);


   button = gtk_button_new_with_mnemonic("_Insert new redirect");
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   if (proto_list)
      g_signal_connect(G_OBJECT(button), "clicked", 
            G_CALLBACK(gtkui_sslredir_add), model);
   else
      gtk_widget_set_sensitive(button, FALSE);


   button = gtk_button_new_with_mnemonic("_Remove redirect");
   gtk_box_pack_start(GTK_BOX(hbox), button, TRUE, TRUE, 0);
   if (proto_list)
      g_signal_connect(G_OBJECT(button), "clicked",
            G_CALLBACK(gtkui_sslredir_del), model);
   else
      gtk_widget_set_sensitive(button, FALSE);

   /* context menu */
   context_menu = gtk_menu_new();
   items = gtk_menu_item_new_with_label("Remove redirect");
   gtk_menu_shell_append(GTK_MENU_SHELL(context_menu), items);
   g_signal_connect(G_OBJECT(items), "activate",
         G_CALLBACK(gtkui_sslredir_del), model);
   gtk_widget_show(items);

   items = gtk_menu_item_new_with_label("Remove all redirects");
   gtk_menu_shell_append(GTK_MENU_SHELL(context_menu), items);
   g_signal_connect(G_OBJECT(items), "activate",
         G_CALLBACK(gtkui_sslredir_del_all), model);
   gtk_widget_show(items);

   g_signal_connect(G_OBJECT(treeview), "button-press-event",
         G_CALLBACK(gtkui_context_menu), context_menu);

   /* remove entries if delete key is pressed */
   g_signal_connect(G_OBJECT(treeview), "key-press-event",
         G_CALLBACK(gtkui_sslredir_key_pressed), model);

   gtk_widget_show_all(sslredir_window);
 
}

/* Add a new line to the Rules list */
static void gtkui_sslredir_add(GtkWidget *widget, gpointer data)
{

   GtkWidget *dialog, *content, *table, *source, *destination, *label, *frame;
   GtkWidget *proto, *af;
   GtkTreeModel *model;
   GtkTreeIter iter;
   GtkCellRenderer *cell1, *cell2;
   GtkWidget *entry_widgets[2];
   int ret = 0;
   guint32 from_port, to_port;
   gchar *name;
   const gchar *from, *to;
   ec_redir_proto_t ip_ver;

   /* unused variabled */
   (void) widget;
   (void) data;


   DEBUG_MSG("gtkui_sslredir_add()");

   /* compile IP protocol family list if not already done */
   if (af_list == NULL) {
      af_list = gtk_list_store_new(2, 
            G_TYPE_STRING,  /* human friendly name */
            G_TYPE_UINT);   /* protocol number for redirect */ 

      gtk_list_store_append(af_list, &iter);
      gtk_list_store_set(af_list, &iter, 
            0, "IPv4", 1, EC_REDIR_PROTO_IPV4, -1);
#ifdef WITH_IPV6
      gtk_list_store_append(af_list, &iter);
      gtk_list_store_set(af_list, &iter,
            0, "IPv6", 1, EC_REDIR_PROTO_IPV6, -1);
#endif
   }

   dialog = gtk_dialog_new_with_buttons("Create new redirect rule",
         GTK_WINDOW(window),
         GTK_DIALOG_MODAL | 
         GTK_DIALOG_DESTROY_WITH_PARENT,
         "_Cancel", GTK_RESPONSE_CANCEL,
         "_Insert", GTK_RESPONSE_OK,
         NULL);

   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_set_border_width(GTK_CONTAINER(content), 20);

   frame = gtk_frame_new("Redirect specification");
   gtk_container_add(GTK_CONTAINER(content), frame);
   //gtk_widget_set_margin_bottom(frame, 10);

   table = gtk_table_new(4, 2, FALSE);
   gtk_table_set_row_spacings(GTK_TABLE(table), 5);
   gtk_table_set_col_spacings(GTK_TABLE(table), 5);
   gtk_container_set_border_width(GTK_CONTAINER(table), 8);
   gtk_container_add(GTK_CONTAINER(frame), table);

   label = gtk_label_new("IP Version:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 0, 1);

   af = gtk_combo_box_new();
   gtk_combo_box_set_model(GTK_COMBO_BOX(af), GTK_TREE_MODEL(af_list));
   gtk_combo_box_set_active(GTK_COMBO_BOX(af), 0);

   cell1 = gtk_cell_renderer_text_new();
   gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(af), cell1, TRUE);
   gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(af), cell1, 
         "text", 0, NULL);
   gtk_table_attach_defaults(GTK_TABLE(table), af, 1, 2, 0, 1);

   label = gtk_label_new("Source:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 1, 2);

   source = gtk_entry_new();
   gtk_entry_set_text(GTK_ENTRY(source), "0.0.0.0/0");
   gtk_widget_grab_focus(source);
   gtk_widget_activate(source);
   gtk_table_attach_defaults(GTK_TABLE(table), source, 1, 2, 1, 2);

   label = gtk_label_new("Destination:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 2, 3);

   destination = gtk_entry_new();
   gtk_entry_set_text(GTK_ENTRY(destination), "0.0.0.0/0");
   gtk_table_attach_defaults(GTK_TABLE(table), destination, 1, 2, 2, 3);

   label = gtk_label_new("Service:");
   gtk_misc_set_alignment(GTK_MISC(label), 0, 0);
   gtk_table_attach_defaults(GTK_TABLE(table), label, 0, 1, 3, 4);

   proto = gtk_combo_box_new();
   gtk_combo_box_set_model(GTK_COMBO_BOX(proto), GTK_TREE_MODEL(proto_list));
   gtk_combo_box_set_active(GTK_COMBO_BOX(proto), 0);
   
   cell2 = gtk_cell_renderer_text_new();
   gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(proto), cell2, TRUE);
   gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(proto), cell2, 
         "text", 1, NULL);
   gtk_table_attach_defaults(GTK_TABLE(table), proto, 1, 2, 3, 4);

   entry_widgets[0] = source;
   entry_widgets[1] = destination;
   g_signal_connect(G_OBJECT(af), "changed", 
         G_CALLBACK(gtkui_sslredir_af_changed), entry_widgets);

   gtk_widget_show_all(dialog);

   if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);

      /* extract information from widgets */
      model = gtk_combo_box_get_model(GTK_COMBO_BOX(af));
      gtk_combo_box_get_active_iter(GTK_COMBO_BOX(af), &iter);
      gtk_tree_model_get(model, &iter, 1, &ip_ver, -1); 

      model = gtk_combo_box_get_model(GTK_COMBO_BOX(proto));
      gtk_combo_box_get_active_iter(GTK_COMBO_BOX(proto), &iter);
      gtk_tree_model_get(model, &iter, 0, &name,
            2, &from_port, 3, &to_port, -1);

      from = gtk_entry_get_text(GTK_ENTRY(source));
      to = gtk_entry_get_text(GTK_ENTRY(destination));

      /* execute redirect action */
      ret = ec_redirect(EC_REDIR_ACTION_INSERT, name, ip_ver,
            from, to, from_port, to_port);


      /* inform user if redirect execution wasn't successful */
      if (ret != E_SUCCESS)
         gtkui_message("Insertion of redirect rule failed.");
      else { /* otherwise add rule to rules list */

         gtk_list_store_append(redirrules, &iter);
         gtk_list_store_set(redirrules, &iter,
               0, ip_ver,
               1, (ip_ver == EC_REDIR_PROTO_IPV4 ? "IPv4" : "IPv6"),
               2, from,
               3, to,
               4, from_port,
               5, to_port,
               6, ec_strlc(name),
               7, ec_struc(name),
               -1);
      }
      

   }

   gtk_widget_destroy(dialog);
   

}

/*
 * remove selected redirect rules
 */
void gtkui_sslredir_del(GtkWidget *widget, gpointer data)
{
   GList *list;
   GtkTreeIter iter, iter_unsorted;
   GtkTreeModel *model;
   int ret;
   gchar *name;
   const gchar *from, *to;
   guint32 from_port, to_port;
   ec_redir_proto_t ip_ver;

   /* variable not used */
   (void) widget;

   DEBUG_MSG("gtkui_sslredir_del()");

   model = gtk_tree_model_sort_get_model(GTK_TREE_MODEL_SORT(data));

   /* get selected entries */
   if (gtk_tree_selection_count_selected_rows(selection) > 0) {
      list = gtk_tree_selection_get_selected_rows(selection, &model);
      for (list = g_list_last(list); list; list = g_list_previous(list)) {
         /* extract parameters from GtkTreeView model */
         gtk_tree_model_get_iter(model, &iter, list->data);
         gtk_tree_model_get(model, &iter, 
               0, &ip_ver,
               2, &from,
               3, &to,
               4, &from_port,
               5, &to_port,
               6, &name,
               -1);

         /* execute redirect action */
         ret = ec_redirect(EC_REDIR_ACTION_REMOVE, name, ip_ver,
               from, to, from_port, to_port);

         /* inform user if redirect execution wasn't successful */
         if (ret != E_SUCCESS)
            gtkui_message("Removal of redirect rule failed.");
         else { /* otherwise remove from list */
            gtk_tree_model_sort_convert_iter_to_child_iter(
                  GTK_TREE_MODEL_SORT(data), &iter_unsorted, &iter);
            gtk_list_store_remove(GTK_LIST_STORE(redirrules), &iter_unsorted);
         }
      }

      /* free the list of selection */
      g_list_free_full(list, (GDestroyNotify)gtk_tree_path_free);
   }

}

/*
 * select all entries in TreeModel then then call gtkui_sslredir_del 
 */
void gtkui_sslredir_del_all(GtkWidget *widget, gpointer data)
{

   DEBUG_MSG("gtkui_sslredir_del_all():");

   gtk_tree_selection_select_all(selection);
   gtkui_sslredir_del(widget, data);

}

/* detach ssl redir tab */
static void gtkui_sslredir_detach(GtkWidget *child)
{
   sslredir_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW(sslredir_window), "SSL Intercept");
   gtk_window_set_default_size(GTK_WINDOW(sslredir_window), 500, 250);
   g_signal_connect(G_OBJECT(sslredir_window), "delete_event", 
         G_CALLBACK(gtkui_sslredir_close), NULL);

   gtkui_page_attach_shortcut(sslredir_window, gtkui_sslredir_attach);

   gtk_container_add(GTK_CONTAINER(sslredir_window), child);
   gtk_window_present(GTK_WINDOW(sslredir_window));

}

/* callback for reattaching the detached ssl redir tab */
static void gtkui_sslredir_attach(void)
{
   gtkui_sslredir_close();
   gtkui_sslredir_show();
}


/* close ssl redir tab */
static void gtkui_sslredir_close(void)
{
   DEBUG_MSG("gtk_sslredir_close");

   gtk_widget_destroy(sslredir_window);
   sslredir_window = NULL;
}

/*
 * create the list for the list of interceptable protocols
 */
static void gtkui_sslredir_create_lists(void)
{
   int res;

   DEBUG_MSG("gtk_sslredir_create_lists()");

   /* populate redirect rules */
   if (redirrules == NULL) {
      redirrules = gtk_list_store_new(8,
            G_TYPE_UINT,    /* IP address family */
            G_TYPE_STRING,  /* IP address family human readable */
            G_TYPE_STRING,  /* source definition */
            G_TYPE_STRING,  /* destination definition */
            G_TYPE_UINT,    /* protocol registered port */
            G_TYPE_UINT,    /* ettercap listener port */
            G_TYPE_STRING,  /* protocol name lower case */
            G_TYPE_STRING); /* protocol name upper case */
      /* walk through list of registered redirects */
      res = ec_walk_redirects(&gtkui_sslredir_add_list);

      if (res == -E_NOTFOUND) {
         DEBUG_MSG("gtk_sslredir_create_lists(): no redirects registered - "
               "apparently no redirect commands enabled in etter.conf");
         gtkui_message("Traffic redirect not enabled in etter.conf. ");
      }
   }


   /* populate registered services */
   if (proto_list == NULL) {
      proto_list = gtk_list_store_new(4,
            G_TYPE_STRING,  /* protocol name lower case */
            G_TYPE_STRING,  /* protocol name upper case */
            G_TYPE_UINT,    /* protocol registered port */
            G_TYPE_UINT);   /* ettercap listener port */

      res = ec_walk_redirect_services(&gtkui_sslredir_add_service);

      if (res == -E_NOTFOUND) {
         g_object_unref(proto_list);
         proto_list = NULL;
      }
   }



}

/*
 * callback function to compose the list of active services
 */
static void gtkui_sslredir_add_service(struct serv_entry *se)
{
   GtkTreeIter iter;

   DEBUG_MSG("gtkui_sslredir_add_service(%s)", se->name);

   /* update protocol list store */
   gtk_list_store_append(proto_list, &iter);
   gtk_list_store_set(proto_list, &iter, 
         0, ec_strlc(se->name),
         1, ec_struc(se->name),
         2, se->from_port,
         3, se->to_port,
         -1);

}
/*
 * callback function to compose the list of active redirects
 */
static void gtkui_sslredir_add_list(struct redir_entry *re)
{
   GtkTreeIter iter;

   DEBUG_MSG("gtkui_sslredir_add_list(%s)", re->name);

   /* add rule to rules list */
   gtk_list_store_append(redirrules, &iter);
   gtk_list_store_set(redirrules, &iter,
         0, re->proto,
         1, (re->proto == EC_REDIR_PROTO_IPV4 ? "IPv4" : "IPv6"),
         2, re->source,
         3, re->destination,
         4, re->from_port,
         5, re->to_port,
         6, ec_strlc(re->name),
         7, ec_struc(re->name),
         -1);

}


/*
 * callback when IP address family is changed
 *    - update preset string of source / destination entry widgets
 */
void gtkui_sslredir_af_changed(GtkWidget *widget, gpointer data)
{
   GtkWidget **widgets;
   GtkTreeModel *model;
   GtkTreeIter iter;
   ec_redir_proto_t proto;

   widgets = data;

   model = gtk_combo_box_get_model(GTK_COMBO_BOX(widget));
   gtk_combo_box_get_active_iter(GTK_COMBO_BOX(widget), &iter);
   gtk_tree_model_get(model, &iter, 1, &proto, -1); 

   switch (proto) {
      case EC_REDIR_PROTO_IPV4:
         gtk_entry_set_text(GTK_ENTRY(widgets[0]), "0.0.0.0/0");
         gtk_entry_set_text(GTK_ENTRY(widgets[1]), "0.0.0.0/0");
         gtk_widget_grab_focus(widgets[0]);
         break;
      case EC_REDIR_PROTO_IPV6:
         gtk_entry_set_text(GTK_ENTRY(widgets[0]), "::/0");
         gtk_entry_set_text(GTK_ENTRY(widgets[1]), "::/0");
         gtk_widget_grab_focus(widgets[0]);
         break;
      default:
         break;
   }

}

/*
 * callback function when delete key is pressed in redirect rule list
 */
gboolean gtkui_sslredir_key_pressed(GtkWidget *widget, GdkEventKey *event,
      gpointer data)
{
   DEBUG_MSG("gtkui_sslredir_key_pressed()");

   if (event->keyval == gdk_keyval_from_name("Delete")) {
      gtkui_sslredir_del(widget, data);
      return TRUE;
   }

   if (event->keyval == gdk_keyval_from_name("Insert")) {
      gtkui_sslredir_add(widget, data);
      return TRUE;
   }

   /* fall through to other handlers */
   return FALSE;
}

/* EOF */

// vim:ts=3:expandtab

