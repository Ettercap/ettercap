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

    $Id: ec_gtk_hosts.c,v 1.6 2004/03/03 13:52:35 daten Exp $
*/

#include <ec.h>
#include <ec_gtk.h>
#include <ec_scan.h>

/* proto */

void gtkui_scan(void);
void gtkui_load_hosts(void);
void gtkui_save_hosts(void);
void gtkui_host_list(void);
void gtkui_refresh_host_list(void);

static void load_hosts(char *file);
static void save_hosts(void);
static void gtkui_hosts_destroy(void);
static void gtkui_delete_host(GtkWidget *widget, gpointer data);
static void gtkui_host_target1(GtkWidget *widget, gpointer data);
static void gtkui_host_target2(GtkWidget *widget, gpointer data);
static struct hosts_list *gtkui_host_selected(void);
static void gtkui_hosts_detach(GtkWidget *child);

/* globals */
static GtkWidget      *hosts_window = NULL;
static GtkTreeSelection  *selection = NULL;
static GtkListStore      *liststore = NULL;

/*******************************************/

/*
 * scan the lan for hosts 
 */
void gtkui_scan(void)
{
   /* wipe the current list */
   del_hosts_list();

   /* no target defined...  force a full scan */
   if (GBL_TARGET1->all_ip && GBL_TARGET2->all_ip &&
      !GBL_TARGET1->scan_all && !GBL_TARGET2->scan_all) {
      GBL_TARGET1->scan_all = 1;
      GBL_TARGET2->scan_all = 1;
   }
   
   /* perform a new scan */
   build_hosts_list();

   gtkui_refresh_host_list();
}

/*
 * display the file open dialog
 */
void gtkui_load_hosts(void)
{
   GtkWidget *dialog;
   char *filename;
   int response = 0;

   DEBUG_MSG("gtk_load_hosts");

   dialog = gtk_file_selection_new ("Select a hosts file...");

   response = gtk_dialog_run (GTK_DIALOG (dialog));
   
   if (response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      filename = gtk_file_selection_get_filename (GTK_FILE_SELECTION (dialog));

      load_hosts(filename);
   }
   gtk_widget_destroy (dialog);
}

static void load_hosts(char *file)
{
   char *tmp;
   char current[PATH_MAX];
   
   DEBUG_MSG("load_hosts %s", file);
   
   SAFE_CALLOC(tmp, strlen(file)+1, sizeof(char));

   /* get the current working directory */
   getcwd(current, PATH_MAX); 

   /* we are opening a file in the current dir.
    * use the relative path, so we can open files
    * in the current dir even if the complete path
    * is not traversable with ec_uid permissions
    */
   if (!strncmp(current, file, strlen(current)))
      sprintf(tmp, "./%s", file+strlen(current));
   else
      sprintf(tmp, "%s", file);

   DEBUG_MSG("load_hosts path == %s", tmp);

   /* wipe the current list */
   del_hosts_list();

   /* load the hosts list */
   scan_load_hosts(tmp);
   
   SAFE_FREE(tmp);
   
   gtkui_host_list();
}

/*
 * display the write file menu
 */
void gtkui_save_hosts(void)
{
#define FILE_LEN  40
   
   DEBUG_MSG("gtk_save_hosts");

   SAFE_FREE(GBL_OPTIONS->hostsfile);
   SAFE_CALLOC(GBL_OPTIONS->hostsfile, FILE_LEN, sizeof(char));
   
   gtkui_input("Output file :", GBL_OPTIONS->hostsfile, FILE_LEN, save_hosts);
}

static void save_hosts(void)
{
   FILE *f;
   
   /* check if the file is writeable */
   f = fopen(GBL_OPTIONS->hostsfile, "w");
   if (f == NULL) {
      ui_error("Cannot write %s", GBL_OPTIONS->hostsfile);
      SAFE_FREE(GBL_OPTIONS->hostsfile);
      return;
   }
 
   /* if ok, delete it */
   fclose(f);
   unlink(GBL_OPTIONS->hostsfile);
   
   scan_save_hosts(GBL_OPTIONS->hostsfile);
}

/*
 * display the host list 
 */
void gtkui_host_list(void)
{
   GtkWidget *scrolled, *treeview, *vbox, *hbox, *button;
   GtkCellRenderer   *renderer;
   GtkTreeViewColumn *column;

   DEBUG_MSG("gtk_host_list");

   if(hosts_window) {
      if(GTK_IS_WINDOW (hosts_window))
         gtk_window_present(GTK_WINDOW (hosts_window));
      else
         gtkui_page_present(hosts_window);
      return;
   }
   
   hosts_window = gtkui_page_new("Host List", &gtkui_hosts_destroy, &gtkui_hosts_detach);

   vbox = gtk_vbox_new(FALSE, 0);
   gtk_container_add(GTK_CONTAINER (hosts_window), vbox);
   gtk_widget_show(vbox);

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

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("IP Address", renderer, "text", 0, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 0);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("MAC Address", renderer, "text", 1, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 1);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   renderer = gtk_cell_renderer_text_new ();
   column = gtk_tree_view_column_new_with_attributes ("Description", renderer, "text", 2, NULL);
   gtk_tree_view_column_set_sort_column_id (column, 2);
   gtk_tree_view_append_column (GTK_TREE_VIEW(treeview), column);

   /* populate the list or at least allocate a spot for it */
   gtkui_refresh_host_list();
  
   /* set the elements */
   gtk_tree_view_set_model(GTK_TREE_VIEW (treeview), GTK_TREE_MODEL (liststore));

   hbox = gtk_hbox_new(TRUE, 0);
   gtk_box_pack_start(GTK_BOX (vbox), hbox, FALSE, FALSE, 0);
   gtk_widget_show(hbox);

   button = gtk_button_new_with_mnemonic("_Delete Host");
   gtk_box_pack_start(GTK_BOX (hbox), button, TRUE, TRUE, 0);
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_delete_host), NULL);
   gtk_widget_show(button);

   button = gtk_button_new_with_mnemonic("Add to Target _1");
   gtk_box_pack_start(GTK_BOX (hbox), button, TRUE, TRUE, 0);
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_host_target1), NULL);
   gtk_widget_show(button);

   button = gtk_button_new_with_mnemonic("Add to Target _2");
   gtk_box_pack_start(GTK_BOX (hbox), button, TRUE, TRUE, 0);
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_host_target2), NULL);
   gtk_widget_show(button);

   gtk_widget_show(hosts_window);
}

static void gtkui_hosts_detach(GtkWidget *child)
{
   hosts_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (hosts_window), "Hosts list");
   gtk_window_set_default_size(GTK_WINDOW (hosts_window), 400, 300);
   g_signal_connect (G_OBJECT (hosts_window), "delete_event", G_CALLBACK (gtk_widget_hide), NULL);

   gtk_container_add(GTK_CONTAINER (hosts_window), child);

   gtk_window_present(GTK_WINDOW (hosts_window));
}

void gtkui_hosts_destroy(void)
{
   gtk_widget_destroy(hosts_window);
   hosts_window = NULL;
}

/*
 * populate the list
 */
void gtkui_refresh_host_list(void)
{
   GtkTreeIter   iter;
   struct hosts_list *hl;
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];
   char name[MAX_HOSTNAME_LEN];

   DEBUG_MSG("gtk_refresh_host_list");

   /* The list store contains a 4th column that is NOT displayed 
      by the treeview widget. This is used to store the pointer
      for each entry's structure. */
   
   if(liststore) 
      gtk_list_store_clear(GTK_LIST_STORE (liststore));
   else
      liststore = gtk_list_store_new (4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_POINTER);

   /* walk the hosts list */
   LIST_FOREACH(hl, &GBL_HOSTLIST, next) {
      /* enlarge the list */ 
      gtk_list_store_append (liststore, &iter);
      /* fill the element */
      gtk_list_store_set (liststore, &iter, 
                          0, ip_addr_ntoa(&hl->ip, tmp),
                          1, mac_addr_ntoa(hl->mac, tmp2),
                          3, hl, -1);
      if (hl->hostname) {
         gtk_list_store_set (liststore, &iter, 2, hl->hostname, -1);
      } else {
         /* resolve the hostname (using the cache) */
         host_iptoa(&hl->ip, name);
         gtk_list_store_set (liststore, &iter, 2, name, -1);
      }
   }
}

/*
 * deletes one host from the list
 */
static void gtkui_delete_host(GtkWidget *widget, gpointer data)
{
   GtkTreeIter iter;
   GtkTreeModel *model;
   struct hosts_list *hl = NULL;

   model = GTK_TREE_MODEL (liststore);

   if (!gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) 
      return; /* nothing is selected */
 
   hl = gtkui_host_selected();

   gtk_list_store_remove(GTK_LIST_STORE (liststore), &iter);

   /* remove the host from the list */
   LIST_REMOVE(hl, next);
   SAFE_FREE(hl->hostname);
   SAFE_FREE(hl);
}

/*
 * add an host to TARGET 1
 */
static void gtkui_host_target1(GtkWidget *widget, gpointer data)
{
   struct hosts_list *hl;
   char tmp[MAX_ASCII_ADDR_LEN];
  
   DEBUG_MSG("gtk_host_target1");
   
   hl = gtkui_host_selected();
   if(!hl)
      return;
  
   /* add the ip to the target */
   add_ip_list(&hl->ip, GBL_TARGET1);

   USER_MSG("Host %s added to TARGET1\n", ip_addr_ntoa(&hl->ip, tmp));
}

/*
 * add an host to TARGET 2
 */
static void gtkui_host_target2(GtkWidget *widget, gpointer data)
{
   struct hosts_list *hl;
   char tmp[MAX_ASCII_ADDR_LEN];
   
   DEBUG_MSG("gtk_host_target2");
   
   hl = gtkui_host_selected();
   if(!hl)
      return;
  
   /* add the ip to the target */
   add_ip_list(&hl->ip, GBL_TARGET2);
   
   USER_MSG("Host %s added to TARGET2\n", ip_addr_ntoa(&hl->ip, tmp));
}

static struct hosts_list *gtkui_host_selected(void) {
   GtkTreeIter iter;
   GtkTreeModel *model;
   struct hosts_list *hl = NULL;

   model = GTK_TREE_MODEL (liststore);

   if (gtk_tree_selection_get_selected (GTK_TREE_SELECTION (selection), &model, &iter)) {
      gtk_tree_model_get (model, &iter, 3, &hl, -1);
   } else 
      return(NULL); /* nothing is selected */
 
   return(hl);
}

/* EOF */

// vim:ts=3:expandtab

