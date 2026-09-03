/*
    ettercap -- GTK4 GUI -- help browser

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

#ifndef OS_WINDOWS

#include <ec.h>
#include <ec_gtk4.h>
#include <ec_file.h>
#include <ec_version.h>

/* globals */
static GtkTextBuffer *textbuf = NULL;

typedef struct {
   const char *title;
   const char *file;
} help_pair;

static const help_pair help_list[] = {
   { "ettercap", "ettercap" },
   { "logging", "etterlog" },
   { "filters", "etterfilter" },
   { "plugins", "ettercap_plugins" },
   { "settings", "etter.conf" },
   { "curses", "ettercap_curses" },
   { NULL, NULL }
};

/* proto */
static void gtkui_help_open(const char *file);

/********************************************/

/*
 * The contents list is a fixed handful of section titles, so it is a
 * GtkStringList behind a GtkListView -- no need for the column view, its
 * sorter, or a boxed item type. The string shown is the section title; the
 * man page it maps to is looked up from help_list by that title when a row
 * is selected.
 */
static void on_help_setup(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_label_new(NULL);

   (void) factory;
   (void) data;

   gtk_label_set_xalign(GTK_LABEL(label), 0.0);
   gtk_widget_set_margin_start(label, 6);
   gtk_widget_set_margin_end(label, 6);
   gtk_list_item_set_child(item, label);
}

static void on_help_bind(GtkListItemFactory *factory, GtkListItem *item,
      gpointer data)
{
   GtkWidget *label = gtk_list_item_get_child(item);
   GtkStringObject *obj = gtk_list_item_get_item(item);

   (void) factory;
   (void) data;

   if (obj != NULL && label != NULL)
      gtk_label_set_text(GTK_LABEL(label), gtk_string_object_get_string(obj));
}

static void on_help_selected(GtkSelectionModel *model, guint position,
      guint n_items, gpointer data)
{
   GtkSingleSelection *single = GTK_SINGLE_SELECTION(model);
   GtkStringObject *obj;
   const char *title;
   const help_pair *section;

   (void) position;
   (void) n_items;
   (void) data;

   obj = gtk_single_selection_get_selected_item(single);
   if (obj == NULL)
      return;

   title = gtk_string_object_get_string(obj);

   for (section = help_list; section->title; section++) {
      if (!strcmp(section->title, title)) {
         gtkui_help_open(section->file);
         return;
      }
   }
}

void gtkui_help(GSimpleAction *action, GVariant *value, gpointer data)
{
   AdwDialog *dialog;
   GtkWidget *toolbar, *header, *hbox, *scrolled, *listview, *textview;
   GtkStringList *titles;
   GtkSingleSelection *selection;
   GtkListItemFactory *factory;
   const help_pair *section;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtkui_help");

   /* the list of section titles */
   titles = gtk_string_list_new(NULL);
   for (section = help_list; section->title; section++)
      gtk_string_list_append(titles, section->title);

   selection = gtk_single_selection_new(G_LIST_MODEL(titles));
   gtk_single_selection_set_autoselect(selection, FALSE);
   gtk_single_selection_set_can_unselect(selection, TRUE);
   gtk_single_selection_set_selected(selection, GTK_INVALID_LIST_POSITION);

   factory = gtk_signal_list_item_factory_new();
   g_signal_connect(factory, "setup", G_CALLBACK(on_help_setup), NULL);
   g_signal_connect(factory, "bind", G_CALLBACK(on_help_bind), NULL);

   listview = gtk_list_view_new(GTK_SELECTION_MODEL(selection), factory);
   g_signal_connect(selection, "selection-changed",
         G_CALLBACK(on_help_selected), NULL);

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), listview);
   gtk_widget_set_size_request(scrolled, 160, -1);

   /* the man-page text area */
   textview = gtk_text_view_new();
   gtk_text_view_set_editable(GTK_TEXT_VIEW(textview), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(textview), FALSE);
   gtk_text_view_set_monospace(GTK_TEXT_VIEW(textview), TRUE);
   textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));

   GtkWidget *text_scroll = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(text_scroll),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(text_scroll), textview);
   gtk_widget_set_hexpand(text_scroll, TRUE);
   gtk_widget_set_vexpand(text_scroll, TRUE);

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
   gtk_box_append(GTK_BOX(hbox), scrolled);
   gtk_box_append(GTK_BOX(hbox), text_scroll);

   header = adw_header_bar_new();
   adw_header_bar_set_title_widget(ADW_HEADER_BAR(header),
         adw_window_title_new(PROGRAM " Help", NULL));

   toolbar = adw_toolbar_view_new();
   adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
   adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), hbox);

   /*
    * AdwDialog is presented, not run: the GTK3 code blocked here on
    * gtk_dialog_run(), which GTK4 removed. There is nothing to collect when
    * it closes -- the man pages are shown live as sections are selected --
    * so there is no response callback either.
    */
   dialog = adw_dialog_new();
   adw_dialog_set_title(dialog, PROGRAM " Help");
   adw_dialog_set_content_width(dialog, 780);
   adw_dialog_set_content_height(dialog, 580);
   adw_dialog_set_child(dialog, toolbar);

   adw_dialog_present(dialog, window);
}

static void gtkui_help_open(const char *file)
{
   /*
    * Try, in order: the system man; a non-standard install dir; the man
    * pages in the build tree as section 8, then section 5 (etter.conf is a
    * man(5) page). This mirrors the GTK3 fallback chain -- only the repeated
    * g_malloc/snprintf/g_spawn boilerplate is folded into a loop.
    */
   static const char *const templates[] = {
      "sh -c \"man %s | col -b\"",
      "sh -c \"man -M " MAN_INSTALLDIR " %s | col -b\"",
      "sh -c \"man ./man/%s.8 | col -b\"",
      "sh -c \"man ./man/%s.5 | col -b\"",
      NULL
   };
   const char *const *tmpl;
   char *data = NULL, *unicode = NULL, *errors = NULL, *cmd;
   gboolean ret = FALSE;

   for (tmpl = templates; *tmpl != NULL; tmpl++) {
      g_clear_pointer(&errors, g_free);
      g_clear_pointer(&data, g_free);

      cmd = g_strdup_printf(*tmpl, file);
      ret = g_spawn_command_line_sync(cmd, &data, &errors, NULL, NULL);
      g_free(cmd);

      /* a run that produced no error text is the page we want */
      if (ret && (errors == NULL || strlen(errors) == 0))
         break;

      /* the last template is the last chance -- report its error */
      if (tmpl[1] == NULL && ret && errors && strlen(errors) > 0)
         ui_error("%s", errors);
   }

   g_clear_pointer(&errors, g_free);

   /* print output of command in help window */
   if (data && ret) {
      if ((unicode = gtkui_utf8_validate(data)))
         gtk_text_buffer_set_text(textbuf, unicode, -1);
   }

   g_free(data);
}

#endif

/* EOF */

// vim:ts=3:expandtab
