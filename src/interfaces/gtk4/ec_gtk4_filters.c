/*
    ettercap -- GTK4 GUI

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
#include <ec_file.h>
#include <ec_filter.h>
#include <ec_version.h>
#include <ec_gtk4.h>

/*******************************************/

static char filter_filename[PATH_MAX];

/*
 * The GTK3 version embedded a GtkFileChooserWidget inside a GtkDialog and
 * blocked on gtk_dialog_run(). GtkFileDialog does the whole job
 * asynchronously and goes through the portal, so this also works when
 * ettercap is packaged as a Flatpak or Snap -- which the embedded chooser
 * could not.
 */
static void on_filter_chosen(gboolean confirmed, gpointer data)
{
   (void) data;

   if (!confirmed)
      return;

   /*
    * load the filters chain.
    * errors are spawned by the function itself
    */
   filter_load_file(filter_filename, EC_GBL_FILTERS, 1);
}

/*
 * display the file open dialog
 */
void gtkui_load_filter(GSimpleAction *action, GVariant *value, gpointer data)
{
   char *path;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_load_filter");

   /* start the browser in the share directory, where the filters live */
   path = get_full_path("share", "");
   if (path != NULL) {
      strncpy(filter_filename, path, sizeof(filter_filename) - 1);
      filter_filename[sizeof(filter_filename) - 1] = '\0';
      SAFE_FREE(path);
   } else {
      filter_filename[0] = '\0';
   }

   gtkui_filename_browse("Select a precompiled filter file...", FALSE,
         filter_filename, sizeof(filter_filename), on_filter_chosen,
         NULL, NULL);
}

/*
 * unload the filter chain
 */
void gtkui_stop_filter(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_stop_filter");

   filter_unload(EC_GBL_FILTERS);

   gtkui_message("Filters were unloaded");
}

/* EOF */

// vim:ts=3:expandtab
