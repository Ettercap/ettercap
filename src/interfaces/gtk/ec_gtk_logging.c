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
#include <ec_log.h>

#define FILE_LEN  40

/* proto */

static void log_all(void);
static void log_info(void);
static void log_msg(void);

/* globals */

static char *logfile;

/*******************************************/

void toggle_compress(void)
{
   if (EC_GBL_OPTIONS->compress) {
      EC_GBL_OPTIONS->compress = 0;
   } else {
      EC_GBL_OPTIONS->compress = 1;
   }
}

/*
 * display the log dialog 
 */
void gtkui_log_all(void)
{
   GtkWidget *dialog;
   gchar *filename;
   DEBUG_MSG("gtk_log_all");

   /* make sure to free if already set */
   SAFE_FREE(logfile);
   SAFE_CALLOC(logfile, FILE_LEN, sizeof(char));

   dialog = gtk_file_chooser_dialog_new("Save all to logfile...",
           GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_SAVE,
           GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
           GTK_STOCK_SAVE, GTK_RESPONSE_OK,
           NULL);
   gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), ".");

   if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
       gtk_widget_hide(dialog);
       filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
       gtk_widget_destroy(dialog);
       memcpy(logfile, filename, FILE_LEN);
       g_free(filename);
       log_all();
   } else {
       gtk_widget_destroy(dialog);
   }
}

static void log_all(void)
{
   /* a check on the input */
   if (strlen(logfile) == 0) {
      ui_error("Please specify a filename");
      return;
   }

   set_loglevel(LOG_PACKET, logfile);
   SAFE_FREE(logfile);
}

/*
 * display the log dialog 
 */
void gtkui_log_info(void)
{
   GtkWidget *dialog;
   gchar *filename;

   DEBUG_MSG("gtk_log_info");

   /* make sure to free if already set */
   SAFE_FREE(logfile);
   SAFE_CALLOC(logfile, FILE_LEN, sizeof(char));

   dialog = gtk_file_chooser_dialog_new("Save infos to logfile...",
           GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_SAVE,
           GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
           GTK_STOCK_SAVE, GTK_RESPONSE_OK,
           NULL);
   gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), ".");

   if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
       gtk_widget_hide(dialog);
       filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
       gtk_widget_destroy(dialog);
       memcpy(logfile, filename, FILE_LEN);
       g_free(filename);
       log_info();
   } else {
       gtk_widget_destroy(dialog);
   }
}

static void log_info(void)
{
   /* a check on the input */
   if (strlen(logfile) == 0) {
      ui_error("Please specify a filename");
      return;
   }

   set_loglevel(LOG_INFO, logfile);
   SAFE_FREE(logfile);
}

void gtkui_stop_log(void)
{
   set_loglevel(LOG_STOP, "");
   gtkui_message("Logging was stopped.");
}

/*
 * display the log dialog 
 */
void gtkui_log_msg(void)
{
   GtkWidget *dialog;
   gchar *filename;
   
   DEBUG_MSG("gtk_log_msg");

   /* make sure to free if already set */
   SAFE_FREE(logfile);
   SAFE_CALLOC(logfile, FILE_LEN, sizeof(char));

   dialog = gtk_file_chooser_dialog_new("Safe Log Messages in file...",
           GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_SAVE,
           GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
           GTK_STOCK_SAVE, GTK_RESPONSE_OK,
           NULL);

   gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), ".");

   if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
       gtk_widget_hide(dialog);
       filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
       gtk_widget_destroy(dialog);
       memcpy(logfile, filename, FILE_LEN);
       g_free(filename);
       log_msg();
   } else {
       gtk_widget_destroy(dialog);
   }
}

static void log_msg(void)
{
   /* a check on the input */
   if (strlen(logfile) == 0) {
      ui_error("Please specify a filename");
      return;
   }

   set_msg_loglevel(LOG_TRUE, logfile);
   SAFE_FREE(logfile);
}

void gtkui_stop_msg(void)
{
   set_msg_loglevel(LOG_FALSE, NULL);
   gtkui_message("Message logging was stopped.");
}

/* EOF */

// vim:ts=3:expandtab

