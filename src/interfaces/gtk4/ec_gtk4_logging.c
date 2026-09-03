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
#include <ec_gtk4.h>
#include <ec_log.h>

/*
 * The GTK3 version held the chosen path in a 40-byte heap buffer and filled
 * it with memcpy(logfile, filename, FILE_LEN) -- a fixed-length copy out of
 * a NUL-terminated string of unknown length. A shorter name read past the
 * end of the source; a longer one was truncated with no terminator. PATH_MAX
 * and a bounded copy remove both hazards, and paths longer than 40 bytes now
 * work, which they previously did not.
 */
static char logfile[PATH_MAX];

/*******************************************/

void toggle_compress(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) data;

   g_simple_action_set_state(action, value);

   EC_GBL_OPTIONS->compress ^= 1;
}

/*
 * The three "choose a file, then start logging at this level" dialogs were
 * three near-identical copies under GTK3, differing only in their title and
 * the one call at the end. Turning them async made the shared shape obvious,
 * so they share one browse helper and dispatch on the level.
 */
enum log_kind {
   LOG_KIND_ALL,
   LOG_KIND_INFO,
   LOG_KIND_MSG,
};

static void on_logfile_chosen(gboolean confirmed, gpointer data)
{
   enum log_kind kind = GPOINTER_TO_INT(data);

   if (!confirmed)
      return;

   /* a check on the input */
   if (strlen(logfile) == 0) {
      ui_error("Please specify a filename");
      return;
   }

   switch (kind) {
      case LOG_KIND_ALL:
         set_loglevel(LOG_PACKET, logfile);
         break;
      case LOG_KIND_INFO:
         set_loglevel(LOG_INFO, logfile);
         break;
      case LOG_KIND_MSG:
         set_msg_loglevel(LOG_TRUE, logfile);
         break;
   }

   logfile[0] = '\0';
}

static void browse_logfile(const char *title, enum log_kind kind)
{
   logfile[0] = '\0';

   gtkui_filename_browse(title, TRUE, logfile, sizeof(logfile),
         on_logfile_chosen, GINT_TO_POINTER(kind), NULL);
}

/*
 * display the log dialog
 */
void gtkui_log_all(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_log_all");

   browse_logfile("Save all to logfile...", LOG_KIND_ALL);
}

void gtkui_log_info(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_log_info");

   browse_logfile("Save infos to logfile...", LOG_KIND_INFO);
}

void gtkui_log_msg(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_log_msg");

   browse_logfile("Save log messages to file...", LOG_KIND_MSG);
}

void gtkui_stop_log(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   set_loglevel(LOG_STOP, "");
   gtkui_message("Logging was stopped.");
}

void gtkui_stop_msg(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   set_msg_loglevel(LOG_FALSE, NULL);
   gtkui_message("Message logging was stopped.");
}

/* EOF */

// vim:ts=3:expandtab
