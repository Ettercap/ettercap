/*
    ettercap -- GTK4 GUI -- asynchronous dialog helpers

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
 * GTK4 removed gtk_dialog_run(). The GTK3 interface leaned on it in two
 * dozen places, always in the same shape:
 *
 *    dialog = gtk_dialog_new_with_buttons(...);
 *    ...populate the content area...
 *    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {
 *       ...read the widgets back and act on them...
 *    }
 *    gtk_widget_destroy(dialog);
 *
 * gtk_dialog_run() worked by spinning a nested main loop, which is exactly
 * what GTK4 will not do: reentering the main loop from inside an event
 * handler lets the application observe half-dispatched state, and it makes
 * the "is this widget still alive?" question unanswerable. So the pattern
 * has to be turned inside out -- the tail of the function becomes a
 * callback.
 *
 * Doing that by hand at every call site would mean two dozen bespoke
 * context structs and two dozen chances to leak one. Instead each helper
 * here takes the caller's context plus a GDestroyNotify and guarantees
 * exactly one of two things happens to it: either the callback runs and
 * then the context is freed, or the dialog is torn down without an answer
 * and the context is freed anyway. Callers never free it themselves.
 */

#include <ec.h>
#include <ec_gtk4.h>

/* the toast overlay lives in ec_gtk4.c and wraps the whole window content */
extern GtkWidget *toastoverlay;

/*******************************************/

/*
 * Shared context for every helper below. `cb`/`data`/`destroy` is the
 * caller's continuation; the remaining fields are whatever the specific
 * helper needs to marshal an answer back before that continuation runs.
 */
struct dialog_ctx {
   gtkui_dialog_cb cb;
   gpointer data;
   GDestroyNotify destroy;

   /* gtkui_input(): where to copy the entered text, and how much fits */
   char *buffer;
   size_t buflen;
   GtkWidget *entry;
};

static void dialog_ctx_free(struct dialog_ctx *ctx)
{
   if (ctx == NULL)
      return;

   if (ctx->destroy != NULL && ctx->data != NULL)
      ctx->destroy(ctx->data);

   SAFE_FREE(ctx);
}

/*
 * Resolve the window a dialog should be transient for.
 *
 * Dialogs can be raised while the main window is being torn down -- the
 * quit path asks for confirmation, for instance. Presenting a dialog
 * against a destroyed parent is a hard error in GTK4, so fall back to a
 * parentless dialog rather than taking the process down with us.
 */
static GtkWidget *dialog_parent(void)
{
   if (window != NULL && GTK_IS_WINDOW(window))
      return window;

   return NULL;
}

/*******************************************/

/*
 * AdwAlertDialog delivers its answer as a response id string rather than
 * the GTK_RESPONSE_* enum GtkDialog used. We only ever need to distinguish
 * "the user accepted" from everything else -- cancelling, pressing Escape,
 * and the dialog being closed programmatically all collapse to FALSE.
 */
static void on_alert_response(GObject *source, GAsyncResult *result,
      gpointer user_data)
{
   struct dialog_ctx *ctx = user_data;
   const char *response;
   gboolean confirmed;

   response = adw_alert_dialog_choose_finish(ADW_ALERT_DIALOG(source), result);
   confirmed = (response != NULL && !strcmp(response, "ok"));

   if (ctx->cb != NULL)
      ctx->cb(confirmed, ctx->data);

   dialog_ctx_free(ctx);
}

void gtkui_dialog_confirm(const char *title, const char *heading,
      GtkWidget *child, gtkui_dialog_cb cb, gpointer data,
      GDestroyNotify destroy)
{
   AdwAlertDialog *dialog;
   struct dialog_ctx *ctx;

   SAFE_CALLOC(ctx, 1, sizeof(struct dialog_ctx));
   ctx->cb = cb;
   ctx->data = data;
   ctx->destroy = destroy;

   dialog = ADW_ALERT_DIALOG(adw_alert_dialog_new(heading, NULL));

   /*
    * AdwDialog has no title of its own the way GtkDialog did -- the heading
    * is what the user sees. When a caller supplies both, the heading gets
    * the bold line and the title becomes the dialog's accessible label, so
    * that tests/gtk4/harness.py can still find a dialog by the name it had
    * under GTK3 even when the visible wording differs.
    */
   if (title != NULL) {
      if (heading == NULL)
         adw_alert_dialog_set_heading(dialog, title);
      gtk_accessible_update_property(GTK_ACCESSIBLE(dialog),
            GTK_ACCESSIBLE_PROPERTY_LABEL, title, -1);
   }

   if (child != NULL)
      adw_alert_dialog_set_extra_child(dialog, child);

   adw_alert_dialog_add_responses(dialog,
         "cancel", "_Cancel",
         "ok",     "_OK",
         NULL);
   adw_alert_dialog_set_response_appearance(dialog, "ok",
         ADW_RESPONSE_SUGGESTED);
   adw_alert_dialog_set_default_response(dialog, "ok");
   adw_alert_dialog_set_close_response(dialog, "cancel");

   adw_alert_dialog_choose(dialog, dialog_parent(), NULL,
         on_alert_response, ctx);
}

void gtkui_dialog_inform(const char *title, const char *body, GtkWidget *child)
{
   AdwAlertDialog *dialog;

   dialog = ADW_ALERT_DIALOG(adw_alert_dialog_new(title, body));

   if (child != NULL)
      adw_alert_dialog_set_extra_child(dialog, child);

   adw_alert_dialog_add_response(dialog, "close", "_Close");
   adw_alert_dialog_set_default_response(dialog, "close");
   adw_alert_dialog_set_close_response(dialog, "close");

   adw_dialog_present(ADW_DIALOG(dialog), dialog_parent());
}

/*******************************************/

/*
 * The entry has to be read before the caller's continuation runs, because
 * the continuation expects to find the answer in the buffer it handed us --
 * that is the contract gtkui_input() had under GTK3 and keeping it means
 * the call sites only grow a callback, they do not change how they read
 * their result.
 */
static void on_input_response(GObject *source, GAsyncResult *result,
      gpointer user_data)
{
   struct dialog_ctx *ctx = user_data;
   const char *response;
   const char *text;
   gboolean confirmed;

   response = adw_alert_dialog_choose_finish(ADW_ALERT_DIALOG(source), result);
   confirmed = (response != NULL && !strcmp(response, "ok"));

   if (confirmed && ctx->buffer != NULL) {
      text = gtk_editable_get_text(GTK_EDITABLE(ctx->entry));
      strncpy(ctx->buffer, text, ctx->buflen - 1);
      ctx->buffer[ctx->buflen - 1] = '\0';
   }

   if (ctx->cb != NULL)
      ctx->cb(confirmed, ctx->data);

   dialog_ctx_free(ctx);
}

void gtkui_input_full(const char *title, char *input, size_t n,
      gtkui_dialog_cb cb, gpointer data, GDestroyNotify destroy)
{
   AdwAlertDialog *dialog;
   struct dialog_ctx *ctx;
   GtkWidget *entry;

   SAFE_CALLOC(ctx, 1, sizeof(struct dialog_ctx));
   ctx->cb = cb;
   ctx->data = data;
   ctx->destroy = destroy;
   ctx->buffer = input;
   ctx->buflen = n;

   entry = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(entry), n - 1);
   /*
    * AdwAlertDialog installs its default response's button as the dialog's
    * default widget, so activates-default is what makes Enter accept the
    * dialog. The GTK3 interface needed an explicit key-press-event handler
    * (gtkui_dialog_enter) for this; that handler has no counterpart here.
    */
   gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
   if (input != NULL && *input != '\0')
      gtk_editable_set_text(GTK_EDITABLE(entry), input);
   ctx->entry = entry;

   dialog = ADW_ALERT_DIALOG(adw_alert_dialog_new(title, NULL));
   adw_alert_dialog_set_extra_child(dialog, entry);
   adw_alert_dialog_add_responses(dialog,
         "cancel", "_Cancel",
         "ok",     "_OK",
         NULL);
   adw_alert_dialog_set_response_appearance(dialog, "ok",
         ADW_RESPONSE_SUGGESTED);
   adw_alert_dialog_set_default_response(dialog, "ok");
   adw_alert_dialog_set_close_response(dialog, "cancel");

   adw_alert_dialog_choose(dialog, dialog_parent(), NULL,
         on_input_response, ctx);

   gtk_widget_grab_focus(entry);
}

/*
 * The ui_ops form. The core hands us a plain void(*)(void) continuation and
 * expects it to run only if the user accepted -- it has no way to be told
 * about a cancellation, and the curses and text interfaces behave the same
 * way, so silently doing nothing on cancel is the correct contract here
 * rather than an omission.
 */
static void on_ui_input(gboolean confirmed, gpointer data)
{
   void (*callback)(void) = data;

   if (confirmed && callback != NULL)
      callback();
}

void gtkui_input(const char *title, char *input, size_t n,
      void (*callback)(void))
{
   gtkui_input_full(title, input, n, on_ui_input, callback, NULL);
}

/*******************************************/

/*
 * File selection.
 *
 * GtkFileChooserDialog is deprecated in GTK4 and, more to the point, was
 * only ever usable here because gtk_dialog_run() could block on it.
 * GtkFileDialog (GTK 4.10) is async by construction and portal-backed, so
 * it also works when ettercap runs inside a Flatpak or Snap -- which the
 * old chooser did not.
 */
static void on_file_response(GObject *source, GAsyncResult *result,
      gpointer user_data)
{
   struct dialog_ctx *ctx = user_data;
   GtkFileDialog *dialog = GTK_FILE_DIALOG(source);
   GFile *file;
   GError *error = NULL;
   char *path;
   gboolean confirmed = FALSE;

   /*
    * The finish call has to happen unconditionally -- it is what consumes
    * the GTask result, and skipping it on a NULL buffer would leak it.
    */
   if (g_object_get_data(source, "ec-save") != NULL)
      file = gtk_file_dialog_save_finish(dialog, result, &error);
   else
      file = gtk_file_dialog_open_finish(dialog, result, &error);

   if (file != NULL) {
      path = g_file_get_path(file);
      if (path != NULL && ctx->buffer != NULL && ctx->buflen > 0) {
         strncpy(ctx->buffer, path, ctx->buflen - 1);
         ctx->buffer[ctx->buflen - 1] = '\0';
         confirmed = TRUE;
      }
      g_free(path);
      g_object_unref(file);
   } else if (error != NULL) {
      /*
       * Distinguish "the user cancelled" from a real failure. Cancelling
       * reports GTK_DIALOG_ERROR_DISMISSED and is not worth a message;
       * anything else is, because the user asked for a file and did not
       * get one.
       */
      if (!g_error_matches(error, GTK_DIALOG_ERROR, GTK_DIALOG_ERROR_DISMISSED))
         gtkui_toast_error(error->message);
      g_error_free(error);
   }

   if (ctx->cb != NULL)
      ctx->cb(confirmed, ctx->data);

   dialog_ctx_free(ctx);
}

void gtkui_filename_browse(const char *title, gboolean save,
      char *filename, size_t n, gtkui_dialog_cb cb, gpointer data,
      GDestroyNotify destroy)
{
   GtkFileDialog *dialog;
   struct dialog_ctx *ctx;
   GtkWindow *parent;

   SAFE_CALLOC(ctx, 1, sizeof(struct dialog_ctx));
   ctx->cb = cb;
   ctx->data = data;
   ctx->destroy = destroy;
   ctx->buffer = filename;
   ctx->buflen = n;

   dialog = gtk_file_dialog_new();
   gtk_file_dialog_set_title(dialog, title);
   gtk_file_dialog_set_modal(dialog, TRUE);

   if (filename != NULL && *filename != '\0') {
      GFile *initial = g_file_new_for_path(filename);
      gtk_file_dialog_set_initial_file(dialog, initial);
      g_object_unref(initial);
   }

   parent = GTK_WINDOW(dialog_parent());

   /*
    * open() and save() have distinct finish functions, and the response
    * handler is shared, so tag the dialog with which one is in flight
    * rather than growing another field on the context.
    */
   if (save) {
      g_object_set_data(G_OBJECT(dialog), "ec-save", GINT_TO_POINTER(1));
      gtk_file_dialog_save(dialog, parent, NULL, on_file_response, ctx);
   } else {
      gtk_file_dialog_open(dialog, parent, NULL, on_file_response, ctx);
   }

   g_object_unref(dialog);
}

/*******************************************/

/*
 * Transient messages.
 *
 * The GTK3 interface put these in a GtkInfoBar that it showed, hid, and
 * re-parented by hand. GtkInfoBar is deprecated in GTK4 and AdwToast does
 * the same job without the bookkeeping: toasts queue, dismiss themselves,
 * and do not reflow the window when they appear.
 */
void gtkui_toast(const char *msg)
{
   AdwToast *toast;

   if (toastoverlay == NULL)
      return;

   toast = adw_toast_new(msg);
   adw_toast_set_timeout(toast, 4);
   adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toastoverlay), toast);
}

void gtkui_toast_error(const char *msg)
{
   AdwToast *toast;
   char *markup;

   if (toastoverlay == NULL)
      return;

   markup = g_markup_printf_escaped("<b>%s</b>", msg);
   toast = adw_toast_new(markup);
   adw_toast_set_use_markup(toast, TRUE);
   /* errors stay until dismissed -- they are not something to miss */
   adw_toast_set_timeout(toast, 0);
   adw_toast_overlay_add_toast(ADW_TOAST_OVERLAY(toastoverlay), toast);
   g_free(markup);
}

/* EOF */

// vim:ts=3:expandtab
