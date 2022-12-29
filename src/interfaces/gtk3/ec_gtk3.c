/*
    ettercap -- GTK+3/GNOME GUI

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
#include <ec_capture.h>
#include <ec_version.h>
#include <ec_geoip.h>

#include <pcap.h>
#include <string.h>

  /* \Device\NPF{...} and description are huge. There should be 2 buffers
   * for this; one for dev-name and 1 for description. Note: dev->description
   * on WinPcap can contain <tab> and newlines!
   */
#define IFACE_LEN  100

/* globals */

GtkApplication *etterapp = NULL;
GtkWidget *window = NULL;   /* main window */
GtkWidget *notebook = NULL;
GtkWidget *main_menu = NULL;
GtkUIManager *menu_manager = NULL;
guint merge_id;
GTimer *progress_timer = NULL;

GtkWidget     *notebook_frame = NULL;
GtkWidget     *textview = NULL;
GtkWidget     *infobar = NULL;
GtkWidget     *infolabel = NULL;
GtkWidget     *infoframe = NULL;
static guint   infotimer = 0;
GtkTextBuffer *msgbuffer = NULL;
GtkTextMark   *endmark = NULL;
static gboolean       progress_canceled = FALSE;
static GtkWidget     *progress_dialog = NULL;
static GtkWidget     *progress_bar = NULL;


/* proto */

void gtkui_start(void);

static void gtkui_init(void);
static void gtkui_cleanup(void);
static void gtkui_update(int target);
static void gtkui_msg(const char *msg);
gboolean gtkui_infobar_expired(gpointer data);
static void gtkui_error(const char *msg);
static void gtkui_fatal_error(const char *msg);
static gboolean gtkui_flush_msg(gpointer data);
static void gtkui_progress(char *title, int value, int max);

GtkApplication* gtkui_setup(void * activate_func, gpointer activate_param);
static void gtkui_build_widgets(GApplication* app, gpointer data);

static void toggle_unoffensive(GSimpleAction *action, GVariant *value, gpointer data);
static void toggle_nopromisc(GSimpleAction *action, GVariant *value, gpointer data);

static void gtkui_file_open(GSimpleAction *action, GVariant *value, gpointer data);
static void read_pcapfile(gchar *file);
static void gtkui_file_write(GSimpleAction *action, GVariant *value, gpointer data);
static void write_pcapfile(void);
static void gtkui_set_iface_unified(GtkComboBox *combo, gpointer data);
static void gtkui_set_iface_bridge(GtkComboBox *combo, gpointer data);
static gboolean gtkui_bridged_switch(GtkSwitch *switcher, gboolean state, gpointer data);
static gboolean gtkui_autostart_switch(GtkSwitch *switcher, gboolean state, gpointer data);
static void gtkui_sniff(GtkButton *button, gpointer data);
static void gtkui_pcap_filter(GSimpleAction *action, GVariant *value, gpointer data);
static void gtkui_set_netmask(GSimpleAction *action, GVariant *value, gpointer data);
static gboolean gtkui_progress_cancel(GtkWidget *window, gpointer data);

#define ENABLED "true"
#define DISABLED "false"

/* wrapper functions which inject the real function call into the main
 * idle loop, ensugin only th emain thread performs GTK operations
*/
static gboolean gtkui_cleanup_shim(gpointer data)
{
   /* variable not used */
   (void) data;

   gtkui_cleanup();
   return FALSE;
}

static void gtkui_cleanup_wrap(void)
{
   g_idle_add(gtkui_cleanup_shim, NULL);
}

static gboolean gtkui_msg_shim(gpointer data)
{
   gtkui_msg(data);
   SAFE_FREE(data);
   return FALSE;
}

static void gtkui_msg_wrap(const char *msg)
{
    char *copy = strdup(msg);
    if (msg) {
       g_idle_add(gtkui_msg_shim, copy);
    } else {
       FATAL_ERROR("out of memory");
    }
}

static gboolean gtkui_error_shim(gpointer data)
{
   gtkui_error(data);
   SAFE_FREE(data);
   return FALSE;
}

static void gtkui_error_wrap(const char *msg)
{

   char *copy = strdup(msg);
   if (msg) {
      g_idle_add(gtkui_error_shim, copy);
   } else {
      FATAL_ERROR("out of memory");
   }
}

static gboolean gtkui_fatal_error_shim(gpointer data) {
   gtkui_fatal_error(data);
   SAFE_FREE(data);
   return FALSE;
}

static void gtkui_fatal_error_wrap(const char *msg) {

   char *copy = strdup(msg);
   if (msg) {
      gtkui_fatal_error_shim(copy);
      //g_idle_add(gtkui_fatal_error_shim, copy);
   } else {
      FATAL_ERROR("out of memory");
   }
}

struct gtkui_input_data {
   char *title;
   char *input;
   size_t n;
   void (*callback)(void);
};

struct gtkui_progress_data {
   char *title;
   int value;
   int max;
};

static gboolean gtkui_progress_shim(gpointer data) {

   struct gtkui_progress_data *gpd = data;
   gdouble delay; 
   gulong usec;

   delay = g_timer_elapsed(progress_timer, &usec);
   delay += usec / 1000000;

   /* render progress bar if not canceled or lasting longer than 750 ms */
   if (!progress_canceled && delay >= 0.75)
      gtkui_progress(gpd->title, gpd->value, gpd->max);
   SAFE_FREE(gpd->title);
   SAFE_FREE(gpd);
   return FALSE;
}

static int gtkui_progress_wrap(char *title, int value, int max) {

   struct gtkui_progress_data *gpd;

   if (value <= 1) {
      g_timer_start(progress_timer);
      progress_canceled = FALSE;
   }

   if (progress_canceled == TRUE) {
      return UI_PROGRESS_INTERRUPTED;
   }

   if (!title) {
    return UI_PROGRESS_UPDATED;
   }

   gpd = malloc(sizeof *gpd);
   if (gpd) {
      gpd->title = strdup(title);
      gpd->value = value;
      gpd->max = max;
      g_idle_add(gtkui_progress_shim, gpd);
   } else {
      FATAL_ERROR("out of memory");
   }

   return value == max
      ? UI_PROGRESS_FINISHED
      : UI_PROGRESS_UPDATED;
}





/********************************************/

void set_gtk_interface(void)
{
   struct ui_ops ops;

   /* wipe the struct */
   memset(&ops, 0, sizeof(ops));

   /* register the functions */
   ops.init = &gtkui_init;
   ops.start = &gtkui_start;
   ops.type = UI_GTK;
   ops.cleanup = &gtkui_cleanup_wrap;
   ops.msg = &gtkui_msg_wrap;
   ops.error = &gtkui_error_wrap;
   ops.fatal_error = &gtkui_fatal_error_wrap;
   ops.input = &gtkui_input;
   ops.progress = &gtkui_progress_wrap;
   ops.update = &gtkui_update;

   ui_register(&ops);

   DEBUG_MSG("GTK3 -> gtk+3 %d.%d.%d\n", gtk_major_version, gtk_minor_version, gtk_micro_version);
}


/*
 * prepare GTK, create the menu/messages window, enter the first loop 
 */
static void gtkui_init(void)
{
   DEBUG_MSG("gtkui_init");

   if(!gtk_init_check(0, NULL)) {
   	FATAL_ERROR("GTK3 failed to initialize. Is X running?");
	   return;
   }

   gtkui_conf_read();

   /* try to explicitely enforce dark theme if preferred */
   if (EC_GBL_CONF->gtkui_prefer_dark_theme)
      g_object_set(gtk_settings_get_default(), 
            "gtk-application-prefer-dark-theme", TRUE,
            NULL);

   etterapp = gtkui_setup(gtkui_build_widgets, NULL);

   /* initialize timer */
   progress_timer = g_timer_new();

   /* gui init loop, calling gtkui_sniff (--> g_application_quit) will cause
    * this to exit so we can proceed to the main loop
    * later. */
   g_application_run(G_APPLICATION(etterapp), 0, NULL);
   g_object_unref(G_OBJECT(etterapp));

   EC_GBL_UI->initialized = 1;
}

/*
 * exit ettercap 
 */
void gtkui_exit(GSimpleAction *action, GVariant *value, gpointer data)
{
   int left, top, width, height;

   (void) action;
   (void) value;
   (void) data;
   DEBUG_MSG("gtkui_exit");

   g_timer_destroy(progress_timer);

   gtk_window_get_position(GTK_WINDOW (window), &left, &top);
   gtk_window_get_size(GTK_WINDOW (window), &width, &height);
   gtkui_conf_set("window_left", left);
   gtkui_conf_set("window_top", top);
   gtkui_conf_set("window_width", width);
   gtkui_conf_set("window_height", height);
 
   g_object_unref(etterapp);
   gtkui_conf_save();
   clean_exit(0);
}

/*
 * reset to the previous state
 */
static void gtkui_cleanup(void)
{
   DEBUG_MSG("gtk_cleanup");

   
}


/*
 * process an UI update notification
 */
static void gtkui_update(int target)
{
    switch (target) {
        case UI_UPDATE_HOSTLIST:
            g_idle_add((GSourceFunc)gtkui_refresh_host_list, NULL);
            break;
        case UI_UPDATE_PLUGINLIST:
            g_idle_add((GSourceFunc)gtkui_refresh_plugin_list, NULL);
            break;
    }

}

/*
 * print a USER_MSG() extracting it from the queue
 */
static void gtkui_msg(const char *msg)
{
   GtkTextIter iter;
   gchar *unicode = NULL;

   DEBUG_MSG("gtkui_msg: %s", msg);

   if((unicode = gtkui_utf8_validate((char *)msg)) == NULL)
         return;

   gtk_text_buffer_get_end_iter(msgbuffer, &iter);
   gtk_text_buffer_insert(msgbuffer, &iter, unicode, -1);
   gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW (textview), 
                                endmark, 0, FALSE, 0, 0);
   return;
}

/* flush pending messages */
gboolean gtkui_flush_msg(gpointer data)
{
   /* variable not used */
   (void) data;

   ui_msg_flush(MSG_ALL);

   return(TRUE);
}

/*
 * display about dialog
 */
void gtkui_about(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *content, *scroll, *vbox, *logo, *label;
   GtkWidget *textview, *header, *stack, *stackswitch;
   GtkTextBuffer *textbuf;
   GtkTextIter iter;
   GError *error = NULL;
   const gchar *path, *unicode;
   gchar *license, *authors;
   gsize length;
   
   (void) action;
   (void) value;
   (void) data;

   header = gtk_header_bar_new();
   gtk_header_bar_set_title(GTK_HEADER_BAR(header), "About");
   gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
   gtk_header_bar_set_decoration_layout(GTK_HEADER_BAR(header), ":close");

   dialog = gtk_dialog_new();
   gtk_window_set_title(GTK_WINDOW(dialog), "About");
   gtk_window_set_titlebar(GTK_WINDOW(dialog), header);
   gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
   gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(window));
   gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER_ON_PARENT);
   gtk_window_set_default_size(GTK_WINDOW(dialog), 450, 300);

   stack = gtk_stack_new();
   gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_SLIDE_LEFT_RIGHT);
   stackswitch = gtk_stack_switcher_new();
   gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(stackswitch), GTK_STACK(stack));
   gtk_header_bar_set_custom_title(GTK_HEADER_BAR(header), stackswitch);


   /* General page */
   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);

   path = INSTALL_DATADIR "/" PROGRAM "/" LOGO_FILE_SMALL;
   if(g_file_test(path, G_FILE_TEST_EXISTS))
      logo = gtk_image_new_from_file(path);
   else /* if neither path is valid gtk will use a broken image icon */
      logo = gtk_image_new_from_file("./share/" LOGO_FILE_SMALL);
   gtk_box_pack_start(GTK_BOX(vbox), logo, TRUE, TRUE, 0);

   label = gtk_label_new("");
   gtk_label_set_markup(GTK_LABEL(label), 
         "<span size=\"xx-large\" weight=\"bold\">" 
         PROGRAM " " EC_VERSION 
         "</span>");
   gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

   label = gtk_label_new("www.ettercap-project.org");
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 0);
   label = gtk_label_new("#ettercap on Libera.Chat IRC (irc.libera.chat:6697)");
   gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 0);
#ifdef HAVE_GEOIP
   if (EC_GBL_CONF->geoip_support_enable) {
      label = gtk_label_new("This product includes GeoLite2 Data created by MaxMind,");
      gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 0);
      label = gtk_label_new("available from https://www.maxmind.com/.");
      gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 0);
   }
#endif
   label = gtk_label_new(" ");
   gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 30);
   gtk_stack_add_titled(GTK_STACK(stack), vbox, "general", "General");

   /* Authors page */
   scroll= gtk_scrolled_window_new(NULL, NULL); 
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);

   /* load the authors file */
   g_file_get_contents("./AUTHORS",
         &authors, &length, &error);
   if (error != NULL) {
      /* no debug message */
      g_error_free(error);
      error = NULL;

      /* 2nd try */
      g_file_get_contents(INSTALL_DATADIR "/" PROGRAM "/AUTHORS",
            &authors, &length, &error);
      if (error != NULL) {
         DEBUG_MSG("failed to load authors file: %s", error->message);
         gtkui_error("Failed to load AUTHORS file.");
         g_error_free(error);
         error = NULL;
      }
   }
   textview = gtk_text_view_new();
   gtk_text_view_set_editable(GTK_TEXT_VIEW(textview), FALSE);
   textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
   if (authors && (unicode = gtkui_utf8_validate(authors)) != NULL) {
      gtk_text_buffer_get_end_iter(textbuf, &iter);
      gtk_text_buffer_insert(textbuf, &iter, unicode, -1);
   }
   gtk_container_add(GTK_CONTAINER(scroll), textview);
   gtk_stack_add_titled(GTK_STACK(stack), scroll, "authors", "Authors");

   /* License page */
   scroll= gtk_scrolled_window_new(NULL, NULL); 
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scroll), 
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);

   /* load license file */
   g_file_get_contents("./LICENSE",
         &license, &length, &error);
   if (error != NULL) {
      /* no debug message */
      g_error_free(error);
      error = NULL;

      /* 2nd try */
      g_file_get_contents(INSTALL_DATADIR "/" PROGRAM "/LICENSE",
            &license, &length, &error);
#ifndef OS_WINDOWS
      if (error != NULL) {
         DEBUG_MSG("failed to load license file: %s, try system path ...", error->message);
         g_error_free(error);
         error = NULL;

         /* 3rd try */
         g_file_get_contents("/usr/share/common-licenses/GPL-2",
               &license, &length, &error);
         }
#endif
         if (error != NULL) {
            DEBUG_MSG("failed to load license file: %s", error->message);
            gtkui_error("Failed to load LICENSE file.");
            g_error_free(error);
            error = NULL;
      }
   }

   textview = gtk_text_view_new();
   gtk_text_view_set_editable(GTK_TEXT_VIEW(textview), FALSE);
   textbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
   if (license && (unicode = gtkui_utf8_validate(license)) != NULL) {
      gtk_text_buffer_get_end_iter(textbuf, &iter);
      gtk_text_buffer_insert(textbuf, &iter, unicode, -1);
   }
   gtk_container_add(GTK_CONTAINER(scroll), textview);

   gtk_stack_add_titled(GTK_STACK(stack), scroll, "license", "License");

   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content), stack);

   // TODO Ctrl+w shall close the window

   gtk_widget_show_all(GTK_WIDGET(dialog));


   gtk_dialog_run(GTK_DIALOG(dialog));

   if (authors)
      g_free(authors);
   if (license)
      g_free(license);

   gtk_widget_destroy(dialog);

}

/*
 * reimplementation of gtk_message_dialog_new() to display a message 
 * dialog with a header-bar since the GTK implementation has hardcoded 
 * disabled this feature in the convenience function gtk_message_dialog_new()
 * and gtk_message_dialog_new() is also not meant anymore to display
 * images or icons indicating the type of message
 */
GtkWidget* gtkui_message_dialog(GtkWindow *parent, GtkDialogFlags flags, 
                                GtkMessageType type, GtkButtonsType buttons, 
                                const char *msg)
{
   GtkWidget *dialog, *label, *icon, *button, *content, *box, *header;

   dialog = gtk_dialog_new();


   /* implement flags */
   if (parent)
      gtk_window_set_transient_for(GTK_WINDOW(dialog), parent);

   if (flags & GTK_DIALOG_MODAL)
      gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);

   if (flags & GTK_DIALOG_DESTROY_WITH_PARENT)
      gtk_window_set_destroy_with_parent(GTK_WINDOW(dialog), TRUE);

   if (flags & GTK_DIALOG_USE_HEADER_BAR) {
      header = gtk_header_bar_new();
      gtk_header_bar_set_decoration_layout(GTK_HEADER_BAR(header), ":close");
      gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
      gtk_window_set_titlebar(GTK_WINDOW(dialog), header);
      gtk_widget_show(header);
   }


   /* buttons */
   switch (buttons) {
      case GTK_BUTTONS_OK:
         button = gtk_dialog_add_button(GTK_DIALOG(dialog), 
               "_OK", GTK_RESPONSE_OK);
         gtk_widget_grab_default(button);
         break;

      case GTK_BUTTONS_CLOSE:
         button = gtk_dialog_add_button(GTK_DIALOG(dialog),
               "_Close", GTK_RESPONSE_CLOSE);
         gtk_widget_grab_default(button);
         break;

      case GTK_BUTTONS_CANCEL:
         button = gtk_dialog_add_button(GTK_DIALOG(dialog),
               "_Cancel", GTK_RESPONSE_CANCEL);
         gtk_widget_grab_default(button);
         break;

      case GTK_BUTTONS_YES_NO:
         button = gtk_dialog_add_button(GTK_DIALOG(dialog),
               "_Yes", GTK_RESPONSE_YES);
         gtk_widget_grab_default(button);

         button = gtk_dialog_add_button(GTK_DIALOG(dialog),
               "_No", GTK_RESPONSE_NO);
         break;

      case GTK_BUTTONS_OK_CANCEL:
         button = gtk_dialog_add_button(GTK_DIALOG(dialog),
               "_OK", GTK_RESPONSE_OK);
         gtk_widget_grab_default(button);

         button = gtk_dialog_add_button(GTK_DIALOG(dialog),
               "_Cancel", GTK_RESPONSE_CANCEL);
         break;

      default: // GTK_BUTTONS_NONE
         break;
   }

   /* create horizontal box for icon and message text */
   box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_set_border_width(GTK_CONTAINER(content), 10);
   gtk_container_add(GTK_CONTAINER(content), box);

   /* icon depending on message type */
   switch (type) {
      case GTK_MESSAGE_INFO:
         gtk_window_set_title(GTK_WINDOW(dialog), "Information");
         icon = gtk_image_new_from_icon_name("dialog-information", GTK_ICON_SIZE_DIALOG);
         gtk_box_pack_start(GTK_BOX(box), icon, FALSE, FALSE, 0);
         break;
      case GTK_MESSAGE_WARNING:
         gtk_window_set_title(GTK_WINDOW(dialog), "Warning");
         icon = gtk_image_new_from_icon_name("dialog-warning", GTK_ICON_SIZE_DIALOG);
         gtk_box_pack_start(GTK_BOX(box), icon, FALSE, FALSE, 0);
         break;
      case GTK_MESSAGE_QUESTION:
         gtk_window_set_title(GTK_WINDOW(dialog), "Question");
         icon = gtk_image_new_from_icon_name("dialog-question", GTK_ICON_SIZE_DIALOG);
         gtk_box_pack_start(GTK_BOX(box), icon, FALSE, FALSE, 0);
         break;
      case GTK_MESSAGE_ERROR:
         gtk_window_set_title(GTK_WINDOW(dialog), "Error");
         icon = gtk_image_new_from_icon_name("dialog-error", GTK_ICON_SIZE_DIALOG);
         gtk_box_pack_start(GTK_BOX(box), icon, FALSE, FALSE, 0);
         break;
      default: // GTK_MESSAGE_OTHER
         break;
   }

   /* message text */
   label = gtk_label_new(msg);
   gtk_box_pack_start(GTK_BOX(box), label, FALSE, FALSE, 0);

   gtk_widget_show_all(box);

   return dialog;
}

/* 
 * some minor notifications don't need a dedicated dialog
 * instead an the infobar widget is being used
 */
GtkWidget* gtkui_infobar_new(GtkWidget *infoframe)
{
   infobar = gtk_info_bar_new();
   gtk_widget_set_no_show_all(infobar, TRUE);

   infolabel = gtk_label_new("");
   gtk_widget_show(infolabel);
   
   gtk_container_add(GTK_CONTAINER(
            gtk_info_bar_get_content_area(GTK_INFO_BAR(infobar))), infolabel);

   gtk_info_bar_add_button(GTK_INFO_BAR(infobar), "_OK", GTK_RESPONSE_OK);

   if (infoframe == NULL)
      infoframe = gtk_frame_new(NULL);
   gtk_widget_set_no_show_all(infoframe, TRUE);
   gtk_frame_set_shadow_type(GTK_FRAME(infoframe), GTK_SHADOW_NONE);
   gtk_container_add(GTK_CONTAINER(infoframe), infobar);
   g_signal_connect(G_OBJECT(infobar), "response", 
         G_CALLBACK(gtkui_infobar_hide), NULL);

   return infoframe;
}

/*
 * show infobar
 */
void gtkui_infobar_show(GtkMessageType type, const gchar *msg)
{

   if (!infobar && !infoframe)
      return;

   if (infobar == NULL)
      infoframe = gtkui_infobar_new(infoframe);

   gtk_label_set_text(GTK_LABEL(infolabel), msg);
   gtk_info_bar_set_message_type(GTK_INFO_BAR(infobar), type);
   gtk_info_bar_set_default_response(GTK_INFO_BAR(infobar), GTK_RESPONSE_OK);

   gtk_widget_show(infobar);
   gtk_widget_show(infoframe);

   infotimer = g_timeout_add_seconds(3, gtkui_infobar_expired, infobar);

}

/*
 * callback when info bar timer expired
 */
gboolean gtkui_infobar_expired(gpointer data)
{
   gtkui_infobar_hide(GTK_WIDGET(data), 0, NULL);
   /* stop timer */
   return FALSE;
}
   

/*
 * callback wrapper to hide infobar necessary due to still (Feb 2018) 
 * unfixed animation bug: https://bugzilla.gnome.org/show_bug.cgi?id=710888
 * implementing suggested workaround to remove and reattach widget
 */
void gtkui_infobar_hide(GtkWidget *widget, gint response, gpointer data)
{
   (void) response;
   (void) data;
   (void) widget;


   if (!infobar || !infoframe)
      return;

   if (infotimer)
      g_source_remove(infotimer);

   gtk_widget_hide(infobar);
   gtk_widget_hide(infoframe);
   gtk_widget_destroy(infobar);
   infobar = NULL;
}

/*
 * print an error
 */
static void gtkui_error(const char *msg)
{
   gchar *unicode = NULL;
   
   DEBUG_MSG("gtkui_error: %s", msg);

   if((unicode = gtkui_utf8_validate((char *)msg)) == NULL)
            return;

   gtkui_infobar_show(GTK_MESSAGE_ERROR, msg);

   return;
}


/*
 * handle a fatal error and exit
 */
static void gtkui_fatal_error(const char *msg)
{
   /* if the gui is working at this point
      display the message in a dialog */
   if(window)
      gtkui_error(msg);

   /* also dump it to console in case ettercap was started in an xterm */
   fprintf(stderr, "FATAL ERROR: %s\n\n\n", msg);

   clean_exit(-1);
}


/*
 * get an input from the user
 */
void gtkui_input(const char *title, char *input, size_t n, void (*callback)(void))
{
   GtkWidget *dialog, *entry, *label, *hbox, *vbox, *image, *content_area;

   dialog = gtk_dialog_new_with_buttons(PROGRAM" Input", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL|GTK_DIALOG_USE_HEADER_BAR, 
                                        "_Cancel", GTK_RESPONSE_CANCEL, 
                                        "_OK",     GTK_RESPONSE_OK,
                                        NULL);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);

   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);

   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox);
   
   image = gtk_image_new_from_icon_name("dialog-question", GTK_ICON_SIZE_DIALOG);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 0);
   
   label = gtk_label_new (title);
   gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
   gtk_label_set_selectable (GTK_LABEL (label), TRUE);
   gtk_box_pack_start (GTK_BOX (hbox), label, TRUE, TRUE, 0);
   
   entry = gtk_entry_new();
   gtk_entry_set_max_length(GTK_ENTRY(entry), n);
   g_object_set_data(G_OBJECT (entry), "dialog", dialog);
   g_signal_connect(G_OBJECT (entry), "activate", G_CALLBACK (gtkui_dialog_enter), NULL);

   
   if (input)
      gtk_entry_set_text(GTK_ENTRY (entry), input); 

   vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_box_pack_start(GTK_BOX(vbox), entry, TRUE, FALSE, 0);
   
   gtk_box_pack_start(GTK_BOX (hbox), vbox, FALSE, FALSE, 5);
   gtk_widget_show_all (hbox);

   if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {

      strncpy(input, gtk_entry_get_text(GTK_ENTRY (entry)), n);

      if (callback != NULL) {
         gtk_widget_destroy(dialog);

         callback();
         return;
      }
   }
   gtk_widget_destroy(dialog);
}


/* 
 * show or update the progress bar
 */
static void gtkui_progress(char *title, int value, int max)
{
   static GtkWidget *hbox, *header, *content;

   /* the first time, create the object */
   if (progress_bar == NULL) {
      header = gtk_header_bar_new();
      gtk_header_bar_set_title(GTK_HEADER_BAR(header), "Progress");
      gtk_header_bar_set_decoration_layout(GTK_HEADER_BAR(header), ":close");
      gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);

      progress_dialog = gtk_dialog_new();
      gtk_window_set_title(GTK_WINDOW (progress_dialog), PROGRAM);
      gtk_window_set_titlebar(GTK_WINDOW(progress_dialog), header);
      gtk_window_set_modal(GTK_WINDOW (progress_dialog), TRUE);
      gtk_window_set_transient_for(GTK_WINDOW(progress_dialog), GTK_WINDOW(window));
      gtk_window_set_position(GTK_WINDOW(progress_dialog), GTK_WIN_POS_CENTER_ON_PARENT);
      gtk_container_set_border_width(GTK_CONTAINER (progress_dialog), 10);
      g_signal_connect(G_OBJECT(progress_dialog), "delete_event", G_CALLBACK(gtkui_progress_cancel), NULL);

      hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 3);
      content = gtk_dialog_get_content_area(GTK_DIALOG(progress_dialog));
      gtk_container_add(GTK_CONTAINER(content), hbox);
    
      progress_bar = gtk_progress_bar_new();
      gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(progress_bar), TRUE);
      gtk_box_pack_start(GTK_BOX(hbox), progress_bar, TRUE, TRUE, 20);

   } 
   
   /* the subsequent calls have to only update the object */
   gtk_progress_bar_set_text(GTK_PROGRESS_BAR(progress_bar), title);
   gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar), (gdouble)((gdouble)value / (gdouble)max));

   /* update dialog window */
   gtk_widget_show_all(progress_dialog);

   /* 
    * when 100%, destroy it
    */
   if (value == max) {
      if (progress_dialog)
         gtk_widget_destroy(progress_dialog);
      progress_dialog = NULL;
      progress_bar = NULL;
   }

}

static gboolean gtkui_progress_cancel(GtkWidget *window, gpointer data) 
{
   /* variable not used */
   (void) window;

   progress_canceled = TRUE;

   /* the progress dialog must be manually destroyed if the cancel button is used */
   if (data != NULL && GTK_IS_WIDGET(data)) {
      gtk_widget_destroy(data);
      progress_dialog = NULL;
      progress_bar = NULL;
   }
   return(FALSE);
}

/*
 * print a message
 */
void gtkui_message(const char *msg)
{
   DEBUG_MSG("gtkui_message: %s", msg);
   gtkui_infobar_show(GTK_MESSAGE_INFO, msg);
}


/*
 * Create the main interface and enter the second loop
 */

void gtkui_start(void)
{
   guint idle_flush;
   gint online;

   DEBUG_MSG("gtkui_start");

   idle_flush = g_timeout_add(500, gtkui_flush_msg, NULL);

   /* which interface do we have to display ? */
   online = (EC_GBL_OPTIONS->read ? 0 : 1);

   /* create second instance of the UI application */
   etterapp = gtkui_setup(gtkui_create_menu, GINT_TO_POINTER(online));

   /* start plugins defined on CLI */
   g_idle_add(gtkui_plugins_autostart, NULL);
   
   /* the main gui loop, once this exits the gui will be destroyed */
   g_application_run(G_APPLICATION(etterapp), 0, NULL);
   g_object_unref(G_OBJECT(etterapp));

   g_source_remove(idle_flush);
}

static void toggle_unoffensive(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) data;

   g_simple_action_set_state(action, value); 

   EC_GBL_OPTIONS->unoffensive ^= 1;
}

static void toggle_nopromisc(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) data;

   g_simple_action_set_state(action, value); 

   EC_GBL_PCAP->promisc ^= 1;
}

/*
 * display the initial menu to setup global options
 * at startup.
 */
GtkApplication* gtkui_setup(void * activate_func, gpointer data)
{
   GtkApplication *app;
   DEBUG_MSG("gtkui_setup");

   app = gtk_application_new("org.gtk.Ettercap", 0);
   g_signal_connect(app, "activate", G_CALLBACK(activate_func), data);

   return app;
}

/*
 * activate callback for GtkApplication for building the widgets 
 * for the setup dialog
 */
static void gtkui_build_widgets(GApplication* app, gpointer data)
{
   GtkWidget *header, *menubutton, *logo, *switcher;
   GtkWidget *layout, *label, *combo1, *combo2, *setting_frame, *grid, *box;
   GtkBuilder *builder;
   GtkListStore *iface_list;
   GtkTreeIter iter;
   GtkCellRenderer *cell1, *cell2;
   gint width, height, left, top;
   gchar *title = NULL;
   char *path = NULL, *markup = NULL;
   guint i;
   pcap_if_t *dev;

   (void) data;

   /* accelerators */
   static gtkui_accel_map_t accels[] = {
      {"app.pcap_filter", {"<Primary>p", NULL}},
      {"app.set_netmask", {"<Primary>n", NULL}},
      {"app.open", {"<Primary>o", NULL}},
      {"app.save", {"<Primary>s", NULL}},
#ifndef OS_WINDOWS
      {"app.help", {"F1", NULL}},
#endif
      {"app.quit", {"<Primary>q", "<Primary>x", NULL}}
   };


   /* actions */
   static GActionEntry action_entries[] = {
      {"set_promisc",      NULL,  NULL, ENABLED,  toggle_nopromisc, {}},
      {"set_unoffensive",  NULL,  NULL, DISABLED, toggle_unoffensive, {}},
      {"open",  gtkui_file_open, NULL, NULL, NULL, {}},
      {"save",  gtkui_file_write, NULL, NULL, NULL, {}},
      {"about", gtkui_about, NULL, NULL, NULL, {}},
      {"shortcuts", gtkui_show_shortcuts, "s", NULL, NULL, {}},
#ifndef OS_WINDOWS
      {"help",        gtkui_help, NULL, NULL, NULL, {}},
#endif
      {"quit",  gtkui_exit, NULL, NULL, NULL, {}},
      {"pcap_filter", gtkui_pcap_filter,   NULL, NULL, NULL, {}},
      {"set_netmask", gtkui_set_netmask,   NULL, NULL, NULL, {}}
   };



   DEBUG_MSG("gtkui_build_widgets (activate method)");

   /* honor CLI options */
   if(!EC_GBL_PCAP->promisc)
      /* setting the menu item active will toggle this setting */
      /* it will be TRUE after the menu is updated */
      action_entries[0].state = DISABLED;

   if(EC_GBL_OPTIONS->unoffensive)
      action_entries[1].state = ENABLED;


   /* add actions to the application */
   g_action_map_add_action_entries(G_ACTION_MAP(app), action_entries, 
         G_N_ELEMENTS(action_entries), app);

   /* map accelerators to actions */
   for (i = 0; i < G_N_ELEMENTS(accels); i++) {
      gtk_application_set_accels_for_action(GTK_APPLICATION(app), 
            accels[i].action, accels[i].accel);
   }

   /* menu structures */
   builder = gtk_builder_new();
   gtk_builder_add_from_string(builder,
         "<interface>"
         "  <menu id='app-menu'>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>_Open PCAP</attribute>"
         "        <attribute name='action'>app.open</attribute>"
         "        <attribute name='icon'>document-open</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>_Save PCAP</attribute>"
         "        <attribute name='action'>app.save</attribute>"
         "        <attribute name='icon'>document-save</attribute>"
         "      </item>"
         "    </section>"
         "    <section>"
#ifndef OS_WINDOWS
         "      <item>"
         "        <attribute name='label' translatable='yes'>Help</attribute>"
         "        <attribute name='action'>app.help</attribute>"
         "        <attribute name='icon'>help-browser</attribute>"
         "      </item>"
#endif
         "      <item>"
         "        <attribute name='label' translatable='yes'>Shortcuts</attribute>"
         "        <attribute name='action'>app.shortcuts</attribute>"
         "        <attribute name='target'>setup-shortcuts</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>_About Ettercap</attribute>"
         "        <attribute name='action'>app.about</attribute>"
         "        <attribute name='icon'>help-about</attribute>"
         "      </item>"
         "    </section>"
         "    <section>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>_Quit</attribute>"
         "        <attribute name='action'>app.quit</attribute>"
         "        <attribute name='icon'>application-exit</attribute>"
         "      </item>"
         "    </section>"
         "  </menu>"
         "  <menu id='options-menu'>"
         "    <section>"
         "    <attribute name='label' translatable='yes'>Options</attribute>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Unoffensive</attribute>"
         "        <attribute name='action'>app.set_unoffensive</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Promisc mode</attribute>"
         "        <attribute name='action'>app.set_promisc</attribute>"
         "      </item>"
         "      <item>"
         "        <attribute name='label' translatable='yes'>Set Netmask</attribute>"
         "        <attribute name='action'>app.set_netmask</attribute>"
         "      </item>"
         "    </section>"
         "  </menu>"
         "</interface>", -1, NULL);
   

   /* set app menu */
   gtk_application_set_app_menu(GTK_APPLICATION(app), 
         G_MENU_MODEL(gtk_builder_get_object(builder, "app-menu")));

   if (g_getenv("APP_MENU_FALLBACK"))
      g_object_set(gtk_settings_get_default(), "gtk-shell-shows-app-menu", FALSE, NULL);


   /* position main window */
   width = gtkui_conf_get("window_width");
   height = gtkui_conf_get("window_height");
   left = gtkui_conf_get("window_left");
   top = gtkui_conf_get("window_top");

   /* setup window needs minimal size */
   width = width < 800 ? 800 : width;
   height = height < 400 ? 400 : height;

   /* Adjust title formatting */
   title = g_strdup(PROGRAM);
   *title = g_ascii_toupper(*title);

   /* create main window */
   window = gtk_application_window_new(GTK_APPLICATION(app));
   gtk_application_window_set_show_menubar(GTK_APPLICATION_WINDOW(window), TRUE);
   gtk_window_set_title(GTK_WINDOW(window), title);
   gtk_window_set_default_size(GTK_WINDOW(window), width, height);

   /* set window icon */
   path = ICON_DIR "/scalable/apps/" ICON_FILE;
   if (g_file_test(path, G_FILE_TEST_EXISTS)) {
      gtk_window_set_icon(GTK_WINDOW(window), gdk_pixbuf_new_from_file(path, NULL));
   }
   else { /* if neither path is valid gtk will use a broken image icon */
      gtk_window_set_icon(GTK_WINDOW(window), gdk_pixbuf_new_from_file("./share/" ICON_FILE, NULL));
   }

   if(left > 0 || top > 0)
      gtk_window_move(GTK_WINDOW(window), left, top);

   g_signal_connect(G_OBJECT (window), "delete_event", G_CALLBACK(gtkui_exit), NULL);

   
   /* create header bar and menu buttons */
   header = gtk_header_bar_new();
   gtk_header_bar_set_title(GTK_HEADER_BAR(header), title);
   gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), EC_VERSION);
   gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
   gtk_window_set_titlebar(GTK_WINDOW(window), header);

   menubutton = gtk_menu_button_new();
   gtk_widget_set_tooltip_text(menubutton, "Options");
   gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(menubutton),
         G_MENU_MODEL(gtk_builder_get_object(builder, "options-menu")));
   gtk_button_set_image(GTK_BUTTON(menubutton),
         gtk_image_new_from_icon_name("open-menu-symbolic", GTK_ICON_SIZE_MENU));
   gtk_header_bar_pack_end(GTK_HEADER_BAR(header), menubutton);


   /* main content area */
   box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
   gtk_container_add(GTK_CONTAINER(window), box);

   /* prepare infobar for later notifications */
   infoframe = gtkui_infobar_new(NULL);
   gtk_box_pack_start(GTK_BOX(box), infoframe, FALSE, FALSE, 0);

   /* the ettercap logo */
   path = INSTALL_DATADIR "/" PROGRAM "/" LOGO_FILE;
   if(g_file_test(path, G_FILE_TEST_EXISTS))
      logo = gtk_image_new_from_file(path);
   else /* if neither path is valid gtk will use a broken image icon */
      logo = gtk_image_new_from_file("./share/" LOGO_FILE);

   /* create overlay to display the logo and overlay the settings widgets */
   layout = gtk_layout_new(NULL, NULL);
   gtk_box_pack_start(GTK_BOX(box), layout, TRUE, TRUE, 0);
   gtk_layout_put(GTK_LAYOUT(layout), logo, 0, 0);

   setting_frame = gtk_frame_new(NULL);
   gtk_frame_set_label(GTK_FRAME(setting_frame), "Setup");
   gtk_frame_set_label_align(GTK_FRAME(setting_frame), 0.5, 0.0);
   gtk_frame_set_shadow_type(GTK_FRAME(setting_frame), GTK_SHADOW_ETCHED_OUT);

   grid = gtk_grid_new();
   gtk_grid_set_row_spacing(GTK_GRID(grid), 10);
   gtk_grid_set_column_spacing(GTK_GRID(grid), 10);
   g_object_set(grid, "margin", 10, NULL);
   gtk_container_add(GTK_CONTAINER(setting_frame), grid);

   label = gtk_label_new(NULL);
   markup = g_markup_printf_escaped(
         "<span style='italic'>%s</span>", 
         "Primary Interface");
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, 1, 1, 1);
   g_free(markup);

   /* make a list of network interfaces */
   iface_list = gtk_list_store_new(2, G_TYPE_STRING, G_TYPE_STRING);
   for (dev = (pcap_if_t *)EC_GBL_PCAP->ifs; dev != NULL; dev = dev->next) {
      gtk_list_store_append(iface_list, &iter);
      gtk_list_store_set(iface_list, &iter, 
            0, dev->name, 1, dev->description, -1); 
   }

   /* make a drop down box for the primary interface and attach the list */
   combo1 = gtk_combo_box_new();
   gtk_combo_box_set_model(GTK_COMBO_BOX(combo1), GTK_TREE_MODEL(iface_list));
   cell1 = gtk_cell_renderer_text_new();
   gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo1), cell1, TRUE);
   gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo1), cell1, 
         "text", 1, NULL);
   g_signal_connect(G_OBJECT(combo1), "changed", 
         G_CALLBACK(gtkui_set_iface_unified), NULL);
   gtk_combo_box_set_active(GTK_COMBO_BOX(combo1), 0);
   gtk_grid_attach(GTK_GRID(grid), combo1, 1, 1, 1, 1);


   label = gtk_label_new(NULL);
   markup = g_markup_printf_escaped(
         "<span style='italic'>%s</span>", 
         "Sniffing at startup");
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, 0, 1, 1);
   g_free(markup);

   switcher = gtk_switch_new();
   box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
   gtk_box_set_homogeneous(GTK_BOX(box), FALSE);
   gtk_box_pack_start(GTK_BOX(box), switcher, FALSE, FALSE, 0);
   gtk_grid_attach(GTK_GRID(grid), box, 1, 0, 1, 1);
   if (EC_GBL_CONF->sniffing_at_startup)
      gtk_switch_set_active(GTK_SWITCH(switcher), TRUE);
   g_signal_connect(G_OBJECT(switcher), "state-set",
         G_CALLBACK(gtkui_autostart_switch), NULL);

   label = gtk_label_new(NULL);
   markup = g_markup_printf_escaped(
         "<span style='italic'>%s</span>", 
         "Bridged sniffing");
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, 2, 1, 1);
   g_free(markup);

   switcher = gtk_switch_new();
   box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
   gtk_box_set_homogeneous(GTK_BOX(box), FALSE);
   gtk_box_pack_start(GTK_BOX(box), switcher, FALSE, FALSE, 0);
   gtk_grid_attach(GTK_GRID(grid), box, 1, 2, 1, 1);

   label = gtk_label_new(NULL);
   markup = g_markup_printf_escaped(
         "<span style='italic'>%s</span>", 
         "Bridged Interface");
   gtk_label_set_markup(GTK_LABEL(label), markup);
   gtk_widget_set_halign(label, GTK_ALIGN_START);
   gtk_grid_attach(GTK_GRID(grid), label, 0, 3, 1, 1);

   /* make a drop down box for the bridge interface and assign the list to it */
   combo2 = gtk_combo_box_new();
   gtk_combo_box_set_model(GTK_COMBO_BOX(combo2), GTK_TREE_MODEL(iface_list));
   cell2 = gtk_cell_renderer_text_new();
   gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo2), cell2, TRUE);
   gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo2), cell2, 
         "text", 1, NULL);
   g_signal_connect(G_OBJECT(combo2), "changed", 
         G_CALLBACK(gtkui_set_iface_bridge), NULL);
   gtk_combo_box_set_active(GTK_COMBO_BOX(combo2), 1);
   gtk_grid_attach(GTK_GRID(grid), combo2, 1, 3 , 1, 1);
   gtk_widget_set_sensitive(combo2, FALSE);

   /* enable / disable bridged interface combo box */
   g_signal_connect(G_OBJECT(switcher), "state-set", 
         G_CALLBACK(gtkui_bridged_switch), combo2);

   gtk_layout_put(GTK_LAYOUT(layout), setting_frame, 450, 10);

   menubutton = gtk_button_new();
   gtk_widget_set_tooltip_text(menubutton, "Accept");
   gtk_button_set_image(GTK_BUTTON(menubutton),
         gtk_image_new_from_icon_name("emblem-ok-symbolic", GTK_ICON_SIZE_BUTTON));
   gtk_header_bar_pack_end(GTK_HEADER_BAR(header), menubutton);
   g_signal_connect(G_OBJECT(menubutton), "clicked", G_CALLBACK(gtkui_sniff), switcher);
   
   gtk_widget_show_all(GTK_WIDGET(window));

   g_object_unref(iface_list);
   g_object_unref(builder);
   g_free(title);


   DEBUG_MSG("gtk_setup: end");
}

/*
 * display the file open dialog
 */
static void gtkui_file_open(GSimpleAction *action, GVariant *value, gpointer data)
{
   GtkWidget *dialog, *chooser, *content;
   gchar *filename;
   int response = 0;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_file_open");


   dialog = gtk_dialog_new_with_buttons("Select a PCAP file for offline sniffing ...", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_USE_HEADER_BAR,
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   gtk_container_set_border_width(GTK_CONTAINER(dialog), 10);

   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   chooser = gtk_file_chooser_widget_new(GTK_FILE_CHOOSER_ACTION_OPEN);
   gtk_container_add(GTK_CONTAINER(content), chooser);
   gtk_widget_show(chooser);

   /* This way the file chooser dialog doesn't start in the recent section */
   gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(chooser), "");

   response = gtk_dialog_run (GTK_DIALOG (dialog));

   if (response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
      /* destroy needs to come before read_pcapfile so gtk_main_quit
         can reside inside read_pcapfile, which is why destroy is here
         twice and not after the if() block */
      gtk_widget_destroy (dialog);

      read_pcapfile (filename);
      g_free(filename);
   } else {
      gtk_widget_destroy (dialog);
   }

}

static void read_pcapfile(gchar *file)
{
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   
   DEBUG_MSG("read_pcapfile %s", file);
   
   SAFE_CALLOC(EC_GBL_OPTIONS->pcapfile_in, strlen(file)+1, sizeof(char));

   snprintf(EC_GBL_OPTIONS->pcapfile_in, strlen(file)+1, "%s", file);

   /* check if the file is good */
   if (is_pcap_file(EC_GBL_OPTIONS->pcapfile_in, pcap_errbuf) != E_SUCCESS) {
      ui_error("%s", pcap_errbuf);
      SAFE_FREE(EC_GBL_OPTIONS->pcapfile_in);
      return;
   }
   
   /* set the options for reading from file */
   EC_GBL_OPTIONS->silent = 1;
   EC_GBL_OPTIONS->unoffensive = 1;
   EC_GBL_OPTIONS->write = 0;
   EC_GBL_OPTIONS->read = 1;

   gtk_main_quit();
}

/*
 * display the write file menu
 */
static void gtkui_file_write(GSimpleAction *action, GVariant *value, gpointer data)
{
#define FILE_LEN  40
   
   GtkWidget *dialog, *content, *chooser;
   gchar *filename;
   int response = 0;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_file_write");
   
   dialog = gtk_dialog_new_with_buttons("Save traffic in a PCAP file ...", 
         GTK_WINDOW (window), 
         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT | GTK_DIALOG_USE_HEADER_BAR,
         "_Cancel", GTK_RESPONSE_CANCEL, 
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   gtk_container_set_border_width(GTK_CONTAINER(dialog), 10);

   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   chooser = gtk_file_chooser_widget_new(GTK_FILE_CHOOSER_ACTION_SAVE);
   gtk_container_add(GTK_CONTAINER(content), chooser);
   gtk_widget_show(chooser);

   /* This way the file chooser dialog doesn't start in the recent section */
   gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(chooser), "");

   response = gtk_dialog_run (GTK_DIALOG (dialog));

   if (response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
      /* destroy needs to come before read_pcapfile so gtk_main_quit
         can reside inside read_pcapfile, which is why destroy is here
         twice and not after the if() block */
      gtk_widget_destroy (dialog);

      EC_GBL_OPTIONS->pcapfile_out = filename;
      write_pcapfile();
   } else {
      gtk_widget_destroy (dialog);
   }
}

static void write_pcapfile(void)
{
   FILE *f;
   
   DEBUG_MSG("write_pcapfile");
   
   /* check if the file is writeable */
   f = fopen(EC_GBL_OPTIONS->pcapfile_out, "w");
   if (f == NULL) {
      ui_error("Cannot write %s", EC_GBL_OPTIONS->pcapfile_out);
      g_free(EC_GBL_OPTIONS->pcapfile_out);
      return;
   }
 
   /* if ok, delete it */
   fclose(f);
   unlink(EC_GBL_OPTIONS->pcapfile_out);

   /* set the options for writing to a file */
   EC_GBL_OPTIONS->write = 1;
   EC_GBL_OPTIONS->read = 0;
}


/*
 * set unified interface when changed in UI
 */
static void gtkui_set_iface_unified(GtkComboBox *combo, gpointer data)
{
   GtkTreeIter iter;
   gchar *iface;

   (void) data;

   gtk_combo_box_get_active_iter(combo, &iter);
   gtk_tree_model_get(gtk_combo_box_get_model(combo), &iter, 0, &iface, -1);

   DEBUG_MSG("gtkui_set_iface_unified: set iface '%s'", iface);

   SAFE_FREE(EC_GBL_OPTIONS->iface);
   SAFE_CALLOC(EC_GBL_OPTIONS->iface, IFACE_LEN, sizeof(char));
   strncpy(EC_GBL_OPTIONS->iface, iface, IFACE_LEN);
}

/*
 * set bridged interface when changed 
 */
static void gtkui_set_iface_bridge(GtkComboBox *combo, gpointer data)
{
   GtkTreeIter iter;
   gchar *iface;

   (void) data;

   gtk_combo_box_get_active_iter(combo, &iter);
   gtk_tree_model_get(gtk_combo_box_get_model(combo), &iter, 0, &iface, -1);

   DEBUG_MSG("gtkui_set_iface_bridge: set iface '%s'", iface);

   SAFE_FREE(EC_GBL_OPTIONS->iface_bridge);
   SAFE_CALLOC(EC_GBL_OPTIONS->iface_bridge, IFACE_LEN, sizeof(char));
   strncpy(EC_GBL_OPTIONS->iface_bridge, iface, IFACE_LEN);
}


/*
 * bridged sniffing switcher callback
 */
static gboolean gtkui_bridged_switch(GtkSwitch *switcher, gboolean state, gpointer data)
{
   (void) data;
   //gtk_switch_set_active(switcher, state);
   gtk_switch_set_state(switcher, state);
   gtk_widget_set_sensitive(GTK_WIDGET(data), gtk_switch_get_active(switcher));

   return TRUE;
}



/*
 * sniffing at startup switcher callback
 */
static gboolean gtkui_autostart_switch(GtkSwitch *switcher, gboolean state, gpointer data)
{
   (void) data;
   //gtk_switch_set_active(switcher, state);
   gtk_switch_set_state(switcher, state);
   EC_GBL_CONF->sniffing_at_startup = gtk_switch_get_active(switcher);

   return TRUE;
}

/*
 * check if unified or bridged sniffing, 
 * then quit this application intance to continue 
 * main functions further initializing ettercap
 */
static void gtkui_sniff(GtkButton *button, gpointer data)
{
   (void) button;

   /* set bridge sniffing if switcher has been set to "on" */
   if (gtk_switch_get_active(GTK_SWITCH(data)))
      set_bridge_sniff();

   /* quit first instance of GtkApplication */
   g_application_quit(G_APPLICATION(etterapp));

}

/*
 * display the pcap filter dialog
 */
static void gtkui_pcap_filter(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

#define PCAP_FILTER_LEN  50
   
   DEBUG_MSG("gtk_pcap_filter");
   
   if (EC_GBL_PCAP->filter == NULL)
       SAFE_CALLOC(EC_GBL_PCAP->filter, PCAP_FILTER_LEN, sizeof(char));

   /* 
    * no callback, the filter is set but we have to return to
    * the interface for other user input
    */
   gtkui_input("Pcap filter :", EC_GBL_PCAP->filter, PCAP_FILTER_LEN, NULL);
}

/*
 * set a different netmask than the system one 
 */
static void gtkui_set_netmask(GSimpleAction *action, GVariant *value, gpointer data)
{
   struct ip_addr net;

   (void) action;
   (void) value;
   (void) data;
   
   DEBUG_MSG("gtkui_set_netmask");
  
   if (EC_GBL_OPTIONS->netmask == NULL)
      SAFE_CALLOC(EC_GBL_OPTIONS->netmask, IP_ASCII_ADDR_LEN, sizeof(char));

   /* 
    * no callback, the filter is set but we have to return to
    * the interface for other user input
    */
   gtkui_input("Netmask :", EC_GBL_OPTIONS->netmask, IP_ASCII_ADDR_LEN, NULL);

   /* sanity check */
   if (strcmp(EC_GBL_OPTIONS->netmask, "") && 
         ip_addr_pton(EC_GBL_OPTIONS->netmask, &net) != E_SUCCESS)
      ui_error("Invalid netmask %s", EC_GBL_OPTIONS->netmask);
            
   /* if no netmask was specified, free it */
   if (!strcmp(EC_GBL_OPTIONS->netmask, ""))
      SAFE_FREE(EC_GBL_OPTIONS->netmask);
}


/*
 * Callback for g_timeout_add() to resolve a IP to name asyncronously
 * if the name is not already in the cache, host_iptoa
 * immediately returns but starts the resolution process
 * in the background. 
 * This function periodically recalls this host_iptoa until
 * a result in available in the cache and updates the widget.
 */
gboolean gtkui_iptoa_deferred(gpointer data)
{
   struct resolv_object *ro;
   char name[MAX_HOSTNAME_LEN];
   ro = (struct resolv_object *)data;

   DEBUG_MSG("gtkui_iptoa_deferred");

   if (host_iptoa(ro->ip, name) == E_SUCCESS) {
      /* 
       * Name has now been resolved in the background
       * Set the widget text and destroy the timer
       */
      if (ro->type == GTK_TYPE_LABEL)
            gtk_label_set_text(GTK_LABEL(ro->widget), name);
      else if (ro->type == GTK_TYPE_LIST_STORE)
            gtk_list_store_set(GTK_LIST_STORE(ro->liststore), 
                  &ro->treeiter, ro->column, name, -1);
      
      /* Free allocated memory */
      SAFE_FREE(ro);

      /* destroy timer */
      return FALSE;
   }
   else  {
      /* Keep trying */
      return TRUE;
   }
}


/* hitting "Enter" keyy in a combo box does the same as clicking OK button */
gboolean gtkui_combo_enter(GtkWidget *widget, GdkEventKey *event, gpointer data)
{
   GtkWidget *dialog;

   /* variable not used */
   (void) data;

   if (event->keyval == GDK_KEY_Return) {
      dialog = g_object_get_data(G_OBJECT(widget), "dialog");
      gtk_dialog_response(GTK_DIALOG (dialog), GTK_RESPONSE_OK);

      return TRUE;
   }

   return FALSE;
}

/* hitting "Enter" key in dialog does same as clicking OK button */
void gtkui_dialog_enter(GtkWidget *widget, gpointer data) {
   GtkWidget *dialog;

   /* variable not used */
   (void) data;

   dialog = g_object_get_data(G_OBJECT(widget), "dialog");
   gtk_dialog_response(GTK_DIALOG (dialog), GTK_RESPONSE_OK);
}

/* create a new notebook (tab) page */
/* returns a parent widget to pack the contents of the page into */
GtkWidget *gtkui_page_new(char *title, void (*callback)(void), void (*detacher)(GtkWidget *)) {
   GtkWidget *parent, *label;
   GtkWidget *hbox, *button, *image;

   /* a container to hold the close button and tab label */
   hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
   gtk_widget_show(hbox);

   /* the label for the tab title */
   label = gtk_label_new(title);
   gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
   gtk_widget_show(label);

   /* the close button */
   button = gtk_button_new();
   gtk_button_set_relief(GTK_BUTTON (button), GTK_RELIEF_NONE);
   gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);
   gtk_widget_set_size_request(button, 20, 20);
   gtk_widget_show(button);

   /* an image for the button */
   image = gtk_image_new_from_icon_name("window-close", GTK_ICON_SIZE_MENU);
   gtk_container_add(GTK_CONTAINER (button), image);
   gtk_widget_show(image);

   /* a parent to pack the contents into */
   parent = gtk_frame_new(NULL);
   gtk_frame_set_shadow_type(GTK_FRAME(parent), GTK_SHADOW_NONE);
   gtk_widget_show(parent);

   if(!notebook && notebook_frame) {
      gtk_container_remove(GTK_CONTAINER (notebook_frame), gtk_bin_get_child(GTK_BIN (notebook_frame)));

      notebook = gtk_notebook_new();
      gtk_notebook_set_tab_pos(GTK_NOTEBOOK (notebook), GTK_POS_TOP);
      gtk_notebook_set_scrollable(GTK_NOTEBOOK (notebook), TRUE);
      gtk_container_add(GTK_CONTAINER (notebook_frame), notebook);
      gtk_widget_show(notebook);

      gtkui_create_tab_menu();
   }

   gtk_notebook_append_page(GTK_NOTEBOOK(notebook), parent, hbox);

   /* attach callback to destroy the tab/page */
   g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK(gtkui_page_close), parent);

   /* attach callback to do specific clean-up */
   if(callback)
      g_object_set_data(G_OBJECT (parent), "destroy", callback);

   if(detacher)
      g_object_set_data(G_OBJECT (parent), "detach", detacher);

   gtkui_page_present(parent);

   return(parent);
}

/* show and focus the page containing child */
void gtkui_page_present(GtkWidget *child) {
   int num = 0;

   num = gtk_notebook_page_num(GTK_NOTEBOOK (notebook), child);
   gtk_notebook_set_current_page(GTK_NOTEBOOK (notebook), num);

}

/* close the page containing the child passed in "data" */
void gtkui_page_close(GtkWidget *widget, gpointer data) {
   GtkWidget *child;
   gint num = 0;
   void (*callback)(void);

   /* variable not used */
   (void) widget;
   (void) data;

   DEBUG_MSG("gtkui_page_close");

   num = gtk_notebook_page_num(GTK_NOTEBOOK(notebook), GTK_WIDGET (data));
   child = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), num);
   g_object_ref(G_OBJECT(child));

   gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), num);

   callback = g_object_get_data(G_OBJECT (child), "destroy");
   if(callback)
      callback();
}

/* close the currently focused notebook page */
void gtkui_page_close_current(GSimpleAction *action, GVariant *value, gpointer data) {
   GtkWidget *child;
   gint num = 0;

   (void) action;
   (void) value;
   (void) data;

   num = gtk_notebook_get_current_page(GTK_NOTEBOOK (notebook));
   child = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), num);

   gtkui_page_close(NULL, child);
}

/* show the context menu when the notebook tabs receive a mouse right-click */
gboolean gtkui_context_menu(GtkWidget *widget, GdkEventButton *event, gpointer data) {
   /* variable not used */
   (void) widget;

    if(event->button == 3) {
#if GTK_CHECK_VERSION(3,22,0)
       gtk_menu_popup_at_pointer(GTK_MENU(data), (GdkEvent*)event);
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

/* detach the currently focused notebook page into a free window */
void gtkui_page_detach_current(GSimpleAction *action, GVariant *value, gpointer data) {
   void (*detacher)(GtkWidget *);
   GtkWidget *child;
   gint num = 0;

   (void) action;
   (void) value;
   (void) data;

   num = gtk_notebook_get_current_page(GTK_NOTEBOOK (notebook));
   if(num < 0)
      return;
   child = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), num);
   g_object_ref(G_OBJECT(child));

   gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), num);
   
   detacher = g_object_get_data(G_OBJECT (child), "detach");
   if(detacher)
      detacher(child);
}

void gtkui_page_attach_shortcut(GtkWidget *win, void (*attacher)(void))
{
   GtkAccelGroup *accel;
   GClosure *closure = NULL;
   GdkModifierType mods;
   gint keyval;

   accel = gtk_accel_group_new ();
   gtk_window_add_accel_group(GTK_WINDOW (win), accel);
   closure = g_cclosure_new(G_CALLBACK(attacher), NULL, NULL);
   gtk_accelerator_parse ("<control>D", &keyval, &mods);
   gtk_accel_group_connect(accel, keyval, mods, 0, closure);
}

/* change view and focus to the next notebook page */
void gtkui_page_right(GSimpleAction *action, GVariant *value, gpointer data) {
   (void) action;
   (void) value;
   (void) data;

   gtk_notebook_next_page(GTK_NOTEBOOK (notebook));
}

/* change view and focus to previous notebook page */
void gtkui_page_left(GSimpleAction *action, GVariant *value, gpointer data) {
   (void) action;
   (void) value;
   (void) data;

   gtk_notebook_prev_page(GTK_NOTEBOOK (notebook));
}

/* for connecting to browse buttons, pass entry widget as callback "data" */
void gtkui_filename_browse(GtkWidget *widget, gpointer data)
{  
   GtkWidget *dialog = NULL;
   gint response = 0;
   const char *filename = NULL;
   
   /* variable not used */
   (void) widget;

   dialog = gtk_file_chooser_dialog_new("Select a file...",
         NULL, GTK_FILE_CHOOSER_ACTION_OPEN, 
         "_Cancel", GTK_RESPONSE_CANCEL,
         "_OK",     GTK_RESPONSE_OK, 
         NULL);
   
   response = gtk_dialog_run (GTK_DIALOG (dialog));
   
   if (response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog); 
      filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));

      gtk_entry_set_text(GTK_ENTRY (data), filename);
   }
   gtk_widget_destroy(dialog);
}

/* make sure data is valid UTF8 */
char *gtkui_utf8_validate(char *data) {
   const gchar *end;
   char *unicode = NULL;

   unicode = data;
   if(!g_utf8_validate (data, -1, &end)) {
      /* if "end" pointer is at beginning of string, we have no valid text to print */
      if(end == unicode) return(NULL);

      /* cut off the invalid part so we don't lose the whole string */
      /* this shouldn't happen often */
      unicode = (char *)end;
      *unicode = 0;
      unicode = data;
   }

   return(unicode);
}

/* EOF */

// vim:ts=3:expandtab

