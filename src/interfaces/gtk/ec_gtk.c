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
#include <ec_capture.h>
#include <ec_version.h>

#include <pcap.h>
#include <string.h>

  /* \Device\NPF{...} and description are huge. There should be 2 buffers
   * for this; one for dev-name and 1 for description. Note: dev->description
   * on WinPcap can contain <tab> and newlines!
   */
#define IFACE_LEN  100

/* globals */

GtkWidget *window = NULL;   /* main window */
GtkWidget *notebook = NULL;
GtkWidget *main_menu = NULL;
GtkUIManager *menu_manager = NULL;
guint merge_id;
GTimer *progress_timer = NULL;

static GtkWidget     *notebook_frame = NULL;
static GtkWidget     *textview = NULL;
static GtkTextBuffer *msgbuffer = NULL;
static GtkTextMark   *endmark = NULL;
static GtkAccelGroup *accel_group = NULL;
static gboolean       progress_canceled = FALSE;
static GtkWidget     *progress_dialog = NULL;
static GtkWidget     *progress_bar = NULL;

/* proto */

void gtkui_start(void);

static void gtkui_init(void);
static void gtkui_cleanup(void);
static void gtkui_update(int target);
static void gtkui_msg(const char *msg);
static void gtkui_error(const char *msg);
static void gtkui_fatal_error(const char *msg);
static gboolean gtkui_flush_msg(gpointer data);
static void gtkui_progress(char *title, int value, int max);

static void gtkui_setup(void);

static void toggle_unoffensive(void);
static void toggle_nopromisc(void);

static void gtkui_file_open(void);
static void read_pcapfile(gchar *file);
static void gtkui_file_write(void);
static void write_pcapfile(void);
static void gtkui_unified_sniff(void);
static void gtkui_unified_sniff_default(void);
static void gtkui_bridged_sniff(void);
static void bridged_sniff(void);
static void gtkui_pcap_filter(void);
static void gtkui_set_netmask(void);
static gboolean gtkui_progress_cancel(GtkWidget *window, gpointer data);



#if GTK_MINOR_VERSION == 2
static void gtkui_page_defocus_tabs(void);
#endif

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





/***#****************************************/

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

   DEBUG_MSG("GTK -> gtk+ %d.%d.%d\n", gtk_major_version, gtk_minor_version, gtk_micro_version);
}


/*
 * prepare GTK, create the menu/messages window, enter the first loop 
 */
static void gtkui_init(void)
{
   DEBUG_MSG("gtk_init");
// g_thread_init has been deprecated since version 2.32 and should not be used in newly-written code. This function is no longer necessary. The GLib threading system is automatically initialized at the start of your program.
#if !(GLIB_CHECK_VERSION(2,32,0))
   g_thread_init(NULL);
#endif

   if(!gtk_init_check(0, NULL)) {
   	FATAL_ERROR("GTK+ failed to initialize. Is X running?");
	   return;
   }

   gtkui_conf_read();

   gtkui_setup();

   /* initialize timer */
   progress_timer = g_timer_new();

   /* gui init loop, calling gtk_main_quit will cause
    * this to exit so we can proceed to the main loop
    * later. */
   gtk_main();

   /* remove the keyboard shortcuts for the setup menus */
   gtk_window_remove_accel_group(GTK_WINDOW (window), accel_group);

   EC_GBL_UI->initialized = 1;
}

/*
 * exit ettercap 
 */
void gtkui_exit(void)
{
   int left, top, width, height;
   DEBUG_MSG("gtkui_exit");

   g_timer_destroy(progress_timer);

   gtk_window_get_position(GTK_WINDOW (window), &left, &top);
   gtk_window_get_size(GTK_WINDOW (window), &width, &height);
   gtkui_conf_set("window_left", left);
   gtkui_conf_set("window_top", top);
   gtkui_conf_set("window_width", width);
   gtkui_conf_set("window_height", height);
 
   gtk_main_quit();
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
void gtkui_about(void)
{
   GtkWidget *dialog, *notebook, *content, *scroll, *vbox, *logo, *label;
   GtkWidget *button, *textview;
   GtkTextBuffer *textbuf;
   GtkTextIter iter;
   GError *error = NULL;
   const gchar *path, *unicode;
   gchar *license, *authors;
   gsize length;

   dialog = gtk_dialog_new();
   gtk_window_set_title(GTK_WINDOW(dialog), "About");
   gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
   gtk_window_set_transient_for(GTK_WINDOW(dialog), GTK_WINDOW(window));
   gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER_ON_PARENT);
   gtk_window_set_default_size(GTK_WINDOW(dialog), 450, 300);

   button = gtk_dialog_add_button(GTK_DIALOG(dialog), "Close", GTK_RESPONSE_CLOSE);
   gtk_button_set_image(GTK_BUTTON(button), 
         gtk_image_new_from_stock(GTK_STOCK_CLOSE, GTK_ICON_SIZE_BUTTON));

   notebook = gtk_notebook_new();

   /* General page */
   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 10, FALSE);

   path = INSTALL_DATADIR "/" PROGRAM "/" LOGO_FILE_SMALL;
   if(g_file_test(path, G_FILE_TEST_EXISTS))
      logo = gtk_image_new_from_file(path);
   else /* if neither path is valid gtk will use a broken image icon */
      logo = gtk_image_new_from_file("./share/" LOGO_FILE_SMALL);
   gtk_box_pack_start(GTK_BOX(vbox), logo, FALSE, FALSE, 0);

   label = gtk_label_new("");
   gtk_label_set_markup(GTK_LABEL(label), 
         "<span size=\"xx-large\" weight=\"bold\">" 
         PROGRAM " " EC_VERSION 
         "</span>");
   gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

   label = gtk_label_new("www.ettercap-project.org");
   gtk_label_set_selectable(GTK_LABEL(label), TRUE);
   gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
#ifdef HAVE_GEOIP
   if (EC_GBL_CONF->geoip_support_enable) {
      label = gtk_label_new("This product includes GeoLite2 Data created by MaxMind,");
      gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 0);
      label = gtk_label_new("available from https://www.maxmind.com/.");
      gtk_box_pack_start(GTK_BOX(vbox), label, TRUE, TRUE, 0);
   }
#endif
   gtk_notebook_append_page(GTK_NOTEBOOK(notebook), vbox, gtk_label_new("General"));

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
   gtk_notebook_append_page(GTK_NOTEBOOK(notebook), scroll, gtk_label_new("Authors"));

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

   gtk_notebook_append_page(GTK_NOTEBOOK(notebook), scroll, gtk_label_new("License"));

   content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content), notebook);

   /* Hitting Enter closes the About dialog */
   gtk_widget_grab_focus(
         gtk_dialog_get_widget_for_response(
            GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE));

   gtk_widget_show_all(GTK_WIDGET(dialog));


   gtk_dialog_run(GTK_DIALOG(dialog));

   if (authors)
      g_free(authors);
   if (license)
      g_free(license);

   gtk_widget_destroy(dialog);

}

/*
 * print an error
 */
static void gtkui_error(const char *msg)
{
   GtkWidget *dialog;
   gchar *unicode = NULL;
   
   DEBUG_MSG("gtkui_error: %s", msg);

   if((unicode = gtkui_utf8_validate((char *)msg)) == NULL)
            return;

   dialog = gtk_message_dialog_new(GTK_WINDOW (window), GTK_DIALOG_MODAL, 
                                   GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", unicode);
   gtk_window_set_position(GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ON_PARENT);

   /* blocking - displays dialog waits for user to click OK */
   gtk_dialog_run(GTK_DIALOG (dialog));

   gtk_widget_destroy(dialog);
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
   GtkWidget *dialog, *entry, *label, *hbox, *image, *content_area;

   dialog = gtk_dialog_new_with_buttons(PROGRAM" Input", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL, 
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, 
                                        GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        NULL);
#if !GTK_CHECK_VERSION(2, 22, 0) // depricated since Gtk 2.22
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);

   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 6, FALSE);

   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox);
   
   image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_QUESTION, GTK_ICON_SIZE_DIALOG);
   gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.0);
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
   
   gtk_box_pack_start(GTK_BOX (hbox), entry, FALSE, FALSE, 5);
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
   static GtkWidget *hbox, *button;

   /* the first time, create the object */
   if (progress_bar == NULL) {
      progress_dialog = gtk_window_new(GTK_WINDOW_TOPLEVEL);
      gtk_window_set_title(GTK_WINDOW (progress_dialog), PROGRAM);
      gtk_window_set_modal(GTK_WINDOW (progress_dialog), TRUE);
      gtk_window_set_transient_for(GTK_WINDOW(progress_dialog), GTK_WINDOW(window));
      gtk_window_set_position(GTK_WINDOW(progress_dialog), GTK_WIN_POS_CENTER_ON_PARENT);
      gtk_container_set_border_width(GTK_CONTAINER (progress_dialog), 5);
      g_signal_connect(G_OBJECT (progress_dialog), "delete_event", G_CALLBACK (gtkui_progress_cancel), NULL);

      hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 3, FALSE);
      gtk_container_add(GTK_CONTAINER (progress_dialog), hbox);
    
      progress_bar = gtk_progress_bar_new();
#if GTK_CHECK_VERSION(3, 0, 0)
      gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(progress_bar), TRUE);
#endif
      gtk_box_pack_start(GTK_BOX (hbox), progress_bar, TRUE, TRUE, 0);

      button = gtk_button_new_from_stock(GTK_STOCK_CANCEL);
      gtk_box_pack_start(GTK_BOX (hbox), button, FALSE, FALSE, 0);
      g_signal_connect(G_OBJECT (button), "clicked", G_CALLBACK (gtkui_progress_cancel), progress_dialog);

   } 
   
   /* the subsequent calls have to only update the object */
   gtk_progress_bar_set_text(GTK_PROGRESS_BAR (progress_bar), title);
   gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR (progress_bar), (gdouble)((gdouble)value / (gdouble)max));

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
   GtkWidget *dialog;
   
   DEBUG_MSG("gtkui_message: %s", msg);

   dialog = gtk_message_dialog_new(GTK_WINDOW (window), GTK_DIALOG_MODAL, 
                                   GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", msg);
   gtk_window_set_position(GTK_WINDOW (dialog), GTK_WIN_POS_CENTER_ON_PARENT);

   /* blocking - displays dialog waits for user to click OK */
   gtk_dialog_run(GTK_DIALOG (dialog));

   gtk_widget_destroy(dialog);
   return;
}


/*
 * Create the main interface and enter the second loop
 */

void gtkui_start(void)
{
   guint idle_flush;

   DEBUG_MSG("gtk_start");

   idle_flush = g_timeout_add(500, gtkui_flush_msg, NULL);
   
   /* which interface do we have to display ? */
   if (EC_GBL_OPTIONS->read)
      gtkui_sniff_offline();
   else
      gtkui_sniff_live();

   /* start plugins defined on CLI */
   g_idle_add(gtkui_plugins_autostart, NULL);
   
   /* the main gui loop, once this exits the gui will be destroyed */
   gtk_main();

   g_source_remove(idle_flush);
}

static void toggle_unoffensive(void)
{
   if (EC_GBL_OPTIONS->unoffensive) {
      EC_GBL_OPTIONS->unoffensive = 0;
   } else {
      EC_GBL_OPTIONS->unoffensive = 1;
   }
}

static void toggle_nopromisc(void)
{
   if (EC_GBL_PCAP->promisc) {
      EC_GBL_PCAP->promisc = 0;
   } else {
      EC_GBL_PCAP->promisc = 1;
   }
}

/*
 * display the initial menu to setup global options
 * at startup.
 */
static void gtkui_setup(void)
{
   GtkTextIter iter;
   GtkWidget *vbox, *scroll, *vpaned, *logo, *main_menu;
   GtkActionGroup *menuactions;
   GtkAction *action;
   GClosure *closure = NULL;
   GError *error = NULL;
   GdkModifierType mods;
   gint keyval, width, height, left, top;
   char *path = NULL;

   static const char *menu_structure = 
      "<ui>"
      "   <menubar name='MenuBar'>"
      "      <menu name='FileMenu' action='FileMenuAction'>"
      "         <menuitem name='Open' action='FileOpenAction' />"
      "         <menuitem name='Save' action='FileSaveAction' />"
      "         <separator />"
      "         <menuitem name='Exit' action='FileExitAction' />"
      "      </menu>"
      "      <menu name='SniffMenu' action='SniffMenuAction'>"
      "         <menuitem name='UnifiedSniffing' action='SniffUnifiedAction' />"
      "         <menuitem name='BridgedSniffing' action='SniffBridgedAction' />"
      "         <separator />"
      "         <menuitem name='SniffFilter' action='SniffFilterAction' />"
      "      </menu>"
      "      <menu name='OptionsMenu' action='OptionsMenuAction'>"
      "         <menuitem name='Unoffensive' action='OptionsUnoffensiveAction' />"
      "         <menuitem name='Promisc' action='OptionsPromiscAction' />"
      "         <menuitem name='Netmask' action='OptionsNetmaskAction' />"
      "      </menu>"
      "      <menu name='HelpMenu' action='HelpMenuAction'>"
#ifndef OS_WINDOWS
      "         <menuitem name='Help' action='HelpAction' />"
#endif
      "         <menuitem name='About' action='AboutDialogAction' />"
      "      </menu>"
      "   </menubar>"
      "</ui>";

   GtkActionEntry menu_items[] = {
      /* File Menu */
      { 
         "FileMenuAction", NULL,
         "_File", NULL,
         NULL, NULL
      },

      { 
         "FileOpenAction", GTK_STOCK_OPEN,
         "_Open", "<control>O", 
         "Open a PCAP file",
         G_CALLBACK(gtkui_file_open) 
      },

      { 
         "FileSaveAction", GTK_STOCK_SAVE, 
         "_Save", "<control>S", 
         "Save traffic as PCAP file", 
         G_CALLBACK(gtkui_file_write) 
      },

      { 
         "FileExitAction", GTK_STOCK_QUIT, 
         "E_xit", "<control>Q", 
         "Exit Ettercap", 
         G_CALLBACK(gtkui_exit) 
      },

      /* Sniff Menu */
      { 
         "SniffMenuAction", NULL, 
         "_Sniff", NULL,
         NULL, NULL
      },

      { 
         "SniffUnifiedAction", GTK_STOCK_DND, 
         "Unified sniffing...", "<control>U", 
         "Switch to unified sniffing mode", 
         G_CALLBACK(gtkui_unified_sniff) 
      },

      { 
         "SniffBridgedAction", GTK_STOCK_DND_MULTIPLE, 
         "Bridged sniffing...", "<control>B", 
         "Switch to bridged sniffing mode", 
         G_CALLBACK(gtkui_bridged_sniff) 
      },

      { 
         "SniffFilterAction", GTK_STOCK_PREFERENCES, 
         "Set pcap filter...", "<control>P", 
         "Limit relevant traffic", 
         G_CALLBACK(gtkui_pcap_filter)
      },

      /* Options Menu */
      { 
         "OptionsMenuAction", NULL, 
         "_Options", NULL,
         NULL, NULL
      },

      { 
         "OptionsNetmaskAction", NULL, 
         "Set netmask", "<control>N", 
         "Override netmask", 
         G_CALLBACK(gtkui_set_netmask) 
      },

      /* Help Menu */
      { 
         "HelpMenuAction", NULL, 
         "_Info", NULL,
         NULL, NULL
      },

#ifndef OS_WINDOWS
      { 
         "HelpAction", GTK_STOCK_HELP, 
         "Help", "F1", 
         "Ettercap documentation", 
         G_CALLBACK(gtkui_help) 
      },
#endif
      {
         "AboutDialogAction", GTK_STOCK_ABOUT,
         "About", NULL,
         "About Ettercap",
         G_CALLBACK(gtkui_about)
      }
   };

   GtkToggleActionEntry toggle_items[] = {
      { 
         "OptionsUnoffensiveAction", NULL, 
         "Unoffensive", NULL, 
         "Keep quiet", 
         G_CALLBACK(toggle_unoffensive),
         FALSE
      },

      { 
         "OptionsPromiscAction", NULL, 
         "Promisc mode", NULL, 
         "Toogle promisc mode (default: on)", 
         G_CALLBACK(toggle_nopromisc),
         FALSE
      }
   };


   DEBUG_MSG("gtkui_setup");

   width = gtkui_conf_get("window_width");
   height = gtkui_conf_get("window_height");
   left = gtkui_conf_get("window_left");
   top = gtkui_conf_get("window_top");

   /* create menu window */
   window = gtk_window_new (GTK_WINDOW_TOPLEVEL);
   gtk_window_set_title(GTK_WINDOW (window), PROGRAM" "EC_VERSION);
   gtk_window_set_default_size(GTK_WINDOW (window), width, height);

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

   g_signal_connect (G_OBJECT (window), "delete_event", G_CALLBACK (gtkui_exit), NULL);

   /* group GtkActions together to one group */
   menuactions = gtk_action_group_new("MenuActions");
   gtk_action_group_add_actions(menuactions, menu_items, G_N_ELEMENTS(menu_items), NULL);
   gtk_action_group_add_toggle_actions(menuactions, toggle_items, G_N_ELEMENTS(toggle_items), NULL);

   /* create a new GtkUIManager instance and assing action group */
   menu_manager = gtk_ui_manager_new();
   gtk_ui_manager_insert_action_group(menu_manager, menuactions, 0);

   /* Load the menu structure XML*/
   merge_id = gtk_ui_manager_add_ui_from_string(menu_manager, menu_structure, -1, &error);
   if (error) {
      g_message("building menu failed: %s", error->message);
      g_error_free(error);
      error = NULL;
   }

   /* some hidden accelerators */
   accel_group = gtk_accel_group_new ();

   closure = g_cclosure_new(G_CALLBACK(gtkui_unified_sniff_default), NULL, NULL);
   gtk_accelerator_parse ("u", &keyval, &mods);
   gtk_accel_group_connect(accel_group, keyval, mods, 0, closure);
   
   closure = g_cclosure_new(G_CALLBACK(gtkui_exit), NULL, NULL);
   gtk_accelerator_parse("<control>X", &keyval, &mods);
   gtk_accel_group_connect(accel_group, keyval, mods, 0, closure);

   /* link accelerator groups to window widget */
   gtk_window_add_accel_group (GTK_WINDOW (window), accel_group);
   gtk_window_add_accel_group(GTK_WINDOW(window), gtk_ui_manager_get_accel_group(menu_manager));

   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
   gtk_container_add(GTK_CONTAINER (window), vbox);
   gtk_widget_show(vbox);

   main_menu = gtk_ui_manager_get_widget(menu_manager, "/MenuBar");
   gtk_box_pack_start(GTK_BOX(vbox), main_menu, FALSE, FALSE, 0);
   gtk_widget_show(main_menu);

   if(EC_GBL_PCAP->promisc) {
      /* setting the menu item active will toggle this setting */
      /* it will be TRUE after the menu is updated */
      EC_GBL_PCAP->promisc = 0;
      action = gtk_ui_manager_get_action(menu_manager, "/MenuBar/OptionsMenu/Promisc");
      gtk_toggle_action_set_active(GTK_TOGGLE_ACTION(action), TRUE);
   }

   if(EC_GBL_OPTIONS->unoffensive) {
      EC_GBL_OPTIONS->unoffensive = 0;
      action = gtk_ui_manager_get_action(menu_manager, "/MenuBar/OptionsMenu/Unoffensive");
      gtk_toggle_action_set_active(GTK_TOGGLE_ACTION(action), TRUE);
   }

#if GTK_CHECK_VERSION(3, 0, 0)
   vpaned = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
#else
   vpaned = gtk_vpaned_new();
#endif

   /* notebook for MDI pages */
   notebook_frame = gtk_frame_new(NULL);
   gtk_frame_set_shadow_type(GTK_FRAME (notebook_frame), GTK_SHADOW_IN);
   gtk_paned_pack1(GTK_PANED(vpaned), notebook_frame, TRUE, TRUE);
   gtk_widget_show(notebook_frame);

   path = INSTALL_DATADIR "/" PROGRAM "/" LOGO_FILE;
   if(g_file_test(path, G_FILE_TEST_EXISTS))
      logo = gtk_image_new_from_file(path);
   else /* if neither path is valid gtk will use a broken image icon */
      logo = gtk_image_new_from_file("./share/" LOGO_FILE);

   gtk_misc_set_alignment (GTK_MISC (logo), 0.5, 0.5);
   gtk_container_add(GTK_CONTAINER (notebook_frame), logo);
   gtk_widget_show(logo);

   /* messages */
   scroll = gtk_scrolled_window_new(NULL, NULL);
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW (scroll),
                                  GTK_POLICY_AUTOMATIC, GTK_POLICY_ALWAYS);
   gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW (scroll), GTK_SHADOW_IN);
   gtk_widget_set_size_request(scroll, -1, 140);
   gtk_paned_pack2(GTK_PANED (vpaned), scroll, FALSE, TRUE);
   gtk_widget_show(scroll);

   textview = gtk_text_view_new();
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW (textview), GTK_WRAP_WORD_CHAR);
   gtk_text_view_set_editable(GTK_TEXT_VIEW (textview), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW (textview), FALSE);
   gtk_container_add(GTK_CONTAINER (scroll), textview);
   gtk_widget_show(textview);

   msgbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW (textview));
   gtk_text_buffer_get_end_iter(msgbuffer, &iter);
   endmark = gtk_text_buffer_create_mark(msgbuffer, "end", &iter, FALSE);

   gtk_box_pack_end(GTK_BOX(vbox), vpaned, TRUE, TRUE, 0);
   gtk_widget_show(vpaned);

   gtk_widget_show(window);

   DEBUG_MSG("gtk_setup: end");
}

/*
 * display the file open dialog
 */
static void gtkui_file_open(void)
{
   GtkWidget *dialog;
   gchar *filename;
   int response = 0;

   DEBUG_MSG("gtk_file_open");

   dialog = gtk_file_chooser_dialog_new("Select a pcap file...", 
            GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_OPEN, 
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_OK,
            NULL);

   /* This way the file chooser dialog doesn't start in the recent section */
   gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), "");

   response = gtk_dialog_run (GTK_DIALOG (dialog));

   if (response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
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
static void gtkui_file_write(void)
{
#define FILE_LEN  40
   
   GtkWidget *dialog;
   gchar *filename;
   int response = 0;

   DEBUG_MSG("gtk_file_write");
   
   dialog = gtk_file_chooser_dialog_new("Save traffic in a pcap file...", 
            GTK_WINDOW(window), GTK_FILE_CHOOSER_ACTION_SAVE, 
            GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
            GTK_STOCK_OPEN, GTK_RESPONSE_OK,
            NULL);

   /* This way the file chooser dialog doesn't start in the recent section */
   gtk_file_chooser_set_current_folder(GTK_FILE_CHOOSER(dialog), "");

   response = gtk_dialog_run (GTK_DIALOG (dialog));

   if (response == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);
      filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
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
 * display the interface selection dialog
 */
static void gtkui_unified_sniff(void)
{
   GtkListStore *iface_list;
   GtkTreeIter iter;
   GtkTreeModel *model;
   GtkCellRenderer *cell;
   const char *iface_desc = NULL;
   char err[100];
   GtkWidget *iface_combo;
   pcap_if_t *dev;
   GtkWidget *dialog, *label, *hbox, *vbox, *image, *content_area;

   DEBUG_MSG("gtk_unified_sniff");

   dialog = gtk_dialog_new_with_buttons(PROGRAM" Input", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL, 
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, 
                                        GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        NULL);
#if !GTK_CHECK_VERSION(2, 22, 0) // depricated since Gtk 2.22
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
  
   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 6, FALSE);

   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox);
  
   image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_QUESTION, GTK_ICON_SIZE_DIALOG);
   gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.0);
   gtk_box_pack_start (GTK_BOX (hbox), image, FALSE, FALSE, 0);
  
   label = gtk_label_new ("Network interface : ");
   gtk_label_set_line_wrap (GTK_LABEL (label), TRUE);
   gtk_label_set_selectable (GTK_LABEL (label), TRUE);
   gtk_box_pack_start (GTK_BOX (hbox), label, TRUE, TRUE, 0);

   /* make a list of network interfaces */
   iface_list = gtk_list_store_new(1, G_TYPE_STRING);
   for(dev = (pcap_if_t *)EC_GBL_PCAP->ifs; dev != NULL; dev = dev->next) {
      gtk_list_store_append(iface_list, &iter);
      gtk_list_store_set(iface_list, &iter, 0, dev->description, -1);
   }

   /* make a drop down box and assign the list to it */
   iface_combo = gtk_combo_box_new();
   gtk_combo_box_set_model(GTK_COMBO_BOX(iface_combo), GTK_TREE_MODEL(iface_list));

   g_object_unref(iface_list);

   cell = gtk_cell_renderer_text_new();
   gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(iface_combo), cell, TRUE);
   gtk_cell_layout_set_attributes( GTK_CELL_LAYOUT( iface_combo ), cell, "text", 0, NULL );
   gtk_combo_box_set_active(GTK_COMBO_BOX(iface_combo), 0);

   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
   gtk_box_pack_start(GTK_BOX(vbox), iface_combo, TRUE, FALSE, 0);
   gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

   /* hitting Enter in the drop down box clicks OK */
   g_object_set_data(G_OBJECT(GTK_COMBO_BOX(iface_combo)), "dialog", dialog);
   g_signal_connect(G_OBJECT(GTK_COMBO_BOX(iface_combo)), 
         "key-press-event", G_CALLBACK(gtkui_combo_enter), NULL);

   /* render the contents of the dialog */
   gtk_widget_show_all (hbox);
   /* show the dialog itself and become interactive */
   if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_OK) {

      gtk_combo_box_get_active_iter(GTK_COMBO_BOX(iface_combo), &iter);
      model = gtk_combo_box_get_model(GTK_COMBO_BOX(iface_combo));
      gtk_tree_model_get(model, &iter, 0, &iface_desc, -1);

      for(dev = (pcap_if_t *)EC_GBL_PCAP->ifs; dev != NULL; dev = dev->next) {
         if(!strncmp(dev->description, iface_desc, IFACE_LEN)) {
            
            SAFE_FREE(EC_GBL_OPTIONS->iface);
            SAFE_CALLOC(EC_GBL_OPTIONS->iface, IFACE_LEN, sizeof(char));

            strncpy(EC_GBL_OPTIONS->iface, dev->name, IFACE_LEN);
            break;
         }
      }

      /* if no match in list */
      if(EC_GBL_OPTIONS->iface == NULL) {
         snprintf(err, 100, "Invalid interface: %s", iface_desc);
         gtkui_error(err);
         gtk_widget_destroy(dialog);
         return;
      }

      /* exit setup iterface */
      gtk_widget_destroy(dialog);
      gtk_main_quit();
      return;
   }
   gtk_widget_destroy(dialog);
}

/* 
 * start unified sniffing with default interface
 */
static void gtkui_unified_sniff_default(void) 
{
   
   DEBUG_MSG("gtkui_unified_sniff_default");

   /* the ec_capture will find the interface for us */
   if (EC_GBL_OPTIONS->iface == NULL) {
      char *iface;

      SAFE_CALLOC(EC_GBL_OPTIONS->iface, IFACE_LEN, sizeof(char));
      iface = capture_default_if();
      ON_ERROR(iface, NULL, "No suitable interface found....");
   
      strncpy(EC_GBL_OPTIONS->iface, iface, IFACE_LEN - 1);
   }

   /* close setup interface and start sniffing */
   gtk_main_quit();
}

/*
 * display the interface selection for bridged sniffing
 */
static void gtkui_bridged_sniff(void)
{
   GtkWidget *dialog, *vbox, *hbox, *image, *content_area;
   GtkWidget *hbox_big, *label, *combo1, *combo2;
   GtkListStore *iface_list;
   GtkTreeIter iter;
   GtkTreeModel *model;
   GtkCellRenderer *cell1, *cell2;
   const char *iface_desc = NULL;
   char err[100];
   pcap_if_t *dev;

   DEBUG_MSG("gtk_bridged_sniff");

   dialog = gtk_dialog_new_with_buttons("Bridged Sniffing", GTK_WINDOW (window),
                                        GTK_DIALOG_MODAL, 
                                        GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, 
                                        GTK_STOCK_OK, GTK_RESPONSE_OK,
                                        NULL);
   gtk_container_set_border_width(GTK_CONTAINER (dialog), 5);
#if !GTK_CHECK_VERSION(2, 22, 0) // depricated since Gtk 2.22
   gtk_dialog_set_has_separator(GTK_DIALOG (dialog), FALSE);
#endif

   hbox_big = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 5, FALSE);

   content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
   gtk_container_add(GTK_CONTAINER(content_area), hbox_big);

   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
   image = gtk_image_new_from_stock (GTK_STOCK_DIALOG_QUESTION, GTK_ICON_SIZE_DIALOG);
   gtk_misc_set_alignment (GTK_MISC (image), 0.5, 0.1);
   gtk_box_pack_start (GTK_BOX (vbox), image, TRUE, FALSE, 5);
   gtk_box_pack_start(GTK_BOX(hbox_big), vbox, FALSE, FALSE, 0);

   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 2, FALSE);
   gtk_container_set_border_width(GTK_CONTAINER (vbox), 5);
   gtk_box_pack_start (GTK_BOX (hbox_big), vbox, TRUE, TRUE, 0);

   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
   gtk_box_pack_start(GTK_BOX (vbox), hbox, TRUE, TRUE, 0);

   label = gtk_label_new ("First network interface  : ");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_box_pack_start(GTK_BOX (hbox), label, TRUE, TRUE, 0);

   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
   gtk_box_pack_start(GTK_BOX (vbox), hbox, TRUE, TRUE, 0);

   label = gtk_label_new ("Second network interface : ");
   gtk_misc_set_alignment(GTK_MISC (label), 0, 0.5);
   gtk_box_pack_start(GTK_BOX (hbox), label, TRUE, TRUE, 0);

   vbox = gtkui_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
   gtk_box_pack_start(GTK_BOX(hbox_big), vbox, TRUE, TRUE, 0);

   /* make a list of network interfaces */
   iface_list = gtk_list_store_new(1, G_TYPE_STRING);
   for(dev = (pcap_if_t *)EC_GBL_PCAP->ifs; dev != NULL; dev = dev->next) {
      gtk_list_store_append(iface_list, &iter);
      gtk_list_store_set(iface_list, &iter, 0, dev->description, -1);
   }

   /* make a drop down box and assign the list to it */
   combo1 = gtk_combo_box_new();
   gtk_combo_box_set_model(GTK_COMBO_BOX(combo1), GTK_TREE_MODEL(iface_list));

   cell1 = gtk_cell_renderer_text_new();
   gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo1), cell1, TRUE);
   gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo1), cell1, "text", 0, NULL);

   gtk_box_pack_start (GTK_BOX (vbox), combo1, TRUE, FALSE, 0);
   gtk_combo_box_set_active(GTK_COMBO_BOX(combo1), 0);

   /* make a drop down box and assign the list to it */
   combo2 = gtk_combo_box_new();
   gtk_combo_box_set_model(GTK_COMBO_BOX(combo2), GTK_TREE_MODEL(iface_list));

   cell2 = gtk_cell_renderer_text_new();
   gtk_cell_layout_pack_start(GTK_CELL_LAYOUT(combo2), cell2, TRUE);
   gtk_cell_layout_set_attributes(GTK_CELL_LAYOUT(combo2), cell2, "text", 0, NULL);

   gtk_box_pack_start(GTK_BOX(vbox), combo2, TRUE, FALSE, 0);
   gtk_combo_box_set_active(GTK_COMBO_BOX(combo2), 1);

   g_object_unref(iface_list);

   /* hitting Enter in the drop down box clicks OK */
   gtk_widget_grab_focus(gtk_dialog_get_widget_for_response(GTK_DIALOG(dialog), GTK_RESPONSE_OK));

   gtk_widget_show_all(hbox_big);

   if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_OK) {
      gtk_widget_hide(dialog);

      gtk_combo_box_get_active_iter(GTK_COMBO_BOX(combo1), &iter);
      model = gtk_combo_box_get_model(GTK_COMBO_BOX(combo1));
      gtk_tree_model_get(model, &iter, 0, &iface_desc, -1);
      for(dev = (pcap_if_t *)EC_GBL_PCAP->ifs; dev != NULL; dev = dev->next) {
         if(!strncmp(dev->description, iface_desc, IFACE_LEN)) {
            
            SAFE_FREE(EC_GBL_OPTIONS->iface);
            SAFE_CALLOC(EC_GBL_OPTIONS->iface, IFACE_LEN, sizeof(char));

            strncpy(EC_GBL_OPTIONS->iface, dev->name, IFACE_LEN);
            break;                      
         }                              
      }

      /* if no match in list */
      if(EC_GBL_OPTIONS->iface == NULL) {
         snprintf(err, 100, "Invalid interface: %s", iface_desc);
         gtkui_error(err);
         gtk_widget_destroy(dialog);
         return;
      }

      gtk_combo_box_get_active_iter(GTK_COMBO_BOX(combo2), &iter);
      model = gtk_combo_box_get_model(GTK_COMBO_BOX(combo2));
      gtk_tree_model_get(model, &iter, 0, &iface_desc, -1);

      for(dev = (pcap_if_t *)EC_GBL_PCAP->ifs; dev != NULL; dev = dev->next) {
         if(!strncmp(dev->description, iface_desc, IFACE_LEN)) {
               
            SAFE_FREE(EC_GBL_OPTIONS->iface_bridge);
            SAFE_CALLOC(EC_GBL_OPTIONS->iface_bridge, IFACE_LEN, sizeof(char));

            strncpy(EC_GBL_OPTIONS->iface_bridge, dev->name, IFACE_LEN);
            break;
         }
      }

      /* if no match in list */
      if(EC_GBL_OPTIONS->iface_bridge == NULL) {
         snprintf(err, 100, "Invalid interface: %s", iface_desc);
         gtkui_error(err);
         gtk_widget_destroy(dialog);
         return;
      }

      bridged_sniff();
   }

   gtk_widget_destroy(dialog);
}

static void bridged_sniff(void)
{
   set_bridge_sniff();
   
   /* leaves setup menu, goes to main interface */
   gtk_main_quit();
}

/*
 * display the pcap filter dialog
 */
static void gtkui_pcap_filter(void)
{
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
static void gtkui_set_netmask(void)
{
   struct ip_addr net;
   
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
   hbox = gtkui_box_new(GTK_ORIENTATION_HORIZONTAL, 0, FALSE);
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
   image = gtk_image_new_from_stock (GTK_STOCK_CLOSE, GTK_ICON_SIZE_MENU);
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

      #if GTK_MINOR_VERSION == 2
      g_signal_connect(G_OBJECT (notebook), "switch-page", G_CALLBACK(gtkui_page_defocus_tabs), NULL);
      #endif 

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

#if GTK_MINOR_VERSION == 2
   gtkui_page_defocus_tabs();
#endif
}

/* defocus tab buttons in notebook (gtk bug work-around */
/* GTK+ 2.0 doesn't have gtk_notebook_get_n_pages and this */
/* bug is fixedin 2.4 so only include this when building on 2.2 */
#if GTK_MINOR_VERSION == 2
static void gtkui_page_defocus_tabs(void)
{
   GList *list = NULL, *curr = NULL;
   GtkWidget *contents, *label;
   int pages = 0;

   /* make sure all the close buttons loose focus */
   for(pages = gtk_notebook_get_n_pages(GTK_NOTEBOOK (notebook)); pages > 0; pages--) {
      contents = gtk_notebook_get_nth_page(GTK_NOTEBOOK (notebook), (pages - 1));
      label = gtk_notebook_get_tab_label(GTK_NOTEBOOK (notebook), contents);

      list = gtk_container_get_children(GTK_CONTAINER (label));
      for(curr = list; curr != NULL; curr = curr->next)
         if(GTK_IS_BUTTON (curr->data))
            gtk_button_leave(GTK_BUTTON (curr->data));
   }
}
#endif

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
void gtkui_page_close_current(void) {
   GtkWidget *child;
   gint num = 0;

   num = gtk_notebook_get_current_page(GTK_NOTEBOOK (notebook));
   child = gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook), num);

   gtkui_page_close(NULL, child);
}

/* show the context menu when the notebook tabs receive a mouse right-click */
gboolean gtkui_context_menu(GtkWidget *widget, GdkEventButton *event, gpointer data) {
   /* variable not used */
   (void) widget;

    if(event->button == 3) {
        gtk_menu_popup(GTK_MENU(data), NULL, NULL, NULL, NULL, 3, event->time);
        /* 
         * button press event handle must return TRUE to keep the selection
         * active when pressing the mouse button 
         */
        return TRUE;
    }

    return FALSE;
}

/* detach the currently focused notebook page into a free window */
void gtkui_page_detach_current(void) {
   void (*detacher)(GtkWidget *);
   GtkWidget *child;
   gint num = 0;

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
void gtkui_page_right(void) {
   gtk_notebook_next_page(GTK_NOTEBOOK (notebook));
}

/* change view and focus to previous notebook page */
void gtkui_page_left(void) {
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
         GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
         GTK_STOCK_OK, GTK_RESPONSE_OK, 
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

GtkWidget *gtkui_box_new(gint orientation, gint spacing, gboolean homogenious) 
{
#if GTK_CHECK_VERSION(3, 0, 0)
   (void) homogenious;
   return gtk_box_new(orientation, spacing);
#else
   if (orientation == GTK_ORIENTATION_VERTICAL)
      return gtk_vbox_new(homogenious, spacing);
   else 
      return gtk_hbox_new(homogenious, spacing);

#endif
}

/* EOF */

// vim:ts=3:expandtab

