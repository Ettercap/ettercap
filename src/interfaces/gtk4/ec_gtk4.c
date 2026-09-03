/*
    ettercap -- GTK4 + libadwaita GUI

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

#include <ec_gtk4.h>
#include <ec_capture.h>
#include <ec_version.h>

#include <pcap.h>
#include <string.h>

/* globals */

AdwApplication *etterapp = NULL;
GtkWidget *window = NULL;        /* main AdwApplicationWindow */
GtkWidget *notebook = NULL;      /* AdwTabView */
GtkWidget *tabbar = NULL;        /* AdwTabBar */
GtkWidget *textview = NULL;
GtkWidget *toastoverlay = NULL;
GtkTextBuffer *msgbuffer = NULL;
GtkTextMark *endmark = NULL;
GTimer *progress_timer = NULL;

static gboolean    progress_canceled = FALSE;
static AdwDialog  *progress_dialog = NULL;
static GtkWidget  *progress_bar = NULL;

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

static AdwApplication *gtkui_setup(void *activate_func, gpointer data);
static void gtkui_build_widgets(GApplication *app, gpointer data);

static void toggle_unoffensive(GSimpleAction *action, GVariant *value, gpointer data);
static void toggle_nopromisc(GSimpleAction *action, GVariant *value, gpointer data);
static void gtkui_sniff(GtkButton *button, gpointer data);

static void gtkui_file_open(GSimpleAction *action, GVariant *value, gpointer data);
static void gtkui_file_write(GSimpleAction *action, GVariant *value, gpointer data);
static void gtkui_pcap_filter(GSimpleAction *action, GVariant *value, gpointer data);
static void gtkui_set_netmask(GSimpleAction *action, GVariant *value, gpointer data);
static void read_pcapfile(const char *file);
static void write_pcapfile(void);

#define ENABLED "true"
#define DISABLED "false"

/*
 * Wrapper functions which inject the real call into the main idle loop,
 * ensuring only the main thread performs GTK operations.
 *
 * This mattered under GTK3 and matters more under GTK4, which is stricter
 * about being touched from anywhere but the thread that owns the main
 * context: the capture threads call USER_MSG() freely, and every one of
 * those has to be hopped onto the main loop before it reaches a widget.
 */

static gboolean gtkui_cleanup_shim(gpointer data)
{
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
   char *copy;

   if (msg == NULL)
      return;

   copy = strdup(msg);
   if (copy == NULL)
      FATAL_ERROR("out of memory");

   g_idle_add(gtkui_msg_shim, copy);
}

static gboolean gtkui_error_shim(gpointer data)
{
   gtkui_error(data);
   SAFE_FREE(data);
   return FALSE;
}

static void gtkui_error_wrap(const char *msg)
{
   char *copy;

   if (msg == NULL)
      return;

   copy = strdup(msg);
   if (copy == NULL)
      FATAL_ERROR("out of memory");

   g_idle_add(gtkui_error_shim, copy);
}

static void gtkui_fatal_error_wrap(const char *msg)
{
   /*
    * Deliberately not deferred to an idle callback: this call ends with
    * clean_exit(), so there would be no later iteration of the main loop
    * in which to run it.
    */
   gtkui_fatal_error(msg);
}

struct gtkui_progress_data {
   char *title;
   int value;
   int max;
};

static gboolean gtkui_progress_shim(gpointer data)
{
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

static int gtkui_progress_wrap(char *title, int value, int max)
{
   struct gtkui_progress_data *gpd;

   if (value <= 1) {
      g_timer_start(progress_timer);
      progress_canceled = FALSE;
   }

   if (progress_canceled == TRUE)
      return UI_PROGRESS_INTERRUPTED;

   if (!title)
      return UI_PROGRESS_UPDATED;

   gpd = malloc(sizeof *gpd);
   if (gpd == NULL)
      FATAL_ERROR("out of memory");

   gpd->title = strdup(title);
   gpd->value = value;
   gpd->max = max;
   g_idle_add(gtkui_progress_shim, gpd);

   return value == max ? UI_PROGRESS_FINISHED : UI_PROGRESS_UPDATED;
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

   DEBUG_MSG("GTK4 -> gtk4 %d.%d.%d / libadwaita %d.%d.%d\n",
         gtk_get_major_version(), gtk_get_minor_version(),
         gtk_get_micro_version(),
         adw_get_major_version(), adw_get_minor_version(),
         adw_get_micro_version());
}

/*
 * prepare GTK, create the menu/messages window, enter the first loop
 */
static void gtkui_init(void)
{
   DEBUG_MSG("gtkui_init");

   /*
    * GTK4's gtk_init_check() takes no arguments -- argc/argv parsing moved
    * to GApplication, which handles the command line for us.
    */
   if (!gtk_init_check()) {
      FATAL_ERROR("GTK4 failed to initialize. Is a display server running?");
      return;
   }

   adw_init();

   gtkui_conf_read();

   /*
    * Theme preference is an AdwStyleManager concern in libadwaita, not a
    * GtkSettings one. Asking for the dark scheme here is a preference, not
    * a demand: AdwStyleManager still honours the system setting when the
    * user has not expressed one.
    */
   if (EC_GBL_CONF->gtkui_prefer_dark_theme)
      adw_style_manager_set_color_scheme(adw_style_manager_get_default(),
            ADW_COLOR_SCHEME_PREFER_DARK);

   etterapp = gtkui_setup(gtkui_build_widgets, NULL);

   /* initialize timer */
   progress_timer = g_timer_new();

   /*
    * gui init loop; calling gtkui_sniff (--> g_application_quit) will cause
    * this to exit so we can proceed to the main loop later.
    */
   g_application_run(G_APPLICATION(etterapp), 0, NULL);
   g_object_unref(G_OBJECT(etterapp));

   EC_GBL_UI->initialized = 1;
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

static AdwApplication *gtkui_setup(void *activate_func, gpointer data)
{
   AdwApplication *app;

   DEBUG_MSG("gtkui_setup");

   /*
    * Default flags (single instance, owns the bus name), matching the GTK3
    * interface. ettercap runs its application object twice -- once for the
    * setup screen, once for the sniffing UI -- but sequentially: the first
    * quits and is unref'd before the second starts, so the second registers
    * cleanly rather than handing off.
    *
    * Owning the bus name is what exports the app's GActions on the session
    * bus, which is both the standard desktop behaviour and what lets the
    * test harness drive actions over D-Bus.
    */
   app = ADW_APPLICATION(adw_application_new(EC_GTK4_APP_ID,
            G_APPLICATION_DEFAULT_FLAGS));
   g_signal_connect(app, "activate", G_CALLBACK(activate_func), data);

   return app;
}

static void toggle_unoffensive(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   (void) data;

   g_simple_action_set_state(action, value);

   EC_GBL_OPTIONS->unoffensive ^= 1;
}

static void toggle_nopromisc(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   (void) data;

   g_simple_action_set_state(action, value);

   EC_GBL_PCAP->promisc ^= 1;
}

/*
 * Leave the setup screen and proceed to the sniffing UI.
 *
 * g_application_quit() ends the first g_application_run() in gtkui_init();
 * the core then calls gtkui_start(), which builds the second application.
 */
static void gtkui_sniff(GtkButton *button, gpointer data)
{
   (void) button;
   (void) data;

   g_application_quit(G_APPLICATION(etterapp));
}

/*******************************************/

/*
 * The about dialog.
 *
 * The GTK3 version hand-built this out of a GtkDialog, a GtkStack, a
 * GtkStackSwitcher and a GtkTextView, then loaded and paginated the LICENSE
 * file itself -- roughly 130 lines. AdwAboutDialog already is that widget,
 * including the licence page, the credits page and the "copy to clipboard"
 * troubleshooting section, so this is mostly a matter of handing it the
 * right strings.
 */
void gtkui_about(GSimpleAction *action, GVariant *value, gpointer data)
{
   AdwDialog *dialog;
   const char *authors[] = {"ALoR <alor@users.sourceforge.net>",
                            "NaGA <crwm@freemail.it>", NULL};

   (void) action;
   (void) value;
   (void) data;

   dialog = adw_about_dialog_new();

   adw_about_dialog_set_application_name(ADW_ABOUT_DIALOG(dialog), PROGRAM);
   adw_about_dialog_set_application_icon(ADW_ABOUT_DIALOG(dialog),
         EC_GTK4_APP_ID);
   adw_about_dialog_set_version(ADW_ABOUT_DIALOG(dialog), EC_VERSION);
   adw_about_dialog_set_comments(ADW_ABOUT_DIALOG(dialog),
         "A comprehensive suite for man in the middle attacks");
   adw_about_dialog_set_website(ADW_ABOUT_DIALOG(dialog),
         "https://www.ettercap-project.org");
   adw_about_dialog_set_issue_url(ADW_ABOUT_DIALOG(dialog),
         "https://github.com/Ettercap/ettercap/issues");
   adw_about_dialog_set_license_type(ADW_ABOUT_DIALOG(dialog),
         GTK_LICENSE_GPL_2_0);
   adw_about_dialog_set_developers(ADW_ABOUT_DIALOG(dialog), authors);
   /*
    * The copyright is rendered as Pango markup, so the bare '&' in the
    * author string is an invalid entity ("Failed to set text" at runtime)
    * and has to be escaped.
    */
   adw_about_dialog_set_copyright(ADW_ABOUT_DIALOG(dialog),
         "Copyright \xc2\xa9 ALoR &amp; NaGA");

   adw_dialog_present(dialog, window);
}

/*******************************************/

/*
 * PCAP file selection.
 *
 * Worth comparing against the GTK3 original, which carried this comment:
 *
 *   "destroy needs to come before read_pcapfile so gtk_main_quit can reside
 *    inside read_pcapfile, which is why destroy is here twice and not after
 *    the if() block"
 *
 * That ordering constraint existed only because gtk_dialog_run() had a
 * nested main loop that read_pcapfile() then quit out from under it. With
 * the answer arriving in a callback there is no nested loop, no destroy to
 * sequence, and no duplicated teardown.
 */

static char pcap_filename[PATH_MAX];

static void on_file_open(gboolean confirmed, gpointer data)
{
   (void) data;

   if (confirmed)
      read_pcapfile(pcap_filename);
}

static void gtkui_file_open(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_file_open");

   pcap_filename[0] = '\0';
   gtkui_filename_browse("Select a PCAP file for offline sniffing...", FALSE,
         pcap_filename, sizeof(pcap_filename), on_file_open, NULL, NULL);
}

static void read_pcapfile(const char *file)
{
   char pcap_errbuf[PCAP_ERRBUF_SIZE];

   DEBUG_MSG("read_pcapfile %s", file);

   SAFE_CALLOC(EC_GBL_OPTIONS->pcapfile_in, strlen(file) + 1, sizeof(char));
   snprintf(EC_GBL_OPTIONS->pcapfile_in, strlen(file) + 1, "%s", file);

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

   /*
    * GTK4 has no gtk_main_quit(); leaving the setup screen means ending the
    * application's run loop, which is what the GTK3 code was really doing.
    */
   g_application_quit(G_APPLICATION(etterapp));
}

static void on_file_write(gboolean confirmed, gpointer data)
{
   (void) data;

   if (!confirmed)
      return;

   EC_GBL_OPTIONS->pcapfile_out = strdup(pcap_filename);
   write_pcapfile();
}

static void gtkui_file_write(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtk_file_write");

   pcap_filename[0] = '\0';
   gtkui_filename_browse("Save traffic in a PCAP file...", TRUE,
         pcap_filename, sizeof(pcap_filename), on_file_write, NULL, NULL);
}

static void write_pcapfile(void)
{
   FILE *f;

   DEBUG_MSG("write_pcapfile");

   /* check if the file is writeable */
   f = fopen(EC_GBL_OPTIONS->pcapfile_out, "w");
   if (f == NULL) {
      ui_error("Cannot write %s", EC_GBL_OPTIONS->pcapfile_out);
      SAFE_FREE(EC_GBL_OPTIONS->pcapfile_out);
      return;
   }

   /* if ok, delete it */
   fclose(f);
   unlink(EC_GBL_OPTIONS->pcapfile_out);

   /* set the options for writing to a file */
   EC_GBL_OPTIONS->write = 1;
}

/*
 * Text prompts. Both were gtk_dialog_run() calls under GTK3; both are
 * expressible directly with the ui_ops-shaped gtkui_input(), whose
 * completion callback was always asynchronous in spirit.
 */

/*
 * The GTK3 version did its sanity check on the line after gtkui_input()
 * returned, which only worked because gtk_dialog_run() had already blocked
 * until the user answered. Here the check has to live in the callback --
 * on return from gtkui_input() the user has not typed anything yet.
 */
static void set_netmask_cb(void)
{
   struct ip_addr net;

   /* if no netmask was specified, free it */
   if (!strcmp(EC_GBL_OPTIONS->netmask, "")) {
      SAFE_FREE(EC_GBL_OPTIONS->netmask);
      return;
   }

   if (ip_addr_pton(EC_GBL_OPTIONS->netmask, &net) != E_SUCCESS)
      ui_error("Invalid netmask %s", EC_GBL_OPTIONS->netmask);
}

static void gtkui_set_netmask(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtkui_set_netmask");

   if (EC_GBL_OPTIONS->netmask == NULL)
      SAFE_CALLOC(EC_GBL_OPTIONS->netmask, IP_ASCII_ADDR_LEN, sizeof(char));

   gtkui_input("Netmask :", EC_GBL_OPTIONS->netmask, IP_ASCII_ADDR_LEN,
         set_netmask_cb);
}

static void gtkui_pcap_filter(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

#define PCAP_FILTER_LEN  50

   DEBUG_MSG("gtkui_pcap_filter");

   if (EC_GBL_PCAP->filter == NULL)
      SAFE_CALLOC(EC_GBL_PCAP->filter, PCAP_FILTER_LEN, sizeof(char));

   /*
    * no callback: the filter is set in place and we return to the
    * interface for other user input
    */
   gtkui_input("Pcap filter :", EC_GBL_PCAP->filter, PCAP_FILTER_LEN, NULL);
}

/*******************************************/

/*
 * activate callback for the application: build the setup window
 */
static void gtkui_build_widgets(GApplication *app, gpointer data)
{
   GtkWidget *toolbar, *header, *menubutton, *content, *scroll;
   GtkWidget *button;
   GMenu *appmenu;
   gint width, height;

   (void) data;

   /*
    * The single source of truth for these shortcuts -- see
    * gtkui_show_shortcuts(), which renders the shortcuts window straight
    * from this table rather than from a separate hand-written copy.
    */
   static gtkui_accel_map_t accels[] = {
      {"app.pcap_filter", {"<Primary>p", NULL},
         "Set a pcap filter", "Capture"},
      {"app.set_netmask", {"<Primary>n", NULL},
         "Set the netmask", "Capture"},
      {"app.open", {"<Primary>o", NULL},
         "Open a pcap file", "File"},
      {"app.save", {"<Primary>s", NULL},
         "Save to a pcap file", "File"},
#ifndef OS_WINDOWS
      {"app.help", {"F1", NULL}, "Show the manual page", "General"},
#endif
      {"app.shortcuts", {"<Primary>question", NULL},
         "Show keyboard shortcuts", "General"},
      {"app.quit", {"<Primary>q", "<Primary>x", NULL},
         "Quit ettercap", "General"}
   };

   static GActionEntry action_entries[] = {
      {"set_promisc",     NULL, NULL, ENABLED,  toggle_nopromisc, {}},
      {"set_unoffensive", NULL, NULL, DISABLED, toggle_unoffensive, {}},
      {"open",      gtkui_file_open,      NULL, NULL, NULL, {}},
      {"save",      gtkui_file_write,     NULL, NULL, NULL, {}},
      {"about",     gtkui_about,          NULL, NULL, NULL, {}},
      {"shortcuts", gtkui_show_shortcuts, NULL, NULL, NULL, {}},
#ifndef OS_WINDOWS
      {"help",      gtkui_help,           NULL, NULL, NULL, {}},
#endif
      {"quit",        gtkui_exit,        NULL, NULL, NULL, {}},
      {"pcap_filter", gtkui_pcap_filter, NULL, NULL, NULL, {}},
      {"set_netmask", gtkui_set_netmask, NULL, NULL, NULL, {}}
   };

   DEBUG_MSG("gtkui_build_widgets (activate method)");

   /* honor CLI options */
   if (!EC_GBL_PCAP->promisc)
      action_entries[0].state = DISABLED;

   if (EC_GBL_OPTIONS->unoffensive)
      action_entries[1].state = ENABLED;

   g_action_map_add_action_entries(G_ACTION_MAP(app), action_entries,
         G_N_ELEMENTS(action_entries), app);

   gtkui_install_accels(GTK_APPLICATION(app), accels, G_N_ELEMENTS(accels));

   /*
    * AdwApplicationWindow has no separate titlebar slot the way GtkWindow
    * did -- the header bar is part of the content, held by an
    * AdwToolbarView. That is what gives the flat, GNOME-native look and
    * what makes the header bar collapse correctly on narrow widths.
    */
   window = adw_application_window_new(GTK_APPLICATION(app));
   gtk_window_set_title(GTK_WINDOW(window), PROGRAM " " EC_VERSION);

   width = gtkui_conf_get("window_width");
   height = gtkui_conf_get("window_height");
   gtk_window_set_default_size(GTK_WINDOW(window),
         width > 0 ? width : 900, height > 0 ? height : 600);

   header = adw_header_bar_new();

   appmenu = g_menu_new();
   g_menu_append(appmenu, "_Open PCAP", "app.open");
   g_menu_append(appmenu, "_Save PCAP", "app.save");
#ifndef OS_WINDOWS
   g_menu_append(appmenu, "_Help", "app.help");
#endif
   g_menu_append(appmenu, "_Keyboard Shortcuts", "app.shortcuts");
   g_menu_append(appmenu, "_About", "app.about");
   g_menu_append(appmenu, "_Quit", "app.quit");

   menubutton = gtk_menu_button_new();
   gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(menubutton), "open-menu-symbolic");
   gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(menubutton),
         G_MENU_MODEL(appmenu));
   adw_header_bar_pack_end(ADW_HEADER_BAR(header), menubutton);

   button = gtk_button_new_with_mnemonic("_Accept");
   gtk_widget_add_css_class(button, "suggested-action");
   g_signal_connect(button, "clicked", G_CALLBACK(gtkui_sniff), NULL);
   adw_header_bar_pack_start(ADW_HEADER_BAR(header), button);

   /*
    * The message log. Everything USER_MSG() produces lands here, which
    * makes it the first thing worth having on screen -- the setup screen's
    * interface picker is built on top of it as the port proceeds.
    */
   textview = gtk_text_view_new();
   gtk_text_view_set_editable(GTK_TEXT_VIEW(textview), FALSE);
   gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(textview), FALSE);
   gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(textview), GTK_WRAP_WORD_CHAR);
   gtk_text_view_set_monospace(GTK_TEXT_VIEW(textview), TRUE);

   msgbuffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(textview));
   {
      GtkTextIter iter;

      gtk_text_buffer_get_end_iter(msgbuffer, &iter);
      endmark = gtk_text_buffer_create_mark(msgbuffer, "end", &iter, FALSE);
   }

   scroll = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll),
         GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), textview);
   gtk_widget_set_vexpand(scroll, TRUE);

   toastoverlay = adw_toast_overlay_new();
   adw_toast_overlay_set_child(ADW_TOAST_OVERLAY(toastoverlay), scroll);

   toolbar = adw_toolbar_view_new();
   adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
   adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), toastoverlay);

   content = toolbar;
   adw_application_window_set_content(ADW_APPLICATION_WINDOW(window), content);

   gtk_window_present(GTK_WINDOW(window));
}

/*
 * exit ettercap
 */
void gtkui_exit(GSimpleAction *action, GVariant *value, gpointer data)
{
   int width, height;

   (void) action;
   (void) value;
   (void) data;

   DEBUG_MSG("gtkui_exit");

   g_timer_destroy(progress_timer);

   /*
    * GTK4 has no gtk_window_get_position(): a client cannot know where the
    * compositor put it, and under Wayland it cannot ask to be put anywhere
    * either. So only the size is worth persisting now -- the stored
    * window_left/window_top keys are left alone rather than removed, so
    * that a config file written here still works if the user goes back to
    * a GTK3 build.
    */
   gtk_window_get_default_size(GTK_WINDOW(window), &width, &height);
   gtkui_conf_set("window_width", width);
   gtkui_conf_set("window_height", height);

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

   if ((unicode = gtkui_utf8_validate((char *)msg)) == NULL)
      return;

   if (msgbuffer == NULL)
      return;

   gtk_text_buffer_get_end_iter(msgbuffer, &iter);
   gtk_text_buffer_insert(msgbuffer, &iter, unicode, -1);
   gtk_text_view_scroll_to_mark(GTK_TEXT_VIEW(textview),
         endmark, 0, FALSE, 0, 0);
}

/* flush pending messages */
static gboolean gtkui_flush_msg(gpointer data)
{
   (void) data;

   ui_msg_flush(MSG_ALL);

   return TRUE;
}

/*
 * Display a message to the user.
 *
 * Under GTK3 this drove a GtkInfoBar that had to be shown, hidden, and
 * expired on a timer by hand. AdwToast does all of that itself.
 */
void gtkui_message(const char *msg)
{
   gtkui_toast(msg);
}

static void gtkui_error(const char *msg)
{
   gchar *unicode = NULL;

   DEBUG_MSG("gtkui_error: %s", msg);

   if ((unicode = gtkui_utf8_validate((char *)msg)) == NULL)
      return;

   gtkui_toast_error(unicode);
}

/*
 * handle a fatal error and exit
 */
static void gtkui_fatal_error(const char *msg)
{
   /*
    * A toast is useless here -- it needs a main loop iteration to render
    * and this function does not return to one. Present it as a blocking
    * dialog only if there is still a window to hang it off; otherwise the
    * console message below is all the user gets, which is also what
    * happens when ettercap dies before the UI exists.
    */
   if (window != NULL)
      gtkui_dialog_inform("Fatal error", msg, NULL);

   /* also dump it to console in case ettercap was started in an xterm */
   fprintf(stderr, "FATAL ERROR: %s\n\n\n", msg);

   clean_exit(-1);
}

/*
 * Progress reporting.
 *
 * The GTK3 version put this in a GtkDialog and relied on the caller
 * continuing to pump the main loop. AdwDialog is presented and dismissed
 * the same way, but note there is no gtk_dialog_run() equivalent -- the
 * progress dialog is purely advisory and the work continues regardless of
 * whether the user is looking at it.
 */
static void on_progress_closed(AdwDialog *dialog, gpointer data)
{
   (void) dialog;
   (void) data;

   /*
    * The dialog is gone; make sure we do not touch its children again, and
    * tell the producer to stop via the return value of the next
    * gtkui_progress_wrap() call.
    */
   progress_canceled = TRUE;
   progress_dialog = NULL;
   progress_bar = NULL;
}

static void gtkui_progress(char *title, int value, int max)
{
   GtkWidget *box;
   GtkWidget *label;

   if (progress_dialog == NULL) {
      box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
      gtk_widget_set_margin_top(box, 12);
      gtk_widget_set_margin_bottom(box, 12);
      gtk_widget_set_margin_start(box, 12);
      gtk_widget_set_margin_end(box, 12);

      label = gtk_label_new(title);
      gtk_label_set_wrap(GTK_LABEL(label), TRUE);
      gtk_box_append(GTK_BOX(box), label);

      progress_bar = gtk_progress_bar_new();
      gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(progress_bar), TRUE);
      gtk_box_append(GTK_BOX(box), progress_bar);

      progress_dialog = ADW_DIALOG(adw_alert_dialog_new(title, NULL));
      adw_alert_dialog_set_extra_child(ADW_ALERT_DIALOG(progress_dialog), box);
      adw_alert_dialog_add_response(ADW_ALERT_DIALOG(progress_dialog),
            "cancel", "_Cancel");
      adw_alert_dialog_set_close_response(ADW_ALERT_DIALOG(progress_dialog),
            "cancel");
      g_signal_connect(progress_dialog, "closed",
            G_CALLBACK(on_progress_closed), NULL);

      adw_dialog_present(progress_dialog, window);
   }

   if (progress_bar != NULL)
      gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(progress_bar),
            max > 0 ? (gdouble)value / (gdouble)max : 0.0);

   /* the work is done -- take the dialog away */
   if (value == max && progress_dialog != NULL) {
      adw_dialog_close(progress_dialog);
      progress_dialog = NULL;
      progress_bar = NULL;
   }
}

/*******************************************/

/*
 * Accelerator registration.
 *
 * Keeping the registered tables around is what lets gtkui_show_shortcuts()
 * render the shortcuts window without a second, hand-maintained copy of the
 * same information. The tables are static storage owned by their callers,
 * so this only records where they are.
 */
struct accel_table {
   const gtkui_accel_map_t *accels;
   guint n_accels;
};

static GSList *accel_tables = NULL;

void gtkui_install_accels(GtkApplication *app,
      const gtkui_accel_map_t *accels, guint n_accels)
{
   struct accel_table *table;
   guint i;

   for (i = 0; i < n_accels; i++)
      gtk_application_set_accels_for_action(app, accels[i].action,
            (const char * const *)accels[i].accel);

   SAFE_CALLOC(table, 1, sizeof(struct accel_table));
   table->accels = accels;
   table->n_accels = n_accels;

   accel_tables = g_slist_append(accel_tables, table);
}

/*
 * Build the shortcuts window from the registered accelerator tables.
 *
 * This replaces ec_gtk3_shortcuts.c entirely. That file described the same
 * shortcuts a second time in GtkShortcutsWindow markup, which meant every
 * new accelerator had to be added in two places and, predictably, some were
 * not. Generating it means the window cannot disagree with the keys that
 * are actually bound.
 */
void gtkui_show_shortcuts(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   GHashTable *groups;
   GHashTableIter groupiter;
   GSList *elem;
   gpointer key, val;
   guint i;

   (void) action;
   (void) value;
   (void) data;

   /*
    * Bucket the flattened tables by group name, preserving the order the
    * groups were first seen so the window reads in the order the menus do.
    */
   groups = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
         (GDestroyNotify)g_ptr_array_unref);

   for (elem = accel_tables; elem != NULL; elem = elem->next) {
      struct accel_table *table = elem->data;

      for (i = 0; i < table->n_accels; i++) {
         const gtkui_accel_map_t *entry = &table->accels[i];
         GPtrArray *bucket;
         const char *group;

         /* a shortcut with no title is not something to show a user */
         if (entry->title == NULL)
            continue;

         group = entry->group != NULL ? entry->group : "General";
         bucket = g_hash_table_lookup(groups, group);
         if (bucket == NULL) {
            bucket = g_ptr_array_new();
            g_hash_table_insert(groups, (gpointer)group, bucket);
         }
         g_ptr_array_add(bucket, (gpointer)entry);
      }
   }

#if ADW_CHECK_VERSION(1, 8, 0)
   AdwDialog *dialog = adw_shortcuts_dialog_new();

   g_hash_table_iter_init(&groupiter, groups);
   while (g_hash_table_iter_next(&groupiter, &key, &val)) {
      GPtrArray *bucket = val;
      AdwShortcutsSection *section = adw_shortcuts_section_new(key);

      for (i = 0; i < bucket->len; i++) {
         const gtkui_accel_map_t *entry = g_ptr_array_index(bucket, i);

         adw_shortcuts_section_add(section,
               adw_shortcuts_item_new(entry->title, entry->accel[0]));
      }
      adw_shortcuts_dialog_add(ADW_SHORTCUTS_DIALOG(dialog), section);
   }

   adw_dialog_present(dialog, window);
#else
   /*
    * libadwaita < 1.8 has no AdwShortcutsDialog. Rather than fall back to
    * GtkShortcutsWindow -- deprecated, notoriously fiddly, and whose
    * programmatic build API only appeared in GTK 4.18 -- lay the same table
    * out by hand in an AdwDialog: a heading per group, then one row per
    * shortcut with its title and a right-aligned accelerator. This depends
    * on nothing past AdwDialog (1.5) and any GTK4, so it presents reliably
    * everywhere the >= 1.8 path does not.
    */
   AdwDialog *dialog;
   GtkWidget *toolbar, *header, *scrolled, *box;

   box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
   gtk_widget_set_margin_top(box, 12);
   gtk_widget_set_margin_bottom(box, 12);
   gtk_widget_set_margin_start(box, 12);
   gtk_widget_set_margin_end(box, 12);

   g_hash_table_iter_init(&groupiter, groups);
   while (g_hash_table_iter_next(&groupiter, &key, &val)) {
      GPtrArray *bucket = val;
      GtkWidget *heading;
      GtkWidget *grid;
      char *markup;
      int row = 0;

      heading = gtk_label_new(NULL);
      markup = g_markup_printf_escaped("<span weight=\"bold\">%s</span>",
            (const char *)key);
      gtk_label_set_markup(GTK_LABEL(heading), markup);
      gtk_widget_set_halign(heading, GTK_ALIGN_START);
      g_free(markup);
      gtk_box_append(GTK_BOX(box), heading);

      grid = gtk_grid_new();
      gtk_grid_set_row_spacing(GTK_GRID(grid), 4);
      gtk_grid_set_column_spacing(GTK_GRID(grid), 24);

      for (i = 0; i < bucket->len; i++) {
         const gtkui_accel_map_t *entry = g_ptr_array_index(bucket, i);
         GtkWidget *title = gtk_label_new(entry->title);
         GtkWidget *accel;
         guint keyval = 0;
         GdkModifierType mods = 0;
         char *label;

         /*
          * accel[0] is the raw form ("<Primary>q"); parse it to the
          * platform label ("Ctrl+Q") so the fallback reads like the
          * AdwShortcutsDialog path rather than showing markup.
          */
         gtk_accelerator_parse(entry->accel[0], &keyval, &mods);
         label = gtk_accelerator_get_label(keyval, mods);
         accel = gtk_label_new(label != NULL ? label : entry->accel[0]);
         g_free(label);

         gtk_widget_set_halign(title, GTK_ALIGN_START);
         gtk_widget_set_hexpand(title, TRUE);
         gtk_widget_set_halign(accel, GTK_ALIGN_END);
         gtk_widget_add_css_class(accel, "dim-label");

         gtk_grid_attach(GTK_GRID(grid), title, 0, row, 1, 1);
         gtk_grid_attach(GTK_GRID(grid), accel, 1, row, 1, 1);
         row++;
      }

      gtk_box_append(GTK_BOX(box), grid);
   }

   scrolled = gtk_scrolled_window_new();
   gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled),
         GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
   gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), box);
   gtk_widget_set_vexpand(scrolled, TRUE);

   header = adw_header_bar_new();
   adw_header_bar_set_title_widget(ADW_HEADER_BAR(header),
         adw_window_title_new("Keyboard Shortcuts", NULL));

   toolbar = adw_toolbar_view_new();
   adw_toolbar_view_add_top_bar(ADW_TOOLBAR_VIEW(toolbar), header);
   adw_toolbar_view_set_content(ADW_TOOLBAR_VIEW(toolbar), scrolled);

   dialog = adw_dialog_new();
   adw_dialog_set_title(dialog, "Keyboard Shortcuts");
   adw_dialog_set_content_width(dialog, 450);
   adw_dialog_set_content_height(dialog, 500);
   adw_dialog_set_child(dialog, toolbar);

   adw_dialog_present(dialog, window);
#endif

   g_hash_table_destroy(groups);
}

/*******************************************/

/*******************************************/

/*
 * MDI pages.
 *
 * GtkNotebook is still available in GTK4, but AdwTabView is the better fit
 * here: ettercap's pages are user-closable and reorderable, which
 * GtkNotebook only does with a pile of manual signal work, and AdwTabView
 * carries the close button, the drag-to-reorder and the overview for free.
 *
 * The page's own callback and detacher are attached to the AdwTabPage as
 * object data rather than tracked in a parallel list, so a page cannot
 * outlive its handlers or be looked up after it is gone.
 */

GtkWidget *gtkui_page_new(char *title, void (*callback)(void),
      void (*detacher)(GtkWidget *))
{
   GtkWidget *content;
   AdwTabPage *page;

   content = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);

   page = adw_tab_view_append(ADW_TAB_VIEW(notebook), content);
   adw_tab_page_set_title(page, title);

   g_object_set_data(G_OBJECT(content), "callback", callback);
   g_object_set_data(G_OBJECT(content), "detacher", detacher);
   g_object_set_data(G_OBJECT(content), "page", page);

   adw_tab_view_set_selected_page(ADW_TAB_VIEW(notebook), page);

   return content;
}

void gtkui_page_present(GtkWidget *child)
{
   AdwTabPage *page = g_object_get_data(G_OBJECT(child), "page");

   if (page != NULL)
      adw_tab_view_set_selected_page(ADW_TAB_VIEW(notebook), page);
}

void gtkui_page_close(GtkWidget *widget, gpointer data)
{
   AdwTabPage *page;

   (void) data;

   page = g_object_get_data(G_OBJECT(widget), "page");
   if (page != NULL)
      adw_tab_view_close_page(ADW_TAB_VIEW(notebook), page);
}

void gtkui_page_close_current(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   AdwTabPage *page;

   (void) action;
   (void) value;
   (void) data;

   page = adw_tab_view_get_selected_page(ADW_TAB_VIEW(notebook));
   if (page != NULL)
      adw_tab_view_close_page(ADW_TAB_VIEW(notebook), page);
}

void gtkui_page_detach_current(GSimpleAction *action, GVariant *value,
      gpointer data)
{
   AdwTabPage *page;
   GtkWidget *content;
   void (*detacher)(GtkWidget *);

   (void) action;
   (void) value;
   (void) data;

   page = adw_tab_view_get_selected_page(ADW_TAB_VIEW(notebook));
   if (page == NULL)
      return;

   content = adw_tab_page_get_child(page);
   detacher = g_object_get_data(G_OBJECT(content), "detacher");
   if (detacher == NULL)
      return;

   /*
    * Hand the content to the detacher before removing the page: the
    * detacher reparents it into a window of its own, and a page removed
    * first would have dropped the last reference to it.
    */
   g_object_ref(content);
   adw_tab_view_close_page(ADW_TAB_VIEW(notebook), page);
   detacher(content);
   g_object_unref(content);
}

void gtkui_page_attach_shortcut(GtkWidget *win, void (*attacher)(void))
{
   GtkEventController *controller;
   GSimpleActionGroup *group;
   GSimpleAction *action;

   /*
    * GTK4 has no GtkAccelGroup: accelerators are event controllers now.
    * A shortcut controller scoped to the detached window keeps the binding
    * local to it, which is what the GTK3 per-window accel group did.
    *
    * The attacher takes no arguments, so its action is connected swapped --
    * the GAction and parameter are ignored. (Casting attacher straight into
    * a GActionEntry.activate slot would be undefined behaviour.)
    */
   group = g_simple_action_group_new();
   action = g_simple_action_new("attach", NULL);
   g_signal_connect_swapped(action, "activate", G_CALLBACK(attacher), NULL);
   g_action_map_add_action(G_ACTION_MAP(group), G_ACTION(action));
   g_object_unref(action);
   gtk_widget_insert_action_group(win, "page", G_ACTION_GROUP(group));
   g_object_unref(group);

   /* Ctrl+D, matching the GTK3 accel group this replaces */
   controller = gtk_shortcut_controller_new();
   gtk_shortcut_controller_set_scope(GTK_SHORTCUT_CONTROLLER(controller),
         GTK_SHORTCUT_SCOPE_GLOBAL);
   gtk_shortcut_controller_add_shortcut(GTK_SHORTCUT_CONTROLLER(controller),
         gtk_shortcut_new(gtk_keyval_trigger_new(GDK_KEY_d, GDK_CONTROL_MASK),
            gtk_named_action_new("page.attach")));
   gtk_widget_add_controller(win, controller);

   g_object_unref(group);
}

void gtkui_page_right(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   adw_tab_view_select_next_page(ADW_TAB_VIEW(notebook));
}

void gtkui_page_left(GSimpleAction *action, GVariant *value, gpointer data)
{
   (void) action;
   (void) value;
   (void) data;

   adw_tab_view_select_previous_page(ADW_TAB_VIEW(notebook));
}

/*******************************************/

/*
 * Deferred reverse name resolution.
 *
 * Retried on a timer until the resolver cache has an answer, then written
 * into the target object's property -- whatever is bound to that property
 * repaints itself.
 *
 * This is safer than the GTK3 version it replaces, which held a
 * GtkTreeIter into a GtkListStore. An iter is not a reference: if the user
 * deleted the host (or the list was rebuilt by a rescan) while resolution
 * was still pending, the pending timer wrote through a stale iter. Holding
 * a reference to the item makes that impossible -- the object simply stays
 * alive until the timer lets go of it.
 */
gboolean gtkui_iptoa_deferred(gpointer data)
{
   struct resolv_object *ro = data;
   char name[MAX_HOSTNAME_LEN];

   DEBUG_MSG("gtkui_iptoa_deferred");

   if (host_iptoa(ro->ip, name) != E_SUCCESS) {
      /* keep trying */
      return TRUE;
   }

   g_object_set(ro->item, ro->property, name, NULL);

   g_object_unref(ro->item);
   SAFE_FREE(ro);

   /* destroy the timer */
   return FALSE;
}

/*
 * validate a string against UTF-8, returning a printable version of it
 */
char *gtkui_utf8_validate(char *data)
{
   const gchar *end;
   static gchar *unicode = NULL;

   if (data == NULL)
      return NULL;

   if (unicode != NULL)
      g_free(unicode);

   unicode = g_locale_to_utf8(data, -1, NULL, NULL, NULL);
   if (unicode == NULL)
      unicode = g_strdup(data);

   /*
    * a stray invalid byte should not cost the whole message; truncate at
    * the first one rather than dropping the string
    */
   if (!g_utf8_validate(unicode, -1, &end))
      unicode[end - unicode] = '\0';

   return unicode;
}

/* EOF */

// vim:ts=3:expandtab
