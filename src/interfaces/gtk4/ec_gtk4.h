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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef ETTERCAP_GTK4_H
#define ETTERCAP_GTK4_H

#include <gtk/gtk.h>
#include <adwaita.h>
#include <glib.h>
#include <glib/gprintf.h>

#define LOGO_FILE "ettercap.png"
#define LOGO_FILE_SMALL "ettercap-small.png"
#define ICON_FILE "ettercap.svg"

/*
 * The application id we register with the session bus under.
 *
 * Underscores, not hyphens: the id doubles as the D-Bus well-known name the
 * application owns, and hyphens are not valid there. The object path GIO
 * derives from it is /org/ettercap_project/Ettercap.
 */
#define EC_GTK4_APP_ID "org.ettercap_project.Ettercap"

struct gtk_conf_entry {
   char *name;
   short value;
};

/*
 * One keyboard shortcut.
 *
 * Under GTK3 this table held only the action and its accelerator, and the
 * shortcuts window was a separate 1372-line file that spelled the same
 * information out again by hand -- so the two could and did drift apart.
 * Here the table is the single source of truth: gtkui_install_accels()
 * feeds it to GtkApplication, and gtkui_show_shortcuts() renders it. Adding
 * a shortcut means adding one row.
 */
typedef struct gtk_accel_map {
   /* detailed action name, e.g. "app.quit" */
   char *action;
   /*
    * NULL terminated accelerator string-array,
    * able to contain up to 2 accelerators per action
    */
   const char * const accel[3];
   /* what the shortcut does, as shown in the shortcuts window */
   const char *title;
   /* which section of the shortcuts window it belongs under */
   const char *group;
} gtkui_accel_map_t;

/*
 * Register a table of accelerators with the application and remember it so
 * the shortcuts window can be generated from it later. Safe to call more
 * than once; ettercap builds a different action set for the startup screen
 * than for the sniffing screen, and both contribute their shortcuts.
 */
extern void gtkui_install_accels(GtkApplication *app,
      const gtkui_accel_map_t *accels, guint n_accels);

/*
 * A host entry as exposed to the list views.
 *
 * GTK4's GtkColumnView binds to a GListModel of GObjects rather than to a
 * GtkListStore of tagged columns, so every list the UI shows now has a
 * corresponding boxed type. Deferred name resolution updates the object's
 * property and the bound row repaints itself -- there is no longer any need
 * to carry a GtkTreeIter around to find the row again.
 */
#define EC_TYPE_HOST_ITEM (ec_host_item_get_type())
G_DECLARE_FINAL_TYPE(EcHostItem, ec_host_item, EC, HOST_ITEM, GObject)

/*
 * Replaces struct resolv_object from the GTK3 interface. Deferred reverse
 * resolution now targets a GObject property instead of a specific widget
 * plus tree iterator, which means the pending resolution stays valid even
 * if the view it feeds is rebuilt or sorted underneath it.
 */
struct resolv_object {
   /* the item whose "name" property gets filled in once resolution lands */
   GObject *item;
   /* the property to write the resolved name into */
   const char *property;
   /* The IP address to resolve */
   struct ip_addr *ip;
};

/* ec_gtk4.c */
extern AdwApplication *etterapp;
extern GtkWidget *window;           /* main AdwApplicationWindow */
extern GtkWidget *notebook;         /* AdwTabView holding the MDI pages */
extern GtkWidget *tabbar;           /* AdwTabBar for the above */
extern GtkWidget *textview;
extern GtkWidget *toastoverlay;     /* AdwToastOverlay, replaces the infobar */
extern GtkTextBuffer *msgbuffer;
extern GtkTextMark *endmark;
extern GTimer *progress_timer;

extern void set_gtk_interface(void);
extern void gtkui_about(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_message(const char *msg);
extern void gtkui_exit(GSimpleAction *action, GVariant *value, gpointer data);

extern void gtkui_sniff_offline(void);
extern void gtkui_sniff_live(void);

extern gboolean gtkui_iptoa_deferred(gpointer data);
extern char *gtkui_utf8_validate(char *data);

/*
 * ec_gtk4_dialogs.c
 *
 * GTK4 removed gtk_dialog_run(): a dialog can no longer block its caller
 * while spinning a nested main loop. Every dialog in this interface is
 * therefore built as
 *
 *    build widgets -> present -> return
 *
 * with the code that used to follow the gtk_dialog_run() call moved into a
 * response callback. The helpers below exist so that transformation is
 * uniform across the ~two dozen dialogs the UI puts up, rather than each
 * one hand-rolling its own async plumbing.
 */

/*
 * Invoked once the user answers a dialog. `confirmed` is TRUE when they
 * accepted (OK/Save/Open) and FALSE when they cancelled or dismissed it.
 * `data` is the caller's context and is released afterwards by the
 * GDestroyNotify handed to the corresponding present function.
 */
typedef void (*gtkui_dialog_cb)(gboolean confirmed, gpointer data);

/*
 * Present a modal OK/Cancel dialog whose body is `child`, and invoke `cb`
 * when it is answered. `heading` may be NULL for a bare dialog. Ownership of
 * `child` passes to the dialog; `data` is released with `destroy` after `cb`
 * returns, so the caller may stash widget pointers in it and read them back
 * from the callback.
 */
extern void gtkui_dialog_confirm(const char *title, const char *heading,
      GtkWidget *child, gtkui_dialog_cb cb, gpointer data,
      GDestroyNotify destroy);

/*
 * Present a purely informational dialog with a single dismiss button.
 * `child` may be NULL when `body` alone suffices.
 */
extern void gtkui_dialog_inform(const char *title, const char *body,
      GtkWidget *child);

/*
 * Prompt for a single line of text.
 *
 * This signature is fixed by struct ui_ops in ec_ui.h -- it is what the
 * core registers as ops.input and what the curses and text interfaces also
 * implement -- so it cannot grow a user-data argument. It was already
 * callback-shaped under GTK3, which makes it the one dialog that needs no
 * restructuring: on acceptance the text is copied into `input` and then
 * `callback` runs, exactly as before.
 */
extern void gtkui_input(const char *title, char *input, size_t n,
      void (*callback)(void));

/*
 * The same prompt, for callers inside this interface that need to carry
 * context through to the answer and to distinguish cancellation from
 * acceptance -- neither of which the ui_ops signature above can express.
 */
extern void gtkui_input_full(const char *title, char *input, size_t n,
      gtkui_dialog_cb cb, gpointer data, GDestroyNotify destroy);

/*
 * Ask for a filename. `save` selects between an open and a save dialog;
 * the chosen path is written into the caller's buffer before `cb` runs.
 */
extern void gtkui_filename_browse(const char *title, gboolean save,
      char *filename, size_t n, gtkui_dialog_cb cb, gpointer data,
      GDestroyNotify destroy);

/*
 * Transient status message shown in the main window's AdwToastOverlay.
 * Replaces the GtkInfoBar the GTK3 interface used (deprecated in GTK4).
 */
extern void gtkui_toast(const char *msg);
extern void gtkui_toast_error(const char *msg);

/* ec_gtk4_menus.c */
extern void gtkui_create_menu(GApplication *app, gpointer data);
extern void gtkui_create_tab_menu(void);

/* MDI pages */
extern GtkWidget *gtkui_page_new(char *title, void (*callback)(void), void (*detacher)(GtkWidget *));
extern void gtkui_page_present(GtkWidget *child);
extern void gtkui_page_close(GtkWidget *widget, gpointer data);
extern void gtkui_page_close_current(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_page_detach_current(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_page_attach_shortcut(GtkWidget *win, void (*attacher)(void));
extern void gtkui_page_right(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_page_left(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk4_start.c */
extern void gtkui_start_sniffing(void);
extern void gtkui_stop_sniffing(void);

/* ec_gtk4_filters.c */
extern void gtkui_load_filter(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_stop_filter(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk4_hosts.c */
#ifdef WITH_IPV6
extern void toggle_ip6scan(GSimpleAction *action, GVariant *value, gpointer data);
#endif
extern void gtkui_scan(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_load_hosts(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_save_hosts(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_host_list(GSimpleAction *action, GVariant *value, gpointer data);
extern gboolean gtkui_refresh_host_list(gpointer data);

/* ec_gtk4_view.c */
extern void gtkui_show_stats(GSimpleAction *action, GVariant *value, gpointer data);
extern void toggle_resolve(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_vis_method(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_vis_regex(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_wifi_key(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk4_targets.c */
extern void toggle_reverse(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_select_protocol(GSimpleAction *action, GVariant *value, gpointer data);
extern void wipe_targets(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_select_targets(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_current_targets(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_create_targets_array(void);

/* ec_gtk4_view_profiles.c */
extern void gtkui_show_profiles(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk4_mitm.c */
extern void gtkui_arp_poisoning(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_icmp_redir(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_port_stealing(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_dhcp_spoofing(GSimpleAction *action, GVariant *value, gpointer data);
#ifdef WITH_IPV6
extern void gtkui_ndp_poisoning(GSimpleAction *action, GVariant *value, gpointer data);
#endif
extern void gtkui_mitm_stop(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk4_redirect.c */
extern void gtkui_sslredir_show(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk4_logging.c */
extern void toggle_compress(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_log_all(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_log_info(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_log_msg(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_stop_log(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_stop_msg(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk4_plugins.c */
extern void gtkui_plugin_mgmt(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_plugin_load(GSimpleAction *action, GVariant *value, gpointer data);
extern gboolean gtkui_refresh_plugin_list(gpointer data);
extern gboolean gtkui_plugins_autostart(gpointer data);

/* ec_gtk4_view_connections.c */
extern void gtkui_show_connections(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk4_conf.c */
extern void gtkui_conf_set(char *name, short value);
extern short gtkui_conf_get(char *name);
extern void gtkui_conf_read(void);
extern void gtkui_conf_save(void);

#ifndef OS_WINDOWS
/* ec_gtk4_help.c */
extern void gtkui_help(GSimpleAction *action, GVariant *value, gpointer data);
#endif

/*
 * The GTK3 interface hand-built its shortcuts window in ec_gtk3_shortcuts.c
 * -- 1372 lines that spell out, widget by widget, information the accel map
 * in ec_gtk4_menus.c already holds. The GTK4 interface generates the window
 * from that map instead, so there is no ec_gtk4_shortcuts.c.
 *
 * On libadwaita >= 1.8 this uses AdwShortcutsDialog; on older runtimes it
 * falls back to GtkShortcutsWindow, which GTK4 still provides (deprecated
 * since 4.18). Both are driven from the same table.
 */
extern void gtkui_show_shortcuts(GSimpleAction *action, GVariant *value, gpointer data);

#endif

/* EOF */

// vim:ts=3:expandtab
