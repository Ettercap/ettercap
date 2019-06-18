#ifndef ETTERCAP_GTK_H
#define ETTERCAP_GTK_H
#define G_DISABLE_CONST_RETURNS
#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#include <glib.h>
#include <glib/gprintf.h>

#define LOGO_FILE "ettercap.png"
#define LOGO_FILE_SMALL "ettercap-small.png"
#define ICON_FILE "ettercap.svg"

#ifndef GTK_WRAP_WORD_CHAR
#define GTK_WRAP_WORD_CHAR GTK_WRAP_WORD
#endif

struct gtk_conf_entry {
   char *name;
   short value;
};

typedef struct gtk_accel_map {
   /* detailed action name */
   char *action;
   /* 
    * NULL terminated accelerator string-array,
    * able to contain up to 2 accelerators per action
    */
   const char * const accel[3];
} gtkui_accel_map_t;

struct resolv_object {
   /* Widget type to be updated */
   GType type;
   /* Widget to be updated */
   GtkWidget *widget;
   /* List Stores are not of type GtkWidget */
   GtkListStore *liststore;
   /* some attributes needed to update the widget */
   GtkTreeIter treeiter;
   guint column;
   /* The IP address to resolve */
   struct ip_addr *ip;
};

/* ec_gtk.c */
extern GtkApplication *etterapp;
extern GtkWidget *window;  /* main window */
extern GtkWidget *notebook, *notebook_frame;
extern GtkWidget *textview;
extern GtkWidget *infobar;
extern GtkWidget *infolabel;
extern GtkWidget *infoframe;
extern GtkTextBuffer *msgbuffer;
extern GtkTextMark *endmark;
extern GTimer *progress_timer;

extern void set_gtk_interface(void);
extern void gtkui_about(GSimpleAction *action, GVariant *value, gpointer data);
extern GtkWidget* gtkui_message_dialog(GtkWindow *parent, GtkDialogFlags flags, 
      GtkMessageType type, GtkButtonsType buttons, const char *msg);
extern GtkWidget* gtkui_infobar_new(GtkWidget *infoframe);
extern void gtkui_infobar_show(GtkMessageType type, const gchar *msg);
extern void gtkui_infobar_hide(GtkWidget *widget, gint response, gpointer data);
extern void gtkui_message(const char *msg);
extern void gtkui_input(const char *title, char *input, size_t n, void (*callback)(void));
extern void gtkui_exit(GSimpleAction *action, GVariant *value, gpointer data);

extern void gtkui_sniff_offline(void);
extern void gtkui_sniff_live(void);


extern gboolean gtkui_iptoa_deferred(gpointer data);
extern gboolean gtkui_combo_enter(GtkWidget *widget, GdkEventKey *event, gpointer data);
extern void gtkui_dialog_enter(GtkWidget *widget, gpointer data);
extern gboolean gtkui_context_menu(GtkWidget *widget, GdkEventButton *event, gpointer data);
extern void gtkui_filename_browse(GtkWidget *widget, gpointer data);
extern char *gtkui_utf8_validate(char *data);

/* MDI pages */
extern GtkWidget *gtkui_page_new(char *title, void (*callback)(void), void (*detacher)(GtkWidget *));
extern void gtkui_page_present(GtkWidget *child);
extern void gtkui_page_close(GtkWidget *widget, gpointer data);
extern void gtkui_page_close_current(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_page_detach_current(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_page_attach_shortcut(GtkWidget *win, void (*attacher)(void));
extern void gtkui_page_right(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_page_left(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk3_menus.c */
/*
 * 0 for offline menus
 * 1 for live menus
 */
extern void gtkui_create_menu(GApplication *app, gpointer data);
extern void gtkui_create_tab_menu(void);


/* ec_gtk3_start.c */
extern void gtkui_start_sniffing(void);
extern void gtkui_stop_sniffing(void);

/* ec_gtk3_filters.c */
extern void gtkui_load_filter(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_stop_filter(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk3_hosts.c */
#ifdef WITH_IPV6
extern void toggle_ip6scan(GSimpleAction *action, GVariant *value, gpointer data);
#endif
extern void gtkui_scan(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_load_hosts(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_save_hosts(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_host_list(GSimpleAction *action, GVariant *value, gpointer data);
extern gboolean gtkui_refresh_host_list(gpointer data);

/* ec_gtk3_view.c */
extern void gtkui_show_stats(GSimpleAction *action, GVariant *value, gpointer data);
extern void toggle_resolve(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_vis_method(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_vis_regex(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_wifi_key(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk3_targets.c */
extern void toggle_reverse(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_select_protocol(GSimpleAction *action, GVariant *value, gpointer data);
extern void wipe_targets(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_select_targets(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_current_targets(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_create_targets_array(void);

/* ec_gtk3_view_profiles.c */
extern void gtkui_show_profiles(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk3_mitm.c */
extern void gtkui_arp_poisoning(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_icmp_redir(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_port_stealing(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_dhcp_spoofing(GSimpleAction *action, GVariant *value, gpointer data);
#ifdef WITH_IPV6
extern void gtkui_ndp_poisoning(GSimpleAction *action, GVariant *value, gpointer data);
#endif
extern void gtkui_mitm_stop(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk3_redirect.c */
extern void gtkui_sslredir_show(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk3_logging.c */
extern void toggle_compress(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_log_all(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_log_info(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_log_msg(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_stop_log(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_stop_msg(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk3_plugins.c */
extern void gtkui_plugin_mgmt(GSimpleAction *action, GVariant *value, gpointer data);
extern void gtkui_plugin_load(GSimpleAction *action, GVariant *value, gpointer data);
extern gboolean gtkui_refresh_plugin_list(gpointer data);

/* ec_gtk3_view_connections.c */
extern void gtkui_show_connections(GSimpleAction *action, GVariant *value, gpointer data);

/* ec_gtk3_conf.c */
extern void gtkui_conf_set(char *name, short value);
extern short gtkui_conf_get(char *name);
extern void gtkui_conf_read(void);
extern void gtkui_conf_save(void);

#ifndef OS_WINDOWS
/* ec_gtk3_help.c */
extern void gtkui_help(GSimpleAction *action, GVariant *value, gpointer data);
#endif

/* ec_gtk3_shortcuts.c */
extern void gtkui_show_shortcuts(GSimpleAction *action, GVariant *value, gpointer data);

#endif

/* EOF */

// vim:ts=3:expandtab

