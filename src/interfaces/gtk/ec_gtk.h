
/* $Id: ec_gtk.h,v 1.2 2004/02/27 03:33:00 daten Exp $ */

#ifndef EC_GTK_H
#define EC_GTK_H
#define G_DISABLE_CONST_RETURNS
#include <gtk/gtk.h>

/* ec_gtk.c */
extern GtkWidget *window;  /* main window */
extern GtkWidget *main_menu;

extern void gui_message(const char *msg);
extern void gui_input(const char *title, char *input, size_t n);
extern void gui_input_call(const char *title, char *input, size_t n, void (*callback)(void));

extern void gui_sniff_offline(void);
extern void gui_sniff_live(void);

/* ec_gtk_menus.c */
/*
 * 0 for offline menus
 * 1 for live menus
 */
extern void gui_create_menu(int live);

/* ec_gtk_start.c */
extern void gui_start_sniffing(void);
extern void gui_stop_sniffing(void);

/* ec_gtk_filters.c */
extern void gui_load_filter(void);
extern void gui_stop_filter(void);

/* ec_gtk_hosts.c */
extern void gui_scan(void);
extern void gui_load_hosts(void);
extern void gui_save_hosts(void);
extern void gui_host_list(void);

/* ec_gtk_view.c */
extern void gui_show_stats(void);
extern void toggle_resolve(void);
extern void gui_vis_method(void);

/* ec_gtk_targets.c */
extern void toggle_reverse(void);
extern void gui_select_protocol(void);
extern void wipe_targets(void);
extern void gui_select_targets(void);
extern void gui_current_targets(void);

/* ec_gtk_view_profiles.c */
extern void gui_show_profiles(void);

/* ec_gtk_mitm.c */
extern void gui_arp_poisoning(void);
extern void gui_icmp_redir(void);
extern void gui_port_stealing(void);
extern void gui_dhcp_spoofing(void);
extern void gui_mitm_stop(void);

/* ec_gtk_logging.c */
extern void toggle_compress(void);
extern void gui_log_all(void);
extern void gui_log_info(void);
extern void gui_log_msg(void);
extern void gui_stop_log(void);
extern void gui_stop_msg(void);

/* ec_gtk_plugins.c */
extern void gui_plugin_mgmt(void);
extern void gui_plugin_load(void);

/* ec_gtk_view_connections.c */
extern void gui_show_connections(void);

#endif

/* EOF */

// vim:ts=3:expandtab

