
/* $Id: ec_gtk.h,v 1.4 2004/02/29 17:37:21 alor Exp $ */

#ifndef EC_GTK_H
#define EC_GTK_H
#define G_DISABLE_CONST_RETURNS
#include <gtk/gtk.h>

/* ec_gtk.c */
extern GtkWidget *window;  /* main window */
extern GtkWidget *main_menu;

extern void gtkui_message(const char *msg);
extern void gtkui_input(const char *title, char *input, size_t n, void (*callback)(void));

extern void gtkui_sniff_offline(void);
extern void gtkui_sniff_live(void);

/* ec_gtk_menus.c */
/*
 * 0 for offline menus
 * 1 for live menus
 */
extern void gtkui_create_menu(int live);

/* ec_gtk_start.c */
extern void gtkui_start_sniffing(void);
extern void gtkui_stop_sniffing(void);

/* ec_gtk_filters.c */
extern void gtkui_load_filter(void);
extern void gtkui_stop_filter(void);

/* ec_gtk_hosts.c */
extern void gtkui_scan(void);
extern void gtkui_load_hosts(void);
extern void gtkui_save_hosts(void);
extern void gtkui_host_list(void);

/* ec_gtk_view.c */
extern void gtkui_show_stats(void);
extern void toggle_resolve(void);
extern void gtkui_vis_method(void);

/* ec_gtk_targets.c */
extern void toggle_reverse(void);
extern void gtkui_select_protocol(void);
extern void wipe_targets(void);
extern void gtkui_select_targets(void);
extern void gtkui_current_targets(void);

/* ec_gtk_view_profiles.c */
extern void gtkui_show_profiles(void);

/* ec_gtk_mitm.c */
extern void gtkui_arp_poisoning(void);
extern void gtkui_icmp_redir(void);
extern void gtkui_port_stealing(void);
extern void gtkui_dhcp_spoofing(void);
extern void gtkui_mitm_stop(void);

/* ec_gtk_logging.c */
extern void toggle_compress(void);
extern void gtkui_log_all(void);
extern void gtkui_log_info(void);
extern void gtkui_log_msg(void);
extern void gtkui_stop_log(void);
extern void gtkui_stop_msg(void);

/* ec_gtk_plugins.c */
extern void gtkui_plugin_mgmt(void);
extern void gtkui_plugin_load(void);

/* ec_gtk_view_connections.c */
extern void gtkui_show_connections(void);

#endif

/* EOF */

// vim:ts=3:expandtab

