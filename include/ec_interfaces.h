
#ifndef EC_INTERFACES_H
#define EC_INTERFACES_H

/* exported functions */

/* console related */
extern void set_console_interface(void);
extern int console_plugin(char *plugin);
extern void console_print_packet(struct packet_object *po);

/* daemon related */
extern void set_daemon_interface(void);

#endif

/* EOF */

// vim:ts=3:expandtab

