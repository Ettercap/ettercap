
/* $Id: ec_interfaces.h,v 1.9 2003/10/11 19:43:42 alor Exp $ */

#ifndef EC_INTERFACES_H
#define EC_INTERFACES_H

/* exported functions */

/* text related */
extern void set_text_interface(void);
extern int text_plugin(char *plugin);
extern void text_print_packet(struct packet_object *po);
extern void text_profiles(void);
extern void text_connections(void);

/* daemon related */
extern void set_daemon_interface(void);

#endif

/* EOF */

// vim:ts=3:expandtab

