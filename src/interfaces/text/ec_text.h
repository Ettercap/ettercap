#ifndef ETTERCAP_TEXT_H
#define ETTERCAP_TEXT_H

extern void set_text_interface(void);
extern int text_plugin(char *plugin);
extern void text_print_packet(struct packet_object *po);
extern void text_profiles(void);
extern void text_connections(void);
extern void text_redirect_print(void);
extern void text_redirect_add(void);
extern void text_redirect_del(int num);

#endif

/* EOF */

// vim:ts=3:expandtab

