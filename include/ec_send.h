
/* $Id: ec_send.h,v 1.6 2003/10/28 21:10:55 alor Exp $ */

#ifndef EC_SEND_H
#define EC_SEND_H

#include <ec_packet.h>
#include <libnet.h>

extern void send_init(void);
extern int send_to_L2(struct packet_object *po);
extern int send_to_L3(struct packet_object *po);
extern int send_to_bridge(struct packet_object *po);

extern int send_arp(u_char type, struct ip_addr *sip, u_int8 *smac, struct ip_addr *tip, u_int8 *tmac);
extern int send_icmp_echo(u_char type, struct ip_addr *sip, u_int8 *smac, struct ip_addr *tip, u_int8 *tmac);

extern u_int8 MEDIA_BROADCAST[MEDIA_ADDR_LEN];
extern u_int8 ARP_BROADCAST[MEDIA_ADDR_LEN];

#define FUNC_BUILDER(func)       libnet_ptag_t func(u_int8 *dst, u_int16 proto)
#define FUNC_BUILDER_PTR(func)   libnet_ptag_t (*func)(u_int8 *dst, u_int16 proto)

extern void add_builder(u_int8 dlt, FUNC_BUILDER_PTR(builder));

#endif

/* EOF */

// vim:ts=3:expandtab

