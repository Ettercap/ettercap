
/* $Id: ec_send.h,v 1.10 2003/11/22 13:57:10 alor Exp $ */

#ifndef EC_SEND_H
#define EC_SEND_H

#include <ec_packet.h>
#include <libnet.h>

extern void send_init(void);
extern int send_to_L2(struct packet_object *po);
extern int send_to_L3(struct packet_object *po);
extern int send_to_bridge(struct packet_object *po);

extern int send_arp(u_char type, struct ip_addr *sip, u_int8 *smac, struct ip_addr *tip, u_int8 *tmac);
extern int send_L2_icmp_echo(u_char type, struct ip_addr *sip, struct ip_addr *tip, u_int8 *tmac);
extern int send_L3_icmp_echo(u_char type, struct ip_addr *sip, struct ip_addr *tip);
extern int send_icmp_redir(u_char type, struct ip_addr *sip, struct ip_addr *gw, struct packet_object *po);
extern int send_dhcp_reply(struct ip_addr *sip, struct ip_addr *tip, u_int8 *tmac, u_int8 *dhcp_hdr, u_int8 *options, size_t optlen);
extern int send_dns_reply(struct ip_addr *sip, struct ip_addr *tip, u_int8 *tmac, u_int16 id, u_int8 *data, size_t datalen);

extern u_int8 MEDIA_BROADCAST[MEDIA_ADDR_LEN];
extern u_int8 ARP_BROADCAST[MEDIA_ADDR_LEN];

#define FUNC_BUILDER(func)       libnet_ptag_t func(u_int8 *dst, u_int16 proto)
#define FUNC_BUILDER_PTR(func)   libnet_ptag_t (*func)(u_int8 *dst, u_int16 proto)

extern void add_builder(u_int8 dlt, FUNC_BUILDER_PTR(builder));

#endif

/* EOF */

// vim:ts=3:expandtab

