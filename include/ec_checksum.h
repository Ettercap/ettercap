
/* $Id: ec_checksum.h,v 1.4 2004/05/13 15:15:11 alor Exp $ */

#ifndef EC_CHECKSUM_H
#define EC_CHECKSUM_H

#include <ec_packet.h>

extern u_int16 L3_checksum(u_char *buf, size_t len);
extern u_int16 L4_checksum(struct packet_object *po);
#define CSUM_INIT    0
#define CSUM_RESULT  0

extern u_int32 CRC_checksum(u_char *buf, size_t len, u_int32 init);
#define CRC_INIT_ZERO   0x0
#define CRC_INIT        0xffffffff
#define CRC_RESULT      0xdebb20e3

#endif

/* EOF */

// vim:ts=3:expandtab

