
/* $Id: ec_checksum.h,v 1.3 2003/10/30 21:48:48 alor Exp $ */

#ifndef EC_CHECKSUM_H
#define EC_CHECKSUM_H

#include <ec_packet.h>

extern u_int16 L3_checksum(u_char *buf, size_t len);
extern u_int16 L4_checksum(struct packet_object *po);

extern u_int32 CRC_checksum(u_char *buf, size_t len);

#endif

/* EOF */

// vim:ts=3:expandtab

