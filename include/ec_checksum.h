
#ifndef EC_CHECKSUM_H
#define EC_CHECKSUM_H

#include <ec_packet.h>

extern u_int16 L3_checksum(struct packet_object *po);
extern u_int16 L4_checksum(struct packet_object *po);

extern u_int32 CRC_checksum(u_char *buf, size_t len);

#endif

/* EOF */

// vim:ts=3:expandtab

