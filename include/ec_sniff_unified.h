
/* $Id: ec_sniff_unified.h,v 1.4 2004/03/31 13:03:08 alor Exp $ */

#ifndef EC_SNIFF_UNIFIED_H
#define EC_SNIFF_UNIFIED_H

/* exported functions */

extern void start_unified_sniff(void);
extern void stop_unified_sniff(void);
extern void forward_unified_sniff(struct packet_object *po);
extern void unified_check_forwarded(struct packet_object *po);
extern void unified_set_forwardable(struct packet_object *po);

#endif

/* EOF */

// vim:ts=3:expandtab

