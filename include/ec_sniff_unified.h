
/* $Id: ec_sniff_unified.h,v 1.3 2003/12/13 18:41:10 alor Exp $ */

#ifndef EC_SNIFF_UNIFIED_H
#define EC_SNIFF_UNIFIED_H

/* exported functions */

extern void start_unified_sniff(void);
extern void stop_unified_sniff(void);
extern void forward_unified_sniff(struct packet_object *po);


#endif

/* EOF */

// vim:ts=3:expandtab

