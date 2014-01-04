#ifndef ETTERCAP_SNIFF_UNIFIED_H_F363282BA1384412BC6DC15E807F56FE
#define ETTERCAP_SNIFF_UNIFIED_H_F363282BA1384412BC6DC15E807F56FE

/* exported functions */

EC_API_EXTERN void start_unified_sniff(void);
EC_API_EXTERN void stop_unified_sniff(void);
EC_API_EXTERN void forward_unified_sniff(struct packet_object *po);
EC_API_EXTERN void unified_check_forwarded(struct packet_object *po);
EC_API_EXTERN void unified_set_forwardable(struct packet_object *po);

#endif

/* EOF */

// vim:ts=3:expandtab

