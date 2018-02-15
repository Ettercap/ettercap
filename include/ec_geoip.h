#ifndef ETTERCAP_GEOIP_H
#define ETTERCAP_GEOIP_H


#include <ec.h>
#include <ec_inet.h>

#ifdef HAVE_GEOIP
EC_API_EXTERN void geoip_init (void);
EC_API_EXTERN const char* geoip_ccode_by_ip (struct ip_addr *ip);
EC_API_EXTERN const char* geoip_country_by_ip (struct ip_addr *ip);
#endif

#endif
