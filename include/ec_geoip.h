#ifndef ETTERCAP_GEOIP_H
#define ETTERCAP_GEOIP_H


#include <ec.h>
#include <ec_inet.h>

#ifdef HAVE_GEOIP
#define MMDB_FILENAME "GeoLite2-Country.mmdb"
#define MAX_GEOIP_STR_LEN 31
EC_API_EXTERN void geoip_init (void);
EC_API_EXTERN char* geoip_ccode_by_ip (struct ip_addr *ip, char* buffer, size_t len);
EC_API_EXTERN char* geoip_country_by_ip (struct ip_addr *ip, char* buffer, size_t len);
#endif

#endif
