#ifndef ETTERCAP_GEOIP_H
#define ETTERCAP_GEOIP_H


#include <ec.h>
#include <ec_inet.h>

#ifdef HAVE_GEOIP
#define MMDB_FILENAME "GeoLite2-Country.mmdb"
#define MAX_GEOIP_STR_LEN 31
#define GEOIP_CCODE 1
#define GEOIP_CNAME 2
EC_API_EXTERN void geoip_init (void);
EC_API_EXTERN char* geoip_get_by_ip (struct ip_addr *ip, const int get_type, char* buffer, size_t len);
#endif

#endif
