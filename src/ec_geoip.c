/*
    ettercap -- GeoIP interface; IPv4/6 address to geolocation lookup.

    Copyright (C) ALoR & NaGA

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/

#include <ec.h>
#include <ec_geoip.h>

#ifdef HAVE_GEOIP

#include <GeoIP.h>

static GeoIP *gi  = NULL;
#ifdef WITH_IPV6
static GeoIP *gi6 = NULL;
#endif

static void geoip_exit (void)
{
   GeoIP_delete (gi);
   gi = NULL;
#ifdef WITH_IPV6
   GeoIP_delete(gi6);
   gi6 = NULL;
#endif
   GeoIP_cleanup();
}

void geoip_init (void)
{
   char *gi_info;

   /* try to find and open it in the default location */
   gi = GeoIP_open_type(GEOIP_COUNTRY_EDITION, GEOIP_MEMORY_CACHE);

   /* not found, fallback in the configuration file value */
   if(!gi) {

      if (!EC_GBL_CONF->geoip_data_file)
         return;

      gi = GeoIP_open (EC_GBL_CONF->geoip_data_file, GEOIP_MEMORY_CACHE);
      if (!gi)
      {
         DEBUG_MSG ("geoip_init: %s not found.", EC_GBL_CONF->geoip_data_file);
         GeoIP_cleanup();
         return;
      }
   }
   gi_info = GeoIP_database_info (gi);

   DEBUG_MSG ("geoip_init: Description: %s.", 
         GeoIPDBDescription[GEOIP_COUNTRY_EDITION]);
   DEBUG_MSG ("geoip_init: Info:        %s. Countries: %u",
         gi_info ? gi_info : "<none>", GeoIP_num_countries());

   atexit (geoip_exit);

   SAFE_FREE(gi_info);
   gi_info = NULL;

#ifdef WITH_IPV6

   /* try to find and open it in the default location */
   gi6 = GeoIP_open_type(GEOIP_COUNTRY_EDITION_V6, GEOIP_MEMORY_CACHE);

   /* not found, fallback in the configuration file value */
   if (!gi6) {
      if (!EC_GBL_CONF->geoip_data_file_v6)
         return;

      gi6 = GeoIP_open(EC_GBL_CONF->geoip_data_file_v6, GEOIP_MEMORY_CACHE);
      if (!gi6) {
         DEBUG_MSG("geoip_init: %s not found.\n", 
               EC_GBL_CONF->geoip_data_file_v6);
         return;
      }
   }

   gi_info = GeoIP_database_info(gi6);

   DEBUG_MSG("geoip_init: Description: %s.", 
         GeoIPDBDescription[GEOIP_COUNTRY_EDITION_V6]);
   DEBUG_MSG("geoip_init: Info:        %s. Countries: %u",
         gi_info ? gi_info : "<none>", GeoIP_num_countries());

   SAFE_FREE(gi_info);
   gi_info = NULL;

#endif
}

/*
 * returns the country code string for a given IP address ...
 *  - the two letter country code from GeoIP database
 *  - "00" if ip address is the default or undefined address
 *  - "--" if ip address is not global
 * return NULL if GeoIP API isn't initialized properly
 */
const char* geoip_ccode_by_ip (struct ip_addr *ip)
{
   int id;
#ifdef WITH_IPV6
   struct in6_addr geo_ip6;
#endif
   char tmp[MAX_ASCII_ADDR_LEN];

   /* 0.0.0.0 or :: */
   if (ip_addr_is_zero(ip)) {
      return "00";
   }

   /* only global IP addresses can have a location */
   if (!ip_addr_is_global(ip)) {
      return "--";
   }

   /* Determine country id by IP address */
   switch (ntohs(ip->addr_type)) {
      case AF_INET:
         if (!gi)
            return NULL;
         id = GeoIP_id_by_ipnum(gi, ntohl(*ip->addr32));
         break;
#ifdef WITH_IPV6
      case AF_INET6:
         if (!gi6)
            return NULL;
         ip_addr_cpy((u_char *)geo_ip6.s6_addr, ip);
         id = GeoIP_id_by_ipnum_v6(gi6, geo_ip6);
         break;
#endif
      default:
         return NULL;
   }

   DEBUG_MSG("geoip_ccode_by_ip: GeoIP country code for ip %s: %s",
         ip_addr_ntoa(ip, tmp), GeoIP_code_by_id(id));

   return GeoIP_code_by_id(id);
}

/*
 * returns the country name string for a given IP address
 * return NULL if GeoIP API isn't initialized properly
 */
const char* geoip_country_by_ip (struct ip_addr *ip)
{
   int id;
#ifdef WITH_IPV6
   struct in6_addr geo_ip6;
#endif
   char tmp[MAX_ASCII_ADDR_LEN];

   /* 0.0.0.0 or :: */
   if (ip_addr_is_zero(ip)) {
      return "No unique location";
   }

   /* only global IP addresses can have a location */
   if (!ip_addr_is_global(ip)) {
      return "No unique location";
   }

   /* Determine country id by IP address */
   switch (ntohs(ip->addr_type)) {
      case AF_INET:
         if (!gi)
            return NULL;
         id = GeoIP_id_by_ipnum(gi, ntohl(*ip->addr32));
         break;
#ifdef WITH_IPV6
      case AF_INET6:
         if (!gi6)
            return NULL;
         ip_addr_cpy((u_char *)geo_ip6.s6_addr, ip);
         id = GeoIP_id_by_ipnum_v6(gi6, geo_ip6);
         break;
#endif
      default:
         return NULL;
   }

   DEBUG_MSG("geoip_country_by_ip: GeoIP country name for ip %s: %s",
         ip_addr_ntoa(ip, tmp), GeoIP_name_by_id(id));

   return GeoIP_name_by_id(id);
}

#endif  /* HAVE_GEOIP */
