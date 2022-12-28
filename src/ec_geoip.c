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
#include <ec_version.h>

#ifdef HAVE_GEOIP

#include <maxminddb.h>

static MMDB_s* mmdb = NULL;

static int geoip_open(const char* filename)
{
   int ret;

   ret = MMDB_open(filename, MMDB_MODE_MMAP, mmdb);
   if (ret != MMDB_SUCCESS) { // Default path to GeoIP Database didn't worked out

      WARN_MSG("geoip_init: MaxMind database file %s cannot be opened: %s",
            filename, MMDB_strerror(ret));

      if (ret == MMDB_IO_ERROR)
         DEBUG_MSG("geoip_init: IO Error opening database file '%s': %s",
            filename, strerror(errno));
   }

   return ret;
}

static void geoip_exit (void)
{
   MMDB_close(mmdb);
   SAFE_FREE(mmdb);
}

void geoip_init (void)
{
   int ret;
   const char* mmdb_default_file;
   MMDB_description_s* descr;

   SAFE_CALLOC(mmdb, 1, sizeof(MMDB_s));

   /* Database file delivered with Ettercap installation */
   mmdb_default_file = INSTALL_DATADIR "/" PROGRAM "/" MMDB_FILENAME;

   /* First try to open alternative database file if one is provided */
   if (EC_GBL_CONF->geoip_data_file && strlen(EC_GBL_CONF->geoip_data_file)) {

      ret = geoip_open(EC_GBL_CONF->geoip_data_file);

      /* No success to open alternative database file - fallback to default */
      if (ret != MMDB_SUCCESS)
         ret = geoip_open(mmdb_default_file);
   }
   /* No alternative database file set - use default */
   else
      ret = geoip_open(mmdb_default_file);

   /* No success opening the alternative or the default database file */
   if (ret != MMDB_SUCCESS) {
      SAFE_FREE(mmdb);
      return;
   }

   /* Metainfo of MaxMind DB for debug purpose */
   descr = mmdb->metadata.description.descriptions[0];
   DEBUG_MSG("geoip_init: Description: %s Lang: %s.",
         descr->description, descr->language);
   DEBUG_MSG("geoip_init: Info: IP version: %d, Epoch: %" PRIu64,
         mmdb->metadata.ip_version, mmdb->metadata.build_epoch);

   /* Output mandatory attribution for Maxmind Geolite2 database */
   USER_MSG("This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com/.\n");

   /* Cleanup */
   atexit (geoip_exit);
}

/*
 * returns the GeoIP information for a given IP address ...
 * return NULL if GeoIP API isn't initialized properly
 */
char* geoip_get_by_ip (struct ip_addr *ip, const int get_type, char* buffer, size_t len)
{
   int ret, mmdb_error;
   struct sockaddr_storage ss;
   struct sockaddr* sa;
   struct sockaddr_in* sa4;
#ifdef WITH_IPV6
   struct sockaddr_in6* sa6;
#endif
   char tmp[MAX_ASCII_ADDR_LEN];

   MMDB_lookup_result_s result;
   MMDB_entry_data_s entry;

   if (get_type == GEOIP_CCODE) {
      /* 0.0.0.0 or :: */
      if (ip_addr_is_zero(ip)) {
         return "00";
      }

      /* only global IP addresses can have a location */
      if (!ip_addr_is_global(ip)) {
         return "--";
      }
   }

   /* not initialized - database file couldn't be opened */
   if (!mmdb) {
      DEBUG_MSG("geoip_ccode_by_ip: MaxMind API not initialized");
      return NULL;
   }

   /* Convert ip_addr struct to sockaddr struct */
   sa = (struct sockaddr *) &ss;
   switch (ntohs(ip->addr_type)) {
      case AF_INET:
         sa4 = (struct sockaddr_in *) &ss;
         sa4->sin_family = ntohs(ip->addr_type);
         ip_addr_cpy((u_char*)&sa4->sin_addr.s_addr, ip);
         break;
#ifdef WITH_IPV6
      case AF_INET6:
         sa6 = (struct sockaddr_in6 *) &ss;
         sa6->sin6_family = ntohs(ip->addr_type);
         ip_addr_cpy((u_char*)&sa6->sin6_addr.s6_addr, ip);
         break;
#endif
      default:
         return NULL;
   }

   result = MMDB_lookup_sockaddr(mmdb, sa, &mmdb_error);

   if (mmdb_error != MMDB_SUCCESS) {
      DEBUG_MSG("geoip_ccode_by_ip: Error looking up IP address %s in maxmind database",
            ip_addr_ntoa(ip, tmp));
      return NULL;
   }

   if (result.found_entry) {
      switch (get_type) {
         case GEOIP_CCODE:
            ret = MMDB_get_value(&result.entry, &entry, "country", "iso_code", NULL);
            break;
         case GEOIP_CNAME:
            ret = MMDB_get_value(&result.entry, &entry, "country", "names", "en", NULL);
            break;
         default:
            return NULL;
            break;
      }
      if (ret != MMDB_SUCCESS) {
         DEBUG_MSG("Error extracting entry from result: %s", MMDB_strerror(ret));
         return NULL;
      }
      if (entry.has_data) {
         if (entry.type == MMDB_DATA_TYPE_UTF8_STRING) {
            /* zero buffer */
            memset(buffer, 0, len);
            /* make sure to copy the exact string or less */
            if (len <= entry.data_size)
               len = len-1;
            else
               len = entry.data_size;
            memcpy(buffer, entry.utf8_string, len);
         }
      }
   }
   else
      return "--";

   /* Determine country id by IP address */
   DEBUG_MSG("geoip_get_by_ip(%d): GeoIP information for ip %s: %s",
         get_type, ip_addr_ntoa(ip, tmp), buffer);

   return buffer;
}


#endif  /* HAVE_GEOIP */
