/*
    etterlog -- analysis module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterlog/el_analyze.c,v 1.1 2003/03/25 18:43:13 alor Exp $
*/

#include <el.h>
#include <ec_log.h>
#include <el_functions.h>

void analyze(void);

/*******************************************/

void analyze(void)
{
   struct log_global_header hdr;
   struct log_header_packet pck;
   u_char *buf = NULL;
   int ret, count = 0;
   
   /* get the global header */
   ret = get_header(&hdr);
   ON_ERROR(ret, -EINVALID, "Invalid log file");
   
   /* read the logfile */
   LOOP {
      ret = get_packet(&pck, &buf);

      /* on error exit the loop */
      if (ret != ESUCCESS)
         break;
      
      count++;
      SAFE_FREE(buf);
   }

   /* adjust the timestamp */
   hdr.tv.tv_sec = ntohl(hdr.tv.tv_sec);
   hdr.tv.tv_usec = ntohl(hdr.tv.tv_usec);
   
   printf("Log file version   : %s\n", hdr.version);
   printf("Timestamp          : %s", ctime((time_t *)&hdr.tv.tv_sec));
   printf("Type               : %s\n", (ntohl(hdr.type) == LOG_PACKET) ? "LOG_PACKET" : "LOG_INFO" );
   printf("Number of packets  : %d\n", count);
   printf("\n");
   
   exit(0);
}

/* EOF */

// vim:ts=3:expandtab

