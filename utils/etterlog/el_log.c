/*
    etterlog -- read the logfile

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterlog/el_log.c,v 1.1 2003/03/25 18:43:14 alor Exp $
*/

#include <el.h>
#include <ec_log.h>

int get_header(struct log_global_header *hdr);
int get_packet(struct log_header_packet *pck, u_char **buf);

/*******************************************/

/*
 * returns the global header 
 */

int get_header(struct log_global_header *hdr)
{
   int c;

   c = read(GBL_LOG_FD, hdr, sizeof(struct log_global_header));

   if (c != sizeof(struct log_global_header))
      return -EINVALID;
   else
      return ESUCCESS;
}


/*
 * read the header of a packet
 * and return the data in the buf
 */

int get_packet(struct log_header_packet *pck, u_char **buf)
{
   int c, len;

   c = read(GBL_LOG_FD, pck, sizeof(struct log_header_packet));

   if (c != sizeof(struct log_header_packet))
      return -EINVALID;
   
   len = ntohl(pck->len);
   
   /* allocate the memory for the buffer */
   *buf = calloc(len, sizeof(u_char));
   ON_ERROR(*buf, NULL, "Can't allocate memory");

   /* copy the data of the packet */
   c = read(GBL_LOG_FD, *buf, len);
   
   if (c != len)
      return -EINVALID;
   
   return ESUCCESS;
}


/* EOF */

// vim:ts=3:expandtab

