/*
    etterlog -- read the logfile

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

    $Id: el_log.c,v 1.14 2003/09/27 17:22:24 alor Exp $
*/

#include <el.h>
#include <ec_log.h>

void open_log(char *file);
int get_header(struct log_global_header *hdr);
int get_packet(struct log_header_packet *pck, u_char **buf);
int get_info(struct log_header_info *inf, struct dissector_info *buf);

/*******************************************/

/* 
 * open the logfile, then drop the privs
 */

void open_log(char *file)
{
   int zerr;
   
   GBL_LOGFILE = strdup(file);

   GBL_LOG_FD = gzopen(file, "rb");
   ON_ERROR(GBL_LOG_FD, NULL, "%s", gzerror(GBL_LOG_FD, &zerr));
 
   /* if we are root, drop privs... */
 
   if ( getuid() == 0 && setuid(65535) < 0)
      ERROR_MSG("Cannot drop priviledges...");

}

/*
 * returns the global header 
 */

int get_header(struct log_global_header *hdr)
{
   int c;

   c = gzread(GBL_LOG_FD, hdr, sizeof(struct log_global_header));

   if (c != sizeof(struct log_global_header))
      return -EINVALID;
   
   /* convert to host order */
   
   hdr->magic = ntohs(hdr->magic);
   
   if (hdr->magic != EC_LOG_MAGIC)
      return -EINVALID;
   
   hdr->first_header = ntohs(hdr->first_header);
   gzseek(GBL_LOG_FD, hdr->first_header, SEEK_SET);
  
   /* adjust the timestamp */
   hdr->tv.tv_sec = ntohl(hdr->tv.tv_sec);
   hdr->tv.tv_usec = ntohl(hdr->tv.tv_usec);
   
   hdr->type = ntohl(hdr->type);
   
   return ESUCCESS;
}


/*
 * read the header of a packet
 * and return the data in the buf
 */

int get_packet(struct log_header_packet *pck, u_char **buf)
{
   int c;

   c = gzread(GBL_LOG_FD, pck, sizeof(struct log_header_packet));

   if (c != sizeof(struct log_header_packet))
      return -EINVALID;
   
   pck->len = ntohl(pck->len);
  
   /* adjust the timestamp */
   pck->tv.tv_sec = ntohl(pck->tv.tv_sec);
   pck->tv.tv_usec = ntohl(pck->tv.tv_usec);
  
   /* allocate the memory for the buffer */
   SAFE_CALLOC(*buf, pck->len, sizeof(u_char));

   /* copy the data of the packet */
   c = gzread(GBL_LOG_FD, *buf, pck->len);
   
   if ((size_t)c != pck->len)
      return -EINVALID;
   
   return ESUCCESS;
}

/*
 * read the header for the info and
 * return the user, pass ecc in buf
 */

int get_info(struct log_header_info *inf, struct dissector_info *buf)
{
   int c;

   /* get the whole header */
   c = gzread(GBL_LOG_FD, inf, sizeof(struct log_header_info));

   /* truncated ? */
   if (c != sizeof(struct log_header_info))
      return -EINVALID;

   /* adjust the variable lengths */
   inf->var.user_len = ntohs(inf->var.user_len);
   inf->var.pass_len = ntohs(inf->var.pass_len);
   inf->var.info_len = ntohs(inf->var.info_len);
   inf->var.banner_len = ntohs(inf->var.banner_len);

   /* 
    * get the dissectors info
    *
    * we can deal only with associated user and pass,
    * so there must be present all of them
    */

   if (inf->var.user_len) {
      SAFE_CALLOC(buf->user, inf->var.user_len + 1, sizeof(char));
      
      c = gzread(GBL_LOG_FD, buf->user, inf->var.user_len);
      if (c != inf->var.user_len)
         return -EINVALID;
   }
   
   if (inf->var.pass_len) {
      SAFE_CALLOC(buf->pass, inf->var.pass_len + 1, sizeof(char));
      
      c = gzread(GBL_LOG_FD, buf->pass, inf->var.pass_len);
      if (c != inf->var.pass_len)
         return -EINVALID;
   }
   
   if (inf->var.info_len) {
      SAFE_CALLOC(buf->info, inf->var.info_len + 1, sizeof(char));
      
      c = gzread(GBL_LOG_FD, buf->info, inf->var.info_len);
      if (c != inf->var.info_len)
         return -EINVALID;
   }
   
   if (inf->var.banner_len) {
      SAFE_CALLOC(buf->banner, inf->var.banner_len + 1, sizeof(char));
      
      c = gzread(GBL_LOG_FD, buf->banner, inf->var.banner_len);
      if (c != inf->var.banner_len)
         return -EINVALID;
   }
   
   return ESUCCESS; 
}

/* EOF */

// vim:ts=3:expandtab

